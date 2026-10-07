"""Offline generated fixture checks; no guest calls or service changes."""
import ast
import importlib.util
import json
import hashlib
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('visual-service-fixture.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
OWNER = '564d8756-3778-d981-d5b1-00a5c7cfef7a'


def guest(action='install', campaign=None):
    script = f.generate(action, OWNER, campaign)
    code = script.split("<<'CULVERT_VISUAL_FIXTURE'\n", 1)[1].rsplit('\nCULVERT_VISUAL_FIXTURE', 1)[0]
    tree = ast.parse(code)
    tree.body.pop()  # Leave the actual fixture callable, do not dispatch it.
    env = {}; exec(compile(tree, '<fixture-test>', 'exec'), env)
    return env, code


class FixtureTests(unittest.TestCase):
    def test_default_bytes_unchanged_and_named_campaign_is_separate(self):
        expected = {'culvert-lab-visual-delay.service': '353059325dc70784e94e07e774dae3c2652611bacf4a58da67a472e11cdfaa3f',
                    'culvert-lab-visual-failure.service': 'f39589095414f075be0f831203300619582fd8256dfcafe1d43af3264f22f6e4'}
        self.assertEqual({name: hashlib.sha256(raw.encode()).hexdigest() for name, raw in f.units().items()}, expected)
        root, names = f.namespace('capture-followup')
        self.assertEqual(root, f.ROOT + '-capture-followup')
        self.assertFalse(set(names) & set(f.NAMES))
        for name, raw in f.units('capture-followup').items():
            self.assertIn('-capture-followup.service', name)
            self.assertIn(root + '/delay-fired' if 'delay' in name else root + '/failure-fired', raw)
            self.assertNotIn(f.ROOT + '/', raw)
        install, _ = guest(campaign='capture-followup')
        remove, _ = guest('remove', campaign='capture-followup')
        self.assertEqual(install['config']['campaign'], 'capture-followup')
        self.assertEqual(install['config']['units'], remove['config']['units'])
        self.assertEqual(install['config']['fixture_root'], remove['config']['fixture_root'])

    def test_campaign_paths_and_guest_namespace_mismatch_refused_before_identity(self):
        for value in ('', '../escape', '/tmp/x', 'Upper', 'space name', 'a--b', 'a-', 'a_b', 'a' * 33, 9):
            with self.assertRaises(ValueError): f.generate('install', OWNER, value)
        for key, value in [('campaign', '../escape'), ('fixture_root', '/tmp/other'), ('units', f.units())]:
            env, _ = guest(campaign='capture-followup')
            env['config'][key] = value
            env['identity'] = mock.Mock()
            with self.assertRaises(ValueError): env['fixture']()
            env['identity'].assert_not_called()

    def test_units_bounded_single_boot_and_no_product_overrides(self):
        units = f.units(); self.assertEqual(len(units), 2)
        for name, raw in units.items():
            self.assertTrue(name.startswith('culvert-lab-visual-'))
            self.assertIn('ConditionPathExists=!/var/lib/culvert-lab-visual-fixture/', raw)
            self.assertIn('Before=multi-user.target', raw)
            self.assertIn('TimeoutStartSec=50s', raw)
            self.assertIn('Restart=no', raw)
            self.assertNotIn('Requires=', raw); self.assertNotIn('DefaultDependencies=no', raw)
            self.assertNotIn('getty', raw); self.assertNotIn('grub', raw)
        self.assertIn('ExecStart=/usr/bin/sleep 45', units[f.NAMES[0]])
        self.assertIn('ExecStart=/usr/bin/false', units[f.NAMES[1]])

    def test_payload_identity_and_lock_code_are_actual_reviewed_functions(self):
        env, code = guest()
        self.assertEqual(env['config']['source'], f.SOURCE)
        self.assertEqual(env['config']['owner_uuid'], OWNER)
        original = (f.HERE / 'qualify-clamav-outage.py').read_text()
        tree = ast.parse(original)
        held = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'HeldLock')
        generated = next(n for n in ast.parse(code).body if isinstance(n, ast.ClassDef) and n.name == 'HeldLock')
        self.assertEqual(ast.dump(held), ast.dump(generated))
        with self.assertRaises(ValueError): f.generate('reboot', OWNER)
        with self.assertRaises(ValueError): f.generate('install', OWNER.upper())
        self.assertNotIn("control('reboot'", code)

    def test_identity_failure_and_pending_maintenance_prevent_all_writes(self):
        env, unused = guest()
        save = mock.Mock(); control = mock.Mock(); env.update(save=save, control=control)
        env['identity'] = mock.Mock(side_effect=ValueError('wrong source/owner'))
        lock = mock.Mock(); env['HeldLock'] = lock
        with self.assertRaises(ValueError): env['fixture']()
        lock.assert_not_called(); save.assert_not_called(); control.assert_not_called()
        env['identity'] = mock.Mock(); env['service_identity'] = lambda: (999, 987)
        locks = [mock.Mock(), mock.Mock()]; lock.side_effect = locks
        env['maintenance_idle'] = mock.Mock(side_effect=ValueError('pending'))
        with self.assertRaises(ValueError): env['fixture']()
        self.assertEqual([x.args[0] for x in lock.call_args_list],
                         ['/run/culvert-os-update.lock', '/var/lib/culvert-maint/host-maintenance.lock'])
        for value in locks: value.close.assert_called_once()
        save.assert_not_called(); control.assert_not_called()

    def test_preexisting_path_refused_under_both_locks(self):
        env, unused = guest()
        locks = [mock.Mock(), mock.Mock()]
        env.update(identity=mock.Mock(), service_identity=lambda: (999, 987),
            HeldLock=mock.Mock(side_effect=locks), maintenance_idle=mock.Mock(), trusted=mock.Mock(),
            save=mock.Mock(), control=mock.Mock())
        with mock.patch.object(env['os'].path, 'lexists', return_value=True):
            with self.assertRaisesRegex(ValueError, 'receipt already'): env['fixture']()
        env['save'].assert_not_called(); env['control'].assert_not_called()
        for lock in locks: lock.close.assert_called_once()

    def test_cleanup_changed_receipt_or_unit_refuses_before_systemd(self):
        for changed in ('receipt', 'unit'):
            env, unused = guest('remove')
            receipt = mock.MagicMock()
            receipt.read_bytes.return_value = json.dumps({} if changed == 'receipt' else {
                k: env['config'][k] for k in ('source', 'owner_uuid', 'campaign', 'fixture_root', 'units', 'lock_source_sha256', 'generator_sha256')}).encode()
            root = mock.MagicMock(); root.__truediv__.return_value = receipt
            root.as_posix.return_value = f.ROOT
            env['Path'] = lambda unused: root
            locks = [mock.Mock(), mock.Mock()]
            regular = mock.Mock(side_effect=[None, ValueError('fixture file changed')]) if changed == 'unit' else mock.Mock()
            env.update(identity=mock.Mock(), service_identity=lambda: (999, 987),
                HeldLock=mock.Mock(side_effect=locks), maintenance_idle=mock.Mock(), trusted=mock.Mock(),
                regular=regular, save=mock.Mock(), control=mock.Mock())
            with mock.patch.object(env['os'].path, 'lexists', return_value=False):
                with self.assertRaises(ValueError): env['fixture']()
            env['save'].assert_not_called(); env['control'].assert_not_called()
            for lock in locks: lock.close.assert_called_once()

    def test_exact_source_vmware_alias_and_firstboot_identity(self):
        import uuid
        env, unused = guest()
        values = {
            '/sys/class/dmi/id/product_uuid': str(uuid.UUID(bytes_le=uuid.UUID(OWNER).bytes)),
            '/sys/class/dmi/id/sys_vendor': 'VMware, Inc.',
            '/var/lib/culvert-appliance/build-info.json': json.dumps({'source': {'git_commit': f.SOURCE, 'git_dirty': False}}),
        }
        def path(name):
            return SimpleNamespace(read_text=lambda: values[name], read_bytes=lambda: values[name].encode(),
                                   is_file=lambda: True)
        env['Path'] = path
        with mock.patch.object(env['os'], 'geteuid', return_value=0, create=True):
            env['identity']()
            for name, bad in [('/sys/class/dmi/id/sys_vendor', 'other'),
                              ('/sys/class/dmi/id/product_uuid', '00000000-0000-0000-0000-000000000000'),
                              ('/var/lib/culvert-appliance/build-info.json', json.dumps({'source': {'git_commit': 'old', 'git_dirty': False}}))]:
                old = values[name]; values[name] = bad
                with self.assertRaises(ValueError): env['identity']()
                values[name] = old


if __name__ == '__main__': unittest.main()
