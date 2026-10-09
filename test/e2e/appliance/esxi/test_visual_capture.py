"""Offline visual observer tests; no ESXi calls or real screenshots."""
import hashlib
import importlib.util
import json
import io
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('visual_capture', Path(__file__).with_name('visual-capture.py'))
v = importlib.util.module_from_spec(spec); spec.loader.exec_module(v)
PNG = b'\x89PNG\r\n\x1a\n' + struct.pack('>I', 13) + b'IHDR' + struct.pack('>II', 640, 400)


class VisualTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name); sec = root / 'secrets'; sec.mkdir(); ev = root / 'evidence'; ev.mkdir()
        self.now = 0.0
        self.state = {'uuid': '564d8756-3778-d981-d5b1-00a5c7cfef7a', 'ref': {'type': 'VirtualMachine', 'value': 'vm-1'},
                      'owner': 'LOCAL-ESXI:fixture', 'name': 'culvert-esxi-fixture', 'path': '/lab/vm/fixture',
                      'endpoint': 'https://192.0.2.1', 'host_ref': 'host', 'ds_ref': 'ds', 'network_ref': 'net', 'phase': 'imported'}
        manifest = root / 'freeze.json'; manifest.write_text(json.dumps({'revision': 'a' * 40}))
        profiles = importlib.util.spec_from_file_location('visual_test_profiles', Path(__file__).with_name('candidate-identities.py'))
        ids = importlib.util.module_from_spec(profiles); profiles.loader.exec_module(ids)
        cfg = dict(ids.source_profile(ids.E7E), controller_manifest=str(manifest))
        scope = root / 'scope.json'; scope.write_text(json.dumps(cfg))
        (ev / 'preflight.json').write_text(json.dumps({'expected_source': v.SOURCE, 'expected_image': cfg['image_id'],
            'artifact': {'ova_sha256': cfg['ova_sha256']}, 'harness_sha': 'a' * 40, 'harness_dirty': False,
            'controller_freeze': {'revision': 'a' * 40}}))
        self.lab = SimpleNamespace(run=root, sec=sec, ev=ev, c=cfg, scope_path=scope,
                                   state_file=root / 'owned.json', state={}, vm=mock.Mock(return_value={'runtime': {'powerState': 'poweredOn'}}))
        self.lab.gov = mock.Mock(side_effect=self.capture_png)
        adapter = v.load().module
        self.lab.capture_snapshot = lambda path,deadline: adapter.capture.snapshot(self.lab,path,deadline)
        self.args = SimpleNamespace(label='cold', seconds=3, interval=1, wait_owned_seconds=5)
        self.acl = mock.Mock()

    def ledger(self): self.lab.state_file.write_text(json.dumps(self.state))
    def sleep(self, seconds): self.now += seconds
    def capture_png(self, command, capture, path, **options):
        self.assertEqual(command, 'vm.console'); self.assertEqual(path, self.state['path'])
        self.assertEqual(options, {'timeout': 10, 'json_output': False})
        Path(capture.removeprefix('-capture=')).write_bytes(PNG)

    def run_capture(self):
        return v.capture(self.lab, self.args, self.acl, clock=lambda: self.now, pause=self.sleep)

    def test_never_queries_vm_until_uuid_and_preflight_are_available(self):
        pending = dict(self.state); pending.pop('uuid'); pending.pop('ref'); pending['phase'] = 'import-pending'
        self.lab.state_file.write_text(json.dumps(pending))
        def pause(seconds):
            self.assertEqual(self.lab.vm.call_count, 0)
            self.sleep(seconds)
            if self.now >= 1: self.ledger()
        result = v.capture(self.lab, self.args, self.acl, clock=lambda: self.now,
                           pause=lambda sec: pause(sec) if self.now < 1 else self.sleep(sec))
        self.assertEqual(result['frames'], 3); self.acl.assert_called_once_with(self.lab)
        self.assertEqual(self.lab.gov.call_count, 3)
        rows = [json.loads(x) for x in (self.lab.sec / 'visual-cold/frames.jsonl').read_bytes().splitlines()]
        self.assertEqual(rows[1]['width'], 640); self.assertEqual(rows[1]['height'], 400)
        self.assertEqual(rows[1]['sha256'], hashlib.sha256(PNG).hexdigest())
        self.assertIn('may precede', result['coverage'])

    def test_missing_uuid_times_out_without_inventory_or_capture(self):
        with self.assertRaisesRegex(ValueError, 'UUID wait expired'): self.run_capture()
        self.assertEqual(self.now, 5); self.lab.vm.assert_not_called(); self.lab.gov.assert_not_called()

    def test_candidate_preflight_mismatch_refuses_before_capture(self):
        self.ledger(); self.lab.c['ova_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'mismatch|differs'): self.run_capture()
        self.lab.vm.assert_not_called(); self.lab.gov.assert_not_called()

    def test_owned_vm_change_and_scope_change_stop_capture(self):
        for what in ('uuid', 'scope'):
            with self.subTest(what=what):
                self.args.label = what; self.now = 0; self.ledger()
                def pause(seconds):
                    self.sleep(seconds)
                    if what == 'uuid':
                        changed = dict(self.state, uuid='00000000-0000-0000-0000-000000000000')
                        self.lab.state_file.write_text(json.dumps(changed))
                    else: self.lab.scope_path.write_text('changed')
                with self.assertRaises(ValueError):
                    v.capture(self.lab, self.args, self.acl, clock=lambda: self.now, pause=pause)
                self.assertEqual(len(list((self.lab.sec / ('visual-' + what)).glob('*.png'))), 1)

    def test_maintenance_poweroff_is_observed_without_power_commands(self):
        self.ledger(); states = iter(['poweredOn'] * 3 + ['poweredOff'] + ['poweredOn'] * 30)
        self.lab.vm.side_effect = lambda **unused: {'runtime': {'powerState': next(states)}}
        result = self.run_capture()
        self.assertTrue(result['observed_powered_off_before_capture'])
        self.assertTrue(all(call.args[0] == 'vm.console' for call in self.lab.gov.call_args_list))

    def test_capture_budgets_and_existing_sequence_are_not_overwritten(self):
        self.ledger(); (self.lab.sec / 'visual-cold').mkdir()
        with self.assertRaises(FileExistsError): self.run_capture()
        self.lab.gov.assert_not_called()
        path = self.lab.sec / 'synthetic.png'; path.write_bytes(PNG)
        for budget in (0, 23):
            with self.assertRaises(ValueError): v.image_metadata(path, budget)
        path.write_bytes(PNG[:16] + struct.pack('>II', 10000, 400))
        with self.assertRaisesRegex(ValueError, 'dimensions'): v.image_metadata(path, 1024)
        path.write_bytes(b'x' * 30)
        with self.assertRaisesRegex(ValueError, 'PNG'): v.image_metadata(path, 1024)

    def test_passive_lock_is_separate_and_exclusive(self):
        (self.lab.run / 'operation.lock').write_text('import or console operation')
        with v.passive_lock(self.lab.run):
            with self.assertRaises(FileExistsError):
                with v.passive_lock(self.lab.run): pass
        self.assertTrue((self.lab.run / 'operation.lock').exists())
        self.assertFalse((self.lab.run / 'visual-capture.lock').exists())

    def test_allowed_lifecycle_phases_and_reset_refusal(self):
        pinned = v.identity(self.state)
        for phase in v.PHASES:
            self.assertEqual(v.identity(dict(self.state, phase=phase)), pinned)
        for phase in ('import-pending', 'deleted', 'identity-reset', 'unknown'):
            with self.assertRaises(ValueError): v.identity(dict(self.state, phase=phase))
        with self.assertRaises(ValueError): v.identity(dict(self.state, deleted=True))
        self.ledger()
        folder = self.lab.sec / 'p1-regressions-confirmation'; folder.mkdir()
        (folder / 'identity-reset.attempt.json').write_text('{}')
        with self.assertRaisesRegex(ValueError, 'reset'): self.run_capture()
        self.lab.gov.assert_not_called()

    def test_key_lock_reviewed_screen_and_single_dispatch(self):
        import sys
        spec = importlib.util.spec_from_file_location('visual_key', Path(__file__).with_name('visual-key.py'))
        key = importlib.util.module_from_spec(spec); spec.loader.exec_module(key)
        spec = importlib.util.spec_from_file_location('key_lab', Path(__file__).with_name('esxi-lab.py'))
        labmod = importlib.util.module_from_spec(spec); spec.loader.exec_module(labmod)
        self.lab.state = self.state
        keyboard = mock.Mock()
        console = SimpleNamespace(b=SimpleNamespace(module=SimpleNamespace(
            Lab=lambda unused: self.lab, validate_scope=lambda unused: None, locked=labmod.locked),
            private_directory=self.acl), Keyboard=mock.Mock(return_value=keyboard))
        def run(label, sha):
            argv = ['visual-key.py', '--scope', str(self.lab.scope_path), '--label', label,
                    '--key', 'alt-f12', '--expected-screen-sha256', sha]
            with mock.patch.object(key, 'load', side_effect=[v, console]), \
                 mock.patch.object(sys, 'argv', argv), mock.patch.object(key.time, 'sleep'), \
                 mock.patch.object(sys, 'stdout', io.StringIO()), mock.patch.object(sys, 'stderr', io.StringIO()):
                return key.main()
        lock = self.lab.run / 'operation.lock'; lock.write_text('PAM operation')
        self.assertEqual(run('locked', hashlib.sha256(PNG).hexdigest()), 90)
        self.lab.gov.assert_not_called(); keyboard.send.assert_not_called()
        self.assertEqual(lock.read_text(), 'PAM operation'); lock.unlink()
        self.assertEqual(run('changed', '0' * 64), 90)
        keyboard.send.assert_not_called()
        self.assertFalse((self.lab.sec / 'visual-key-changed/intent.json').exists())
        self.assertEqual(run('accepted', hashlib.sha256(PNG).hexdigest()), 0)
        keyboard.send.assert_called_once_with('KEY_ALT_F12')
        self.assertTrue((self.lab.sec / 'visual-key-accepted/intent.json').exists())
        self.assertTrue((self.lab.sec / 'visual-key-accepted/complete.json').exists())
        self.assertFalse(lock.exists())

    def test_poweron_gate_requires_exact_fresh_observer_or_refuses_in_30s(self):
        spec = importlib.util.spec_from_file_location('visual_lab_gate', Path(__file__).with_name('esxi-lab.py'))
        labmod = importlib.util.module_from_spec(spec); spec.loader.exec_module(labmod)
        labmod.wait_visual_capture(SimpleNamespace(c={}))
        self.lab.c['visual_capture_label'] = 'cold'
        self.state['visual_capture_nonce'] = 'a' * 32; self.lab.state = self.state
        self.lab.scope_path.write_text(json.dumps(self.lab.c))
        directory = self.lab.sec / 'visual-cold'; directory.mkdir()
        record = {k: self.state[k] for k in ('uuid', 'ref', 'owner', 'visual_capture_nonce')}
        record.update(scope_sha256=hashlib.sha256(self.lab.scope_path.read_bytes()).hexdigest(),
                      power_state='poweredOff', monotonic_ns=10_000_000_000)
        path = directory / 'armed.json'
        for field, bad in [('visual_capture_nonce', 'b' * 32), ('uuid', 'wrong'), ('scope_sha256', 'wrong'),
                           ('power_state', 'poweredOn'), ('monotonic_ns', 1)]:
            with self.subTest(field=field):
                path.write_text(json.dumps(dict(record, **{field: bad})))
                with mock.patch.object(labmod.time, 'monotonic_ns', return_value=12_000_000_000):
                    with self.assertRaises(labmod.Refused):
                        labmod.wait_visual_capture(self.lab, clock=lambda: self.now, pause=self.sleep)
        path.write_text(json.dumps(record))
        with mock.patch.object(labmod.time, 'monotonic_ns', return_value=12_000_000_000):
            labmod.wait_visual_capture(self.lab, clock=lambda: self.now, pause=self.sleep)
        path.unlink()
        with self.assertRaisesRegex(labmod.Refused, 'remains powered off'):
            labmod.wait_visual_capture(self.lab, clock=lambda: self.now, pause=self.sleep)
        self.assertEqual(self.now, 30); self.lab.gov.assert_not_called()

    def test_observer_arms_gate_after_owned_poweroff_and_private_acl(self):
        self.lab.c['visual_capture_label'] = 'cold'; self.state['visual_capture_nonce'] = 'a' * 32
        self.lab.scope_path.write_text(json.dumps(self.lab.c)); self.ledger()
        states = iter(['poweredOff'] + ['poweredOn'] * 30)
        self.lab.vm.side_effect = lambda **unused: {'runtime': {'powerState': next(states)}}
        result = self.run_capture()
        self.assertTrue(result['observed_powered_off_before_capture']); self.acl.assert_called_once()
        armed = json.loads((self.lab.sec / 'visual-cold/armed.json').read_bytes())
        self.assertEqual(armed['visual_capture_nonce'], self.state['visual_capture_nonce'])
        self.assertEqual(armed['uuid'], self.state['uuid'])


class GuestInspectionTests(unittest.TestCase):
    def test_empty_console_open_bounds_and_readonly_ioctl(self):
        import sys
        fake_fcntl = SimpleNamespace(ioctl=mock.Mock(return_value=struct.pack('i', 0)))
        spec = importlib.util.spec_from_file_location('visual_inspect', Path(__file__).with_name('visual-console-inspect.py'))
        with mock.patch.dict(sys.modules, {'fcntl': fake_fcntl}):
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        with mock.patch.object(module.subprocess, 'run', return_value=SimpleNamespace(returncode=124, stdout=b'', stderr=b'SYNTHETIC_SECRET')) as run:
            value = module.console_open()
        self.assertEqual(run.call_args.args[0], ['timeout', '--signal=TERM', '--kill-after=1s', '3s', 'sh', '-c', ': > /dev/console'])
        self.assertEqual(run.call_args.kwargs['timeout'], 6)
        self.assertEqual(value['exit'], 124); self.assertNotIn('SYNTHETIC_SECRET', json.dumps(value))
        with mock.patch.multiple(module.os, O_NOCTTY=256, O_NONBLOCK=2048, create=True), \
             mock.patch.object(module.os, 'open', return_value=42), mock.patch.object(module.os, 'close') as close:
            self.assertEqual(module.vt_mode()['mode'], 0)
        fake_fcntl.ioctl.assert_called_once_with(42, 0x4B3B, bytes(4)); close.assert_called_once_with(42)


if __name__ == '__main__': unittest.main()
