"""Offline firstboot continuation tests. No guest, credentials or network calls."""
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('registry_precondition', Path(__file__).with_name('prepare-lab-registry.py'))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
ids = r.module('precondition_ids', Path(__file__).with_name('candidate-identities.py'))
PROFILE = ids.source_profile(ids.E2E3)


class PreconditionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.original = self.root / 'original'
        self.run = self.root / 'run'; self.sec = self.run / 'secrets'; self.sec.mkdir(parents=True)
        self.ops = self.original / '.tools/private-operations'; self.ops.mkdir(parents=True)
        self.scope = dict(PROFILE, run_dir=str(self.run), endpoint='https://192.0.2.1')
        self.lab = SimpleNamespace(c=self.scope, run=self.run, sec=self.sec, state={'uuid': 'owned'})
        self.pins = mock.patch.multiple(r, SOURCE=PROFILE['source_sha'], OVA=PROFILE['ova_sha256'], BASELINE=PROFILE['image_id'])
        self.pins.start(); self.addCleanup(self.pins.stop)
        self.manifest = {'revision': r.ORIGINAL_CONTROLLER,
                         'files': {'test/e2e/appliance/esxi/prepare-lab-registry.py': r.ORIGINAL_HELPER}}
        (self.original / '.tools/controller-freeze.json').write_text(json.dumps(self.manifest))
        (self.original / '.tools/scope-2e3.json').write_text(json.dumps(self.scope))
        self.failure = (b'Traceback (most recent call last):\n  File "<stdin>", line 30, in <module>\n'
                        b'  File "<stdin>", line 12, in need\nValueError: first boot incomplete\n\n')
        self.assertEqual(hashlib.sha256(self.failure).hexdigest(), r.ORIGINAL_TRANSPORT)
        (self.sec / 'registry-preparation-transport.txt').write_bytes(self.failure)
        (self.sec / 'registry-preparation-attempt.json').write_text(json.dumps({'status': 'blocked', 'uuid': 'owned'}))
        self.result('a', b'1\n' + self.failure[:-1])
        self.proof = {'schema': 1, 'uid': 0, 'source_sha': ids.E2E3,
                      'boot_id': '63283258-a14f-4239-86c5-b6e73b5bc16a', 'firstboot_complete': True,
                      'registry_root_exists': False, 'registry_ca_exists': False, 'registry_containers': []}
        raw = json.dumps(self.proof).encode()
        (self.ops / 'firstboot-registry-observation.out').write_bytes(raw)
        self.result('b', b'0\n' + raw)

    def result(self, token, raw):
        directory = self.sec / ('transport-' + token * 48); directory.mkdir(exist_ok=True)
        (directory / 'result').write_bytes(raw)

    def binding(self):
        verify = mock.Mock(return_value=self.manifest)
        with mock.patch.object(r, 'module', return_value=SimpleNamespace(verify=verify)):
            value = r.continuation_binding(self.lab, self.original)
        verify.assert_called_once_with(self.original / '.tools/controller-freeze.json', self.original)
        return value

    def test_exact_failure_owner_payload_and_original_evidence_remain_bound(self):
        before = {p: p.read_bytes() for p in self.sec.rglob('*') if p.is_file()}
        record = self.binding()
        self.assertEqual(record['uuid'], 'owned')
        self.assertEqual(record['original_payload_sha256'], hashlib.sha256(r.guest_script()).hexdigest())
        self.assertEqual(before, {p: p.read_bytes() for p in self.sec.rglob('*') if p.is_file()})
        for change in ('controller', 'helper', 'owner', 'transport', 'result', 'missing-result', 'duplicate-result', 'observation', 'receipt'):
            with self.subTest(change=change):
                manifest = copy.deepcopy(self.manifest)
                if change == 'controller': self.manifest['revision'] = '0' * 40
                if change == 'helper': self.manifest['files'][next(iter(self.manifest['files']))] = '0' * 64
                if change == 'owner': self.lab.state['uuid'] = 'other'
                if change == 'transport': (self.sec / 'registry-preparation-transport.txt').write_bytes(self.failure + b'changed')
                if change == 'result': self.result('a', b'1\nwrong')
                if change == 'missing-result': (self.sec / ('transport-' + 'a' * 48) / 'result').unlink()
                if change == 'duplicate-result': self.result('c', b'1\n' + self.failure[:-1])
                if change == 'observation': (self.ops / 'firstboot-registry-observation.out').write_text(json.dumps(dict(self.proof, registry_ca_exists=True)))
                if change == 'receipt': (self.sec / 'registry-preparation-receipt.json').touch()
                with self.assertRaises(ValueError): self.binding()
                self.manifest = manifest; self.lab.state['uuid'] = 'owned'
                (self.sec / 'registry-preparation-transport.txt').write_bytes(self.failure)
                self.result('a', b'1\n' + self.failure[:-1])
                (self.sec / ('transport-' + 'c' * 48) / 'result').unlink(missing_ok=True)
                (self.ops / 'firstboot-registry-observation.out').write_bytes(json.dumps(self.proof).encode())
                (self.sec / 'registry-preparation-receipt.json').unlink(missing_ok=True)

    def test_guest_wait_is_bounded_and_no_docker_mutation_is_issued(self):
        guest = {}; exec(r.WAIT_GUEST, guest)
        clock = [0.0]; sleeps = []
        def pause(seconds): sleeps.append(seconds); clock[0] += seconds
        with self.assertRaisesRegex(ValueError, 'expired'):
            guest['wait_complete'](lambda: False, lambda: clock[0], pause)
        self.assertEqual(clock[0], 900); self.assertEqual(len(sleeps), 180)
        clock[0] = 0
        guest['wait_complete'](lambda: clock[0] >= 10, lambda: clock[0], pause)
        self.assertEqual(clock[0], 10)
        with mock.patch.object(guest['os'].path, 'lexists', return_value=False), \
             mock.patch.object(guest['subprocess'], 'run') as run:
            guest['audit'](containers=False); run.assert_not_called()
            run.return_value = SimpleNamespace(returncode=0, stdout=b'culvert\n')
            guest['audit']()
            self.assertEqual(run.call_args.args[0], ['docker', 'ps', '-a', '--format', '{{.Names}}'])
            run.return_value.stdout = b'culvert-lab-registry\n'
            with self.assertRaises(ValueError): guest['audit']()

    def test_failed_wait_records_privately_and_refuses_mutation(self):
        args = SimpleNamespace(scope=Path('scope'), bind='192.0.2.1')
        with mock.patch.object(r, 'console_run', return_value=SimpleNamespace(returncode=1, stdout=b'SYNTHETIC_PRIVATE_ERROR', stderr=b'')) as run:
            with self.assertRaisesRegex(ValueError, 'no registry mutation'):
                r.wait_provisioning(args, self.lab, 'registry-preparation-firstboot-continuation', self.binding())
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[2], 960)
        payload = run.call_args.args[1]
        self.assertNotIn(b'docker pull', payload)
        self.assertNotIn(b'root.mkdir', payload)
        self.assertIn(ids.E2E3.encode(), payload)
        self.assertIn(PROFILE['image_id'].encode(), payload)
        self.assertEqual(json.loads((self.sec / 'registry-preparation-attempt.json').read_bytes()), {'status': 'blocked', 'uuid': 'owned'})
        self.assertFalse((self.sec / 'registry-preparation-firstboot-continuation-dispatch.json').exists())

    def test_changed_guest_source_or_boot_refuses_before_wait(self):
        guest = {}; exec(r.WAIT_GUEST, guest)
        config = {'source': ids.E2E3, 'image': PROFILE['image_id'], 'boot_id': self.proof['boot_id']}
        build = {'source': {'git_commit': ids.E2E3, 'git_dirty': False},
                 'application': {'index_digest': PROFILE['image_id']}}
        for changed in ('source', 'boot'):
            value = copy.deepcopy(build)
            if changed == 'source': value['source']['git_commit'] = ids.D698
            with mock.patch.object(guest['os'], 'geteuid', return_value=0, create=True), \
                 mock.patch.object(guest['pathlib'], 'Path') as path:
                path.return_value.read_bytes.return_value = json.dumps(value).encode()
                path.return_value.read_text.return_value = 'another-boot'
                guest['wait_complete'] = mock.Mock()
                with self.assertRaises(ValueError): guest['main'](config)
                guest['wait_complete'].assert_not_called()

    def test_main_wait_failure_never_dispatches_fixture_or_exposes_private_error(self):
        current_hash = hashlib.sha256(Path(r.__file__).read_bytes()).hexdigest()
        self.scope['controller_manifest'] = str(self.root / 'new-freeze.json')
        self.lab.vm = mock.Mock()
        boot = SimpleNamespace(module=SimpleNamespace(Lab=mock.Mock(return_value=self.lab),
                    validate_scope=mock.Mock(), atomic_json=lambda p, v: p.write_text(json.dumps(v))),
                    private_directory=mock.Mock())
        freeze = SimpleNamespace(verify=mock.Mock(return_value={'revision': '1' * 40,
                  'files': {'test/e2e/appliance/esxi/prepare-lab-registry.py': current_hash}}))
        real_module = r.module
        def load(name, path):
            if name == 'registry_bootstrap': return boot
            if name == 'registry_current_freeze': return freeze
            return real_module(name, path)
        binding = self.binding()
        original = (self.sec / 'registry-preparation-attempt.json').read_bytes()
        argv = ['registry', '--scope', 'synthetic', '--bind', '192.0.2.1',
                '--resume-firstboot-incomplete', '--original-controller-root', str(self.original)]
        error = io.StringIO()
        with mock.patch.object(r, 'module', side_effect=load), mock.patch.object(r.sys, 'argv', argv), \
             mock.patch.object(r, 'continuation_binding', return_value=binding), \
             mock.patch.object(r, 'console_run', return_value=SimpleNamespace(returncode=1, stdout=b'SYNTHETIC_SECRET', stderr=b'')) as run, \
             contextlib.redirect_stderr(error):
            self.assertEqual(r.main(), 90)
            self.assertEqual(r.main(), 90)  # Exclusive new marker prevents another attempt.
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[2], 960)
        self.assertNotIn('SYNTHETIC_SECRET', error.getvalue())
        self.assertEqual((self.sec / 'registry-preparation-attempt.json').read_bytes(), original)
        record = json.loads((self.sec / 'registry-preparation-firstboot-continuation-attempt.json').read_bytes())
        self.assertEqual(record['status'], 'blocked')
        self.assertFalse((self.sec / 'registry-preparation-firstboot-continuation-dispatch.json').exists())


if __name__ == '__main__':
    unittest.main()
