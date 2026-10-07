import importlib.util
import base64
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('resume', Path(__file__).with_name('post-os-resume.py'))
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


class ResumeTests(unittest.TestCase):
    def test_exact_shared_tail_excludes_completed_mutations(self):
        source = Path(__file__).with_name('fixtures') / 'post-os-resume-historical.sh'
        historical = source.read_bytes().replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        body = resume.tail(historical)
        self.assertIn("culvert-os-update reboot", body)
        self.assertIn('api GET /api/backups', body)
        for forbidden in ('culvert-os-update os', 'signed_update_rollback', 'POST /api/setup'):
            self.assertNotIn(forbidden, body)
        with self.assertRaisesRegex(ValueError, 'unexpected shared'):
            resume.tail(historical + b'\n')
        current = Path(__file__).parents[1] / 'lab/appliance-lab.sh'
        with self.assertRaisesRegex(ValueError, 'unexpected shared'):
            resume.tail(current.read_bytes())

    def test_reentry_after_reboot_dispatch_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            ev = root / 'evidence'; ev.mkdir()
            private = root / 'secrets/p1-regressions'; private.mkdir(parents=True)
            (private/'network-before.attempt.json').write_text(json.dumps({'uuid':'owned','status':'blocked'}))
            (root/'owned.json').write_text(json.dumps({'uuid':'owned'}))
            names = ['firstboot-steps','console-login','image-identity','admin-login','agent-backup',
                     'backup-listed','restore-dry-run','restore-complete','unsigned-apply-refused',
                     'signed-apply','signed-rollback','os-update']
            (ev/'checks.jsonl').write_text('\n'.join(json.dumps({'step':'7','check':name,'result':'pass'}) for name in names))
            for name in ('07-check-after-update.txt','esxi-boot-id-before.txt','09-post-backup-mutation-name.txt'):
                (ev/name).write_text('evidence')
            scope = {'source_sha':resume.SOURCE,'ova_sha256':resume.OVA}
            self.assertEqual(resume.validate(scope,root)['uuid'], 'owned')
            (ev/'07-reboot.txt').write_text('')
            with self.assertRaisesRegex(ValueError,'already dispatched'):
                resume.validate(scope,root)
            (ev/'07-reboot.txt').unlink()
            (ev/'checks-post-os-resume.jsonl').write_text(json.dumps({'check':'post-os-resume','result':'info'}))
            (ev/'post-os-resume-boot-id.txt').write_text('evidence')
            confirm=root/'secrets/p1-regressions-confirmation'; confirm.mkdir()
            (confirm/'network-before.attempt.json').write_text(json.dumps({'status':'blocked','campaign':'confirmation'}))
            self.assertEqual(resume.validate(scope,root,True)['uuid'],'owned')
            (ev/'checks-post-os-resume.jsonl').write_text(json.dumps({'check':'reboot','result':'pass'}))
            with self.assertRaisesRegex(ValueError,'progressed beyond precheck'):
                resume.validate(scope,root,True)


class D698ResumeTests(unittest.TestCase):
    def fixture(self, root):
        ev = root / 'evidence'; ev.mkdir()
        private = root / 'secrets/p1-regressions'; private.mkdir(parents=True)
        (private / 'network-before.attempt.json').write_text(json.dumps({'uuid': 'owned', 'status': 'blocked', 'campaign': 'initial'}))
        (root / 'owned.json').write_text(json.dumps({'uuid': 'owned'}))
        names = ['firstboot-steps', 'console-login', 'image-identity', 'admin-login', 'agent-backup',
                 'backup-listed', 'restore-dry-run', 'restore-complete', 'unsigned-apply-refused',
                 'signed-apply', 'signed-rollback', 'os-update']
        (ev / 'checks.jsonl').write_text('\n'.join(json.dumps({'step': '7', 'check': name, 'result': 'pass'}) for name in names))
        for name in ('07-check-after-update.txt', 'esxi-boot-id-before.txt', '09-post-backup-mutation-name.txt'):
            (ev / name).write_text('evidence')
        output = (b'Traceback (most recent call last):\n'
                  b'  File "p1-guest-checks.py", line 219, in network_before\n'
                  b'ValueError: one default IPv4 route required\n')
        encode = lambda value: {'bytes': len(value), 'base64': base64.b64encode(value).decode(), 'truncated': False}
        (private / 'console-transport-1.json').write_text(json.dumps({'exit': 1, 'stdout': encode(output), 'stderr': encode(b'')}))
        transport = root / ('secrets/transport-' + 'a' * 48); transport.mkdir()
        (transport / 'result').write_bytes(b'1\n' + output)
        spec = importlib.util.spec_from_file_location('identities', Path(__file__).with_name('candidate-identities.py'))
        identities = importlib.util.module_from_spec(spec); spec.loader.exec_module(identities)
        return dict(identities.source_profile(identities.D698), max_vms=1)

    def test_d698_exact_tail_excludes_completed_phases_and_checks_raw_before_normalization(self):
        raw = (Path(__file__).with_name('fixtures') / 'post-os-resume-d698.sh').read_bytes().replace(b'\r\n', b'\n')
        for source in (raw, raw.replace(b'\n', b'\r\n')):
            body = resume.tail(source, resume.D698)
            self.assertIn('culvert-os-update reboot', body)
            self.assertIn('lab_after_reboot_observation', body)
            self.assertIn('agent_status_verdict', body)
            for forbidden in ('culvert-os-update os', 'signed_update_rollback', 'POST /api/setup', 'lab_before_reboot'):
                self.assertNotIn(forbidden, body)
            with self.assertRaises(ValueError):
                resume.tail(source + b'\n', resume.D698)
        with self.assertRaises(ValueError):
            resume.tail(raw, resume.SOURCE)

    def test_current_shared_library_cannot_resume_historical_d698_campaign(self):
        raw = (Path(__file__).parents[1] / 'lab/appliance-lab.sh').read_bytes()
        with self.assertRaisesRegex(ValueError, 'unexpected shared'):
            resume.tail(raw, resume.D698)

    def test_retained_route_gap_is_required_and_never_replayed_after_dispatch(self):
        for change in ('none', 'wrong-image', 'earlier-fail', 'reboot', 'confirmation', 'second-transport', 'bad-result', 'wrong-error'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); scope = self.fixture(root)
                private = root / 'secrets/p1-regressions'
                if change == 'wrong-image': scope['image_id'] = 'sha256:' + '0' * 64
                if change == 'earlier-fail':
                    with (root / 'evidence/checks.jsonl').open('a') as out:
                        out.write('\n' + json.dumps({'step': '7', 'check': 'unexpected', 'result': 'fail'}))
                if change == 'reboot': (root / 'evidence/07-reboot.txt').touch()
                if change == 'confirmation': (root / 'secrets/p1-regressions-confirmation').mkdir()
                if change == 'second-transport': (private / 'console-transport-2.json').write_bytes((private / 'console-transport-1.json').read_bytes())
                if change == 'bad-result': next((root / 'secrets').glob('transport-*/result')).write_bytes(b'wrong')
                if change == 'wrong-error':
                    path = private / 'console-transport-1.json'; value = json.loads(path.read_bytes())
                    raw = base64.b64decode(value['stdout']['base64']).replace(b'line 219', b'line 173')
                    value['stdout']['base64'] = base64.b64encode(raw).decode(); path.write_text(json.dumps(value))
                if change == 'none':
                    record = resume.validate(scope, root)
                    self.assertEqual(record['source'], resume.D698)
                    self.assertIn('measurement only', record['qualification_scope'])
                    self.assertTrue(record['retained_failure_binding']['authenticated_result_sha256'])
                    with self.assertRaises(ValueError): resume.validate(scope, root, continuation=True)
                else:
                    with self.assertRaises(ValueError): resume.validate(scope, root)


if __name__ == '__main__':
    unittest.main()
