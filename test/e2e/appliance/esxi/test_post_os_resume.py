import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('resume', Path(__file__).with_name('post-os-resume.py'))
resume = importlib.util.module_from_spec(spec)
spec.loader.exec_module(resume)


class ResumeTests(unittest.TestCase):
    def test_exact_shared_tail_excludes_completed_mutations(self):
        source = Path(__file__).parents[1] / 'lab/appliance-lab.sh'
        body = resume.tail(source.read_bytes())
        self.assertIn("culvert-os-update reboot", body)
        self.assertIn('api GET /api/backups', body)
        for forbidden in ('culvert-os-update os', 'signed_update_rollback', 'POST /api/setup'):
            self.assertNotIn(forbidden, body)
        with self.assertRaisesRegex(ValueError, 'unexpected shared'):
            resume.tail(source.read_bytes() + b'\n')

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


if __name__ == '__main__':
    unittest.main()
