"""Exercise Bash restore evidence with synthetic API responses; no guest calls."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
BASH=shutil.which('bash') if os.name!='nt' else 'C:/Program Files/Git/bin/bash.exe'

@unittest.skipUnless(BASH and Path(BASH).exists(),'Bash unavailable')
class RestoreEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);(self.root/'actual-restore').mkdir()

    def shell(self,command):
        env=dict(os.environ,PY_EXE=Path(sys.executable).as_posix(),HELPER=(HERE/'restore-checks.sh').as_posix(),EV=self.root.as_posix(),SEC=self.root.as_posix())
        return subprocess.run([BASH,'-c','set -e; python3(){ "$PY_EXE" "$@"; }; source "$HELPER"; '+command],env=env,text=True,capture_output=True)

    def snapshot(self,phase,domains):
        (self.root/'actual-restore'/('allowlist-'+phase+'.txt')).write_text(json.dumps({'domains':domains})+'\n200\n')

    def test_actual_traffic_failure_retained_without_body_or_secret(self):
        result=self.shell("esxi_restore_record_traffic before 403 000; esxi_restore_record_traffic after 'secret-body' 403")
        self.assertEqual(result.returncode,0,result.stderr)
        before=json.loads((self.root/'09-restore-traffic-before.json').read_bytes())
        self.assertEqual((before['allowed_http_status'],before['blocked_http_status']),('403','000'))
        self.assertEqual((before['expected_allowed'],before['expected_blocked']),('200','403'))
        self.assertNotIn('secret-body',(self.root/'09-restore-traffic-after.json').read_text())
        self.assertNotEqual(self.shell('esxi_restore_record_traffic before 200 403').returncode,0)

    def test_snapshot_is_get_only_and_exclusive(self):
        command="api(){ [[ $1 == GET && $2 == /api/security-scan/feeds/domain-allowlist ]]; printf '%s\\n' '{\"domains\":[]}' 200; }; esxi_restore_record_allowlist before"
        self.assertEqual(self.shell(command).returncode,0)
        original=(self.root/'actual-restore/allowlist-before.txt').read_bytes()
        self.assertNotEqual(self.shell(command).returncode,0)
        self.assertEqual((self.root/'actual-restore/allowlist-before.txt').read_bytes(),original)

    def test_exact_set_and_marker_loss_preserve_private_verdict(self):
        expected=['example.com','allowlist-survives-marker.example','custom.example']
        self.snapshot('before',expected);self.snapshot('after',['example.com'])
        self.assertEqual(self.shell('esxi_restore_assert_allowlist before').returncode,0)
        self.assertNotEqual(self.shell('esxi_restore_assert_allowlist after').returncode,0)
        value=json.loads((self.root/'actual-restore/allowlist-after-verdict.json').read_bytes())
        self.assertEqual(value['expected'],sorted(expected));self.assertEqual(value['actual'],['example.com'])
        self.assertEqual(value['result'],'fail');self.assertFalse(value['mutation_performed'])

    def test_source_marker_missing_is_not_exercised(self):
        self.snapshot('before',['example.com'])
        self.assertNotEqual(self.shell('esxi_restore_assert_allowlist before').returncode,0)
        self.assertIn('marker',json.loads((self.root/'actual-restore/allowlist-before-verdict.json').read_bytes())['reason'])

    def test_unchanged_full_set_passes(self):
        expected=['example.com','allowlist-survives-marker.example','custom.example']
        self.snapshot('before',expected);self.snapshot('after',list(reversed(expected)))
        result=self.shell('esxi_restore_assert_allowlist before; esxi_restore_assert_allowlist after')
        self.assertEqual(result.returncode,0,result.stderr)

if __name__=='__main__':unittest.main()
