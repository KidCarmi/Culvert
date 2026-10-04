"""Undispatched continuation and SSH diagnostic tests; no live calls."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('p1_continuation', Path(__file__).with_name('p1-regressions.py'))
p1 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p1)


class UndispatchedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name)
        self.folder = self.private / 'p1-regressions-confirmation'
        self.folder.mkdir()
        self.marker = self.folder / 'network-before.attempt.json'
        self.original = json.dumps({'status': 'blocked', 'uuid': 'owned', 'campaign': 'confirmation'}).encode()
        self.marker.write_bytes(self.original)
        output = json.dumps({'confirmation_state_exists': False, 'source': p1.SOURCE,
                             'boot_id': '11111111-1111-4111-8111-111111111111'}) + '\n'
        self.proof = self.private / 'observation.json'
        self.proof.write_text(json.dumps({'exit': 0, 'stdout': output, 'stderr': ''}))
        self.result = self.private / ('transport-' + 'a' * 48) / 'result'
        self.result.parent.mkdir()
        self.result.write_bytes(b'0\n' + output.encode())

    def binding(self):
        return p1.campaigns.continuation_binding(self.private, 'confirmation', 'owned', self.proof)

    def test_only_verified_separate_pass_can_satisfy_downstream(self):
        binding = self.binding()
        continued = self.folder / 'network-before.continuation-attempt.json'
        for status in ('started', 'blocked', 'pass'):
            continued.write_text(json.dumps({'status': status, 'uuid': 'owned', 'campaign': 'confirmation',
                                            'continuation': binding}))
            if status == 'pass':
                self.assertEqual(p1.campaigns.effective_stage(self.private, 'confirmation', 'network-before', 'owned')['status'], 'pass')
            else:
                with self.assertRaises(ValueError):
                    p1.campaigns.effective_stage(self.private, 'confirmation', 'network-before', 'owned')
        self.assertEqual(self.marker.read_bytes(), self.original)
        self.marker.write_bytes(self.original + b' ')
        with self.assertRaises(ValueError):
            p1.campaigns.effective_stage(self.private, 'confirmation', 'network-before', 'owned')

    def test_missing_console_receipt_or_preexisting_guest_report_refuses(self):
        self.result.unlink()
        with self.assertRaises(ValueError):
            self.binding()
        (self.folder / 'network-before.json').write_text('{}')
        with self.assertRaises(ValueError):
            self.binding()
        self.assertEqual(self.marker.read_bytes(), self.original)

    def test_drifted_proof_cannot_support_existing_pass(self):
        binding = self.binding()
        (self.folder / 'network-before.continuation-attempt.json').write_text(json.dumps(
            {'status': 'pass', 'uuid': 'owned', 'campaign': 'confirmation', 'continuation': binding}))
        report = json.loads(self.proof.read_text())
        report['stderr'] = 'failure'
        self.proof.write_text(json.dumps(report))
        with self.assertRaises(ValueError):
            p1.campaigns.effective_stage(self.private, 'confirmation', 'network-before', 'owned')

    def test_status_probe_closes_stdin_and_retains_success_and_timeout_evidence(self):
        with mock.patch.object(p1, 'operator_command', return_value=['ssh', 'fixture']), mock.patch.object(
                p1.subprocess, 'run', return_value=subprocess.CompletedProcess(['ssh'], 0, b'{}', b'')) as run:
            p1.prove_operator(None, None, None, evidence=self.folder)
            self.assertEqual(run.call_args.kwargs['stdin'], subprocess.DEVNULL)
            self.assertEqual(run.call_args.kwargs['timeout'], 60)
        with mock.patch.object(p1, 'operator_command', return_value=['ssh', 'fixture']), mock.patch.object(
                p1.subprocess, 'run', side_effect=subprocess.TimeoutExpired(['ssh'], 60, output=b'partial', stderr=b'diagnostic')):
            with self.assertRaises(subprocess.TimeoutExpired):
                p1.prove_operator(None, None, None, evidence=self.folder)
        records = [json.loads(path.read_text()) for path in self.folder.glob('operator-probe-*.json')]
        self.assertEqual(len(records), 2)
        self.assertTrue(any(row['exit'] == 0 for row in records))
        self.assertTrue(any(row['timed_out'] and row['stderr']['bytes'] == len(b'diagnostic') for row in records))


if __name__ == '__main__':
    unittest.main()
