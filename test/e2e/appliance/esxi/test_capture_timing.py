"""Offline tests: no ESXi, guest, or console transport calls."""
import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace

import timing_capture


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guest = load('guest_capture', 'capture-guest-timing.py')
vm = load('vm_capture', 'capture-vm-performance.py')


class CaptureTests(unittest.TestCase):
    def test_capture_labels_cannot_escape_or_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lab = SimpleNamespace(run=root, sec=root / 'secrets', ev=root / 'evidence')
            lab.sec.mkdir()
            lab.ev.mkdir()
            for label in ('../elsewhere', '/absolute', 'a/b', 'a\\b', '', 'x' * 49):
                with self.assertRaises(ValueError):
                    timing_capture.destinations(lab, label, 'vm-performance')
            paths = timing_capture.destinations(lab, 'after-reboot', 'vm-performance')
            paths[0].write_bytes(b'synthetic')
            with self.assertRaises(ValueError):
                timing_capture.destinations(lab, 'after-reboot', 'vm-performance')

    def test_private_capture_bounds_both_streams_and_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result = timing_capture.capture([sys.executable, '-c', 'import sys; print("synthetic"); print("private",file=sys.stderr)'],
                b'', root / 'out', root / 'err', 3)
            self.assertEqual(result['exit_code'], 0)
            self.assertNotIn('private', json.dumps(result))
            result = timing_capture.capture([sys.executable, '-c', 'print("x"*3000000)'],
                b'', root / 'large', root / 'largeerr', 3)
            self.assertTrue(result['oversize'])
            self.assertEqual((root / 'large').stat().st_size, timing_capture.LIMIT)
            result = timing_capture.capture([sys.executable, '-c', 'import time; time.sleep(5)'],
                b'', root / 'slow', root / 'slowerr', .15)
            self.assertTrue(result['timeout'])

    def test_guest_summary_discards_all_unapproved_fields(self):
        rows = [{'event': 'guest_timing_started'}, {'event': 'backup_timing', 'probe': 'agent_backups',
                 'elapsed_seconds': 10.1, 'result': 'timeout', 'secret': 'synthetic-private'},
                {'event': 'guest_timing_finished'}]
        result = guest.summarize(b'\n'.join(json.dumps(row).encode() for row in rows))
        self.assertTrue(result['complete'])
        self.assertEqual(result['observation_error_count'], 1)
        self.assertNotIn('synthetic-private', json.dumps(result))
        with self.assertRaises(ValueError):
            guest.summarize(json.dumps(rows[0]).encode())

    def fixture(self):
        ref = {'type': 'VirtualMachine', 'value': 'synthetic-vm'}
        data = {'sample': [{'entity': ref, 'sampleInfo': [
            {'timestamp': '2026-10-05T01:00:00Z', 'interval': 20},
            {'timestamp': '2026-10-05T01:00:20Z', 'interval': 20},
            {'timestamp': '2026-10-05T01:00:40Z', 'interval': 20}],
            'value': [{'name': 'virtualDisk.totalReadLatency.average', 'unit': 'millisecond',
                       'instance': 'scsi0:0', 'value': [10, -1, 30]}]}]}
        return data, ref

    def test_metrics_exclude_missing_and_preserve_window_semantics(self):
        data, ref = self.fixture()
        result = vm.summarize(data, ref)
        row = result['metrics'][0]
        self.assertEqual((row['valid_samples'], row['missing_samples'], row['sample_mean']), (2, 1, 20))
        row = vm.summarize(data, ref, vm.timestamp('2026-10-05T01:00:20Z'),
                           vm.timestamp('2026-10-05T01:00:20Z'))['metrics'][0]
        self.assertEqual(row['valid_samples'], 0)
        self.assertNotIn('sample_mean', row)

    def test_metrics_refuse_other_vm_bad_units_lengths_and_nan(self):
        data, ref = self.fixture()
        bad = copy.deepcopy(data)
        bad['sample'][0]['entity']['value'] = 'other'
        with self.assertRaises(ValueError):
            vm.summarize(bad, ref)
        for key, value in [('unit', 'wrong'), ('value', [1]), ('value', [1, float('nan'), 3])]:
            bad = copy.deepcopy(data)
            bad['sample'][0]['value'][0][key] = value
            with self.assertRaises(ValueError):
                vm.summarize(bad, ref)
        for value in ('2026-10-05T01:00:00', 'private', '2026-10-05T01:00:00+02:00'):
            with self.assertRaises(ValueError):
                vm.timestamp(value)

    def test_production_window_refuses_five_minute_fallback(self):
        data, ref = self.fixture()
        self.assertEqual(vm.summarize(data, ref, required_interval=20)['intervals_seconds'], [20])
        for row in data['sample'][0]['sampleInfo']:
            row['interval'] = 300
        with self.assertRaises(ValueError):
            vm.summarize(data, ref, required_interval=20)


if __name__ == '__main__':
    unittest.main()
