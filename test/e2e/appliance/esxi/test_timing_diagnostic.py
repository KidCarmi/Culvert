"""Synthetic/local-only timing observer tests; no guest or hypervisor calls."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controller = load('timing_controller', 'timing-diagnostic.py')
guest = load('timing_guest', 'timing-diagnostic-guest.py')


class TimingTests(unittest.TestCase):
    def test_ssh_observer_uses_only_operator_and_retains_pins(self):
        lab = mock.Mock()
        lab.ssh_command.return_value = ['ssh', '-o', 'StrictHostKeyChecking=yes', 'culvert@192.0.2.1']
        with mock.patch.object(controller, 'bounded_command', return_value=('ok', b'{"schema_version":1,"phase":"ready"}')) as run:
            self.assertTrue(controller.ssh_probe(lab, '192.0.2.1', 22)['operator_ready'])
        argv = run.call_args.args[0]
        self.assertEqual(argv[-2:], ['culvert-operator@192.0.2.1', 'status-json'])
        self.assertIn('StrictHostKeyChecking=yes', argv)

    def test_return_requires_observed_failure_and_never_proves_reboot(self):
        states = {}
        def probe(result, ready=True):
            return controller.transition(states, {'probe': 'operator_status', 'result': result,
                                                 'operator_ready': ready}, True)
        self.assertFalse(probe('ok')['first_success_after_observed_failure'])
        self.assertFalse(probe('ok', False)['first_success_after_observed_failure'])
        self.assertTrue(probe('ok')['first_success_after_observed_failure'])
        self.assertFalse(probe('ok')['first_success_after_observed_failure'])
        self.assertNotIn('boot', json.dumps(states))

    def test_status_exports_only_allowlisted_facts(self):
        raw = json.dumps({'schema_version': 1, 'phase': 'ready', 'application_responding': True,
                          'management_available': True, 'password': 'synthetic-not-for-export',
                          'interfaces': ['private'], 'firstboot': {'anything': 'hidden'}})
        result = controller.public_status(raw)
        self.assertEqual(result, {'phase': 'ready', 'operator_ready': True,
                                 'application_responding': True, 'management_available': True})
        self.assertNotIn('synthetic', json.dumps(result))
        self.assertFalse(controller.public_status('{"schema_version":1,"phase":"provisioned"}')['operator_ready'])
        for value in ('[]', '{}', '{"schema_version":2}'):
            with self.assertRaises(ValueError):
                controller.public_status(value)

    def test_measurement_never_exports_exception(self):
        def failure():
            raise ValueError('synthetic-private-detail')
        result = controller.measured('operator_status', failure)
        self.assertEqual(result['result'], 'failed')
        self.assertNotIn('private-detail', json.dumps(result))
        self.assertGreaterEqual(result['elapsed_seconds'], 0)
        self.assertGreaterEqual(result['ended']['monotonic_ns'], result['started']['monotonic_ns'])

    def test_command_timeout_and_size_are_bounded_without_output(self):
        status, raw = controller.bounded_command([sys.executable, '-c', 'import time; time.sleep(5)'], .15)
        self.assertEqual((status, raw), ('timeout', b''))
        status, raw = controller.bounded_command([sys.executable, '-c', 'print("x"*70000)'], 3)
        self.assertEqual((status, raw), ('oversize', b''))
        status, raw = controller.bounded_command([sys.executable, '-c', 'print("synthetic"); raise SystemExit(2)'], 3)
        self.assertEqual((status, raw), ('command_failed', b''))

    def test_dispatch_marker_is_intent_only_bounded_and_strict(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'marker'
            self.assertIsNone(controller.read_marker(path))
            good = {'event': 'dispatch_intent', **controller.stamp()}
            path.write_text(json.dumps(good), encoding='utf-8')
            self.assertEqual(controller.read_marker(path), good)
            for value in ({**good, 'secret': 'synthetic'}, {**good, 'event': 'reboot_proven'},
                          {**good, 'utc': 'bad'}, {**good, 'monotonic_ns': 'bad'}):
                path.write_text(json.dumps(value), encoding='utf-8')
                with self.assertRaises(ValueError):
                    controller.read_marker(path)
            path.write_text('x' * 1025, encoding='utf-8')
            with self.assertRaises(ValueError):
                controller.read_marker(path)

    def test_marker_is_atomic_exclusive_and_no_temp_residue(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'marker'
            controller.write_marker(path)
            first = path.read_bytes()
            self.assertEqual(controller.read_marker(path)['event'], 'dispatch_intent')
            with self.assertRaises(FileExistsError):
                controller.write_marker(path)
            self.assertEqual(path.read_bytes(), first)
            self.assertEqual([p.name for p in Path(directory).iterdir()], ['marker'])

    def test_guest_spawn_error_is_sanitized(self):
        with mock.patch.object(guest.subprocess, 'Popen', side_effect=OSError('private-path')):
            row, raw = guest.command(['synthetic'], 1)
        self.assertEqual((row['result'], raw), ('spawn_failed', b''))
        self.assertNotIn('private-path', json.dumps(row))

    def test_guest_unit_selection_and_listing_body_never_leak(self):
        result = guest.parse_units(b'Id=docker.service\nActiveState=active\nExecMainStartTimestampMonotonic=123\nSecret=hidden\n\nId=unrelated.service\nActiveState=active')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['ExecMainStartTimestampMonotonic'], 123)
        self.assertNotIn('hidden', json.dumps(result))
        listed = guest.listing_result('compose_backups', b'[{"filename":"private-name","secret":"hidden"}]')
        self.assertEqual(listed, {'listing_succeeded': True, 'entry_count': 1})
        self.assertFalse(guest.listing_result('agent_backups', b'403')['listing_succeeded'])
        for raw in (b'200\nsecret', b'000', b'x'):
            with self.assertRaises(ValueError):
                guest.listing_result('agent_backups', raw)

    def test_guest_commands_are_fixed_read_only_listing(self):
        probes = guest.probes(25)
        self.assertEqual(len(probes), 2)
        self.assertIn('http://localhost/v1/backups', probes[0][1])
        self.assertIn('--list-backups', probes[1][1])
        self.assertFalse(any('--confirm' in args or 'reboot' in args for _, args, _ in probes))
        with mock.patch.object(guest.os, 'geteuid', return_value=1000, create=True):
            with self.assertRaises(ValueError):
                guest.main([])

    def test_io_pressure_accepts_numeric_fields_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'pressure'
            path.write_text('some avg10=12.34 avg60=0.00 total=12 unexpected=private\nfull avg10=0.00 total=0\n', encoding='ascii')
            value = guest.pressure(path)
            self.assertEqual(value['some']['avg10'], 12.34)
            self.assertNotIn('private', json.dumps(value))
            path.write_bytes(b'x' * 2049)
            with self.assertRaises(ValueError):
                guest.pressure(path)


if __name__ == '__main__':
    unittest.main()
