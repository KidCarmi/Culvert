"""Offline only: execute real controller logic using bounded fake transports."""
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('status_cache_probe', Path(__file__).with_name('status-cache-probe.py'))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

BASELINE = {'agent_version': 'v1.2.3', 'backup': {'filename': 'a.enc', 'size_bytes': 10, 'encrypted': True}}


class Clock:
    now = 0

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class Client:
    host, cookie = '192.0.2.1', 'secret-cookie'

    def public(self, kind, deadline):
        return {'ok': True}


class ProbeTests(unittest.TestCase):
    def test_cancel_handshake_then_headers_then_one_close(self):
        calls = []
        class Sock:
            def settimeout(self, duration):
                assert duration == 0.1
            def recv(self, length):
                assert length == 1
                calls.append('wait')
                raise TimeoutError()
            def shutdown(self, direction):
                calls.append('shutdown')
        class Conn:
            sock = Sock()
            def connect(self):
                calls.append('TLS')
            def request(self, method, path, headers):
                calls.append((method, path))
            def close(self):
                calls.append('close')
        row = probe.cancel_once(Client(), Conn, iter([1, 2, 100000002]).__next__)
        self.assertEqual(calls, ['TLS', ('GET', '/api/maintenance-agent'), 'wait', 'shutdown', 'close'])
        self.assertFalse(row['response_data_before_cancel'])
        self.assertTrue(row['within_schedule_tolerance'])
        self.assertNotIn('secret-cookie', json.dumps(row))

    def test_private_transport_failure_never_copies_error_message(self):
        class Broken:
            cookie = 'secret-cookie'
            def request(self, *args, **kwargs):
                raise ValueError('password=hunter2 Cookie=secret-cookie')
        row = probe.observation(Broken(), '/api/maintenance-agent', 0.9, 'status')
        self.assertFalse(row['transport_ok'])
        self.assertNotIn('hunter2', json.dumps(row))
        self.assertNotIn('secret-cookie', json.dumps(row))

    def test_uuid_binding_refuses_different_owner_before_network(self):
        lab = SimpleNamespace(state={'uuid': '564de9b1-cdf7-0472-e998-f3f50d80816d'})
        with self.assertRaisesRegex(ValueError, 'owned UUID differs'):
            probe.verify_binding(lab, {}, {}, {}, b'', '664de9b1-cdf7-0472-e998-f3f50d80816d')

    def test_exactly_one_cancel_one_backup_twenty_polls_and_ttl_wait(self):
        clock, calls, records = Clock(), [], []
        def cancel(client):
            calls.append(('cancel', clock.now))
            return {'cancelled': True}
        def observe(client, path, timeout, kind):
            calls.append((path, timeout))
            return {'transport_ok': True, 'kind': kind}
        with patch.object(probe.recovery, 'sample', return_value={'healthy': True}):
            result = probe.experiment(Client(), BASELINE, records.append, clock.clock, clock.sleep, cancel, observe)
        self.assertEqual(calls.count(('cancel', 17)), 1)
        self.assertEqual(calls.count(('/api/backups', 5)), 1)
        self.assertEqual(calls.count(('/api/maintenance-agent', 0.9)), 20)
        self.assertEqual(clock.now, 36)
        self.assertEqual(result['historical_A1_attribution'], 'not_established')

    def test_unhealthy_baseline_never_cancels(self):
        with patch.object(probe.recovery, 'sample', return_value={'healthy': False}):
            with self.assertRaises(ValueError):
                probe.experiment(Client(), BASELINE, lambda x: None, cancel=lambda c: self.fail('cancelled'))

    def test_transport_failure_stops_further_polls(self):
        clock, calls = Clock(), []
        def observe(client, path, timeout, kind):
            calls.append(kind)
            return {'transport_ok': False}
        with patch.object(probe.recovery, 'sample', return_value={'healthy': True}):
            probe.experiment(Client(), BASELINE, lambda x: None, clock.clock, clock.sleep, lambda c: {}, observe)
        self.assertEqual(calls.count('status'), 1)
        self.assertEqual(calls.count('fresh_backup_listing'), 1)

    def test_evidence_limit_and_exclusive_name(self):
        stream = io.BytesIO()
        rows = probe.PrivateRows(stream)
        for _ in range(32):
            rows.emit({'kind': 'test'})
        with self.assertRaises(ValueError):
            rows.emit({'kind': 'overflow'})
        with self.assertRaises(ValueError):
            probe.PrivateRows(io.BytesIO()).emit({'body': 'x' * probe.MAX_PRIVATE})

    def test_classification_requires_pattern_backup_recovery_and_valid_cancel(self):
        cancel = {'cancelled': True, 'response_data_before_cancel': False, 'within_schedule_tolerance': True}
        negative = {'transport_ok': True, 'http_status': 200, 'body_sha256': 'same',
                    'value': {'available': False, 'reason': 'context canceled'},
                    'started': {'monotonic_ns': 1}, 'ended': {'monotonic_ns': 2}}
        positive = {'transport_ok': True, 'http_status': 200,
                    'value': {'available': True, 'compose_stack_up': True, 'agent_version': 'v1.2.3'},
                    'started': {'monotonic_ns': 3}}
        backup = {'transport_ok': True, 'http_status': 200,
                  'value': {'available': True, 'count': 1, 'backups': [BASELINE['backup']]}}
        rows = [negative, negative, positive]
        self.assertEqual(probe.classify(cancel, rows, backup, BASELINE)['result'], 'observed')
        self.assertEqual(probe.classify(dict(cancel, response_data_before_cancel=True), rows, backup, BASELINE)['result'], 'inconclusive')
        self.assertEqual(probe.classify(cancel, rows[:-1], backup, BASELINE)['result'], 'inconclusive')
        self.assertEqual(probe.classify(cancel, rows, {}, BASELINE)['result'], 'inconclusive')
        self.assertEqual(probe.classify(cancel, rows + [{'transport_ok': False}], backup, BASELINE)['result'], 'inconclusive')


if __name__ == '__main__':
    unittest.main()
