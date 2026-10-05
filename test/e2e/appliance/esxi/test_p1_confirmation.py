"""Bounded convergence and evidence separation tests; never access a guest."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


guest = load('confirmation_guest', 'p1-guest-checks.py')
controller = load('confirmation_controller', 'p1-regressions.py')
EXPECTED = {'interface': 'ens160', 'address': '192.0.2.2/24', 'gateway': '192.0.2.1'}


class Clock:
    now = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class ConfirmationTests(unittest.TestCase):
    def test_transient_gap_and_later_flap_are_retained_before_stable_pass(self):
        clock, outcomes = Clock(), iter([False, True, False, True, True, True])
        def observe(expected, deadline):
            self.assertEqual(expected, EXPECTED)
            return {'routes': [], 'addresses': [], 'errors': [], 'matches': next(outcomes)}
        with tempfile.TemporaryDirectory() as temp:
            result = guest.wait_network_stable(EXPECTED, Path(temp), clock, clock.sleep, observe)
            rows = [json.loads(line) for line in (Path(temp) / 'rollback-network-observations.jsonl').read_text().splitlines()]
            self.assertEqual(rows, result['observations'])
            self.assertEqual([row['matches'] for row in rows], [False, True, False, True, True, True])
            self.assertEqual(result['elapsed_seconds'], 10)
            self.assertFalse(result['immediate_match'])
            with self.assertRaises(FileExistsError):
                guest.wait_network_stable(EXPECTED, Path(temp), clock, clock.sleep, observe)

    def test_persistent_gap_hits_deadline_and_leaves_observations(self):
        clock = Clock()
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, '60 seconds'):
                guest.wait_network_stable(EXPECTED, Path(temp), clock, clock.sleep,
                    lambda expected, deadline: {'matches': False, 'routes': [], 'addresses': [], 'errors': []})
            self.assertEqual(clock.now, 60)
            rows = (Path(temp) / 'rollback-network-observations.jsonl').read_text().splitlines()
            self.assertEqual(len(rows), 30)
            self.assertTrue(all(json.loads(row)['matches'] is False for row in rows))

    def test_route_absence_still_captures_address_and_wrong_interface_cannot_pass(self):
        addresses = [{'ifname': 'ens160', 'addr_info': [{'scope': 'global', 'local': '192.0.2.2', 'prefixlen': 24}]}]
        with mock.patch.object(guest, 'command', side_effect=[json.dumps([]), json.dumps(addresses)]) as command:
            row = guest.observe_network(EXPECTED, guest.time.monotonic() + 60)
        self.assertFalse(row['matches'])
        self.assertEqual(row['addresses'], addresses)
        self.assertEqual(command.call_count, 2)
        for interface, expected_result in [('ens161', False), ('ens160', True)]:
            routes = [{'dev': interface, 'gateway': EXPECTED['gateway']}]
            with mock.patch.object(guest, 'command', side_effect=[json.dumps(routes), json.dumps(addresses)]):
                self.assertEqual(guest.observe_network(EXPECTED, guest.time.monotonic() + 60)['matches'], expected_result)

    def test_prevalidation_requires_unchanged_original_and_never_modifies_it(self):
        before = {'identity': {'source': guest.SOURCE, 'boot_id': 'original'}, 'network': EXPECTED,
                  'netplan': {'exists': False}}
        with tempfile.TemporaryDirectory() as temp:
            original = Path(temp)
            (original / 'netplan-shim').mkdir()
            baseline = json.dumps(before).encode()
            trace = ('\n'.join(guest.INJECTION_SEQUENCE) + '\n').encode()
            (original / 'network-before.json').write_bytes(baseline)
            (original / 'netplan-shim' / 'trace').write_bytes(trace)
            with mock.patch.object(guest, 'ORIGINAL_STATE', original):
                self.assertTrue(guest.confirmation_prevalidation(before)['source_unchanged'])
                changed = copy.deepcopy(before)
                changed['identity']['boot_id'] = 'rebooted'
                with self.assertRaises(ValueError):
                    guest.confirmation_prevalidation(changed)
                (original / 'network-injection-passed.json').write_text('{}')
                with self.assertRaises(ValueError):
                    guest.confirmation_prevalidation(before)
            self.assertEqual((original / 'network-before.json').read_bytes(), baseline)
            self.assertEqual((original / 'netplan-shim' / 'trace').read_bytes(), trace)

    def test_separate_namespace_requires_stopped_original_blocked_attempt(self):
        with tempfile.TemporaryDirectory() as temp:
            private = Path(temp)
            initial = controller.campaigns.directory(private, 'initial')
            initial.mkdir()
            marker = initial / 'network-before.attempt.json'
            raw = json.dumps({'status': 'blocked', 'uuid': 'owned-uuid'}).encode()
            marker.write_bytes(raw)
            result = controller.campaigns.initial_failure(private, 'owned-uuid', 'confirmation')
            self.assertEqual(result['result'], 'blocked')
            self.assertNotEqual(initial, controller.campaigns.directory(private, 'confirmation'))
            (initial / 'stage.lock').mkdir()
            with self.assertRaises(ValueError):
                controller.campaigns.initial_failure(private, 'owned-uuid', 'confirmation')
            (initial / 'stage.lock').rmdir()
            with self.assertRaises(ValueError):
                controller.campaigns.initial_failure(private, 'other-uuid', 'confirmation')
            self.assertEqual(marker.read_bytes(), raw)

    def test_controller_requires_recorded_convergence_and_original_binding(self):
        clock = Clock()
        with tempfile.TemporaryDirectory() as temp:
            convergence = guest.wait_network_stable(EXPECTED, Path(temp), clock, clock.sleep,
                lambda expected, deadline: {'matches': True, 'routes': [], 'addresses': [], 'errors': []})
        value = {'campaign': 'confirmation', 'convergence': convergence,
                 'initial_failure': {'source_unchanged': True, 'original_baseline_sha256': 'a' * 64,
                                     'original_trace_sha256': 'b' * 64}}
        self.assertTrue(controller.valid_confirmation(value))
        for field, altered in [('elapsed_seconds', 61), ('max_seconds', 120), ('immediate_match', False),
                               ('observations', convergence['observations'][:2])]:
            bad = copy.deepcopy(value)
            bad['convergence'][field] = altered
            self.assertFalse(controller.valid_confirmation(bad), field)
        value['initial_failure']['source_unchanged'] = False
        self.assertFalse(controller.valid_confirmation(value))


if __name__ == '__main__':
    unittest.main()
