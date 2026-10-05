"""Offline reboot timing oracles; never authenticate or contact a VM."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('production_probes', Path(__file__).with_name('production-recovery-probes.py'))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
NS = 1_000_000_000
OLD = '11111111-1111-4111-8111-111111111111'
NEW = '22222222-2222-4222-8222-222222222222'
BASELINE = {'schema': 1, 'source_sha': 'a' * 40, 'image_id': 'sha256:' + 'b' * 64,
            'policy_sha256': 'c' * 64, 'ca_sha256': 'd' * 64, 'agent_version': 'v1.0.260-candidate.gabcdef',
            'backup': {'filename': 'fixture.tar.gz.enc', 'size_bytes': 100, 'encrypted': True}}


def acceptance():
    return {'event': 'acceptance', 'schema': 1, 'kind': 'maintenance_accepted', 'cycle_id': 'reboot-1',
            'controller_monotonic_ns': 100 * NS, 'old_boot_id': OLD, 'operation_id': 'fixture-op',
            'source_sha': BASELINE['source_sha'], 'image_id': BASELINE['image_id']}


def proof():
    epoch = 1_000_000 * NS
    return {'schema': 1, 'cycle_id': 'reboot-1', 'source_sha': BASELINE['source_sha'],
            'image_id': BASELINE['image_id'], 'boot_id': NEW, 'clamav_endpoint_binding_verified': True,
            'correlation': {'guest_monotonic_ns': 100 * NS, 'guest_realtime_ns': epoch + 100 * NS,
                            'controller_started_monotonic_ns': 220 * NS, 'controller_finished_monotonic_ns': 221 * NS,
                            'controller_started_realtime_ns': epoch + 220 * NS, 'controller_finished_realtime_ns': epoch + 221 * NS},
            'samples': [{'boot_id': NEW, 'monotonic_ns': index * NS, 'realtime_ns': epoch + index * NS,
                         'clamav_ping': {'pong': True, 'started_monotonic_ns': index * NS,
                                         'ended_monotonic_ns': index * NS + 1_000_000,
                                         'elapsed_ns': 1_000_000}} for index in range(2, 112, 2)]}


def sample(second, healthy=True, outage=False):
    return {'event': 'sample', 'started_monotonic_ns': second * NS, 'ended_monotonic_ns': (second + 1) * NS,
            'admin_login_monotonic_ns': 140 * NS, 'healthy': healthy, 'external_outage': outage}


def observations():
    return [acceptance(), sample(110, False, True), sample(150), sample(155), sample(160),
            {'event': 'first_ready_backup', 'result': 'pass', 'available': True, 'archive_matches': True,
             'trigger_sample_started_monotonic_ns': 150 * NS,
             'started_monotonic_ns': 151 * NS, 'ended_monotonic_ns': 152 * NS, 'elapsed_ns': NS}]


class RecoveryProbeTests(unittest.TestCase):
    def test_verified_changed_boot_and_consecutive_oracles_pass(self):
        result = p.verify(observations(), BASELINE, proof(), confirmed_at={'monotonic_ns': 400 * NS})
        self.assertEqual(result['result'], 'pass')
        self.assertEqual(result['seconds_to_three_healthy_samples'], 61)
        self.assertEqual(result['observed_ready_monotonic_ns'], 161 * NS)
        self.assertEqual(result['controller_confirmed_at']['monotonic_ns'], 400 * NS)

    def test_health_200_disabled_scanner_or_unavailable_agent_never_pass(self):
        health = {'status': 'ok', 'clamav': 'connected', 'ssl_inspection': 'ready', 'setup_complete': True}
        self.assertTrue(p.health_verdict(200, health))
        for value in ('disabled', 'unreachable', '', None):
            self.assertFalse(p.health_verdict(200, dict(health, clamav=value)))
        ready = {'status': 'ready', 'checks': {key: {'status': 'ok'} for key in p.REQUIRED_READY}}
        self.assertTrue(p.ready_verdict(200, ready))
        del ready['checks']['clamav']
        self.assertFalse(p.ready_verdict(200, ready))
        agent = {'available': True, 'compose_stack_up': True, 'agent_version': BASELINE['agent_version']}
        self.assertTrue(p.agent_verdict(agent))
        self.assertFalse(p.agent_verdict(dict(agent, available=False)))
        self.assertFalse(p.agent_verdict(dict(agent, compose_stack_up=False)))
        operator = {'schema_version': 1, 'phase': 'ready', 'application_responding': True, 'management_available': True}
        self.assertTrue(p.operator_verdict(operator))
        self.assertFalse(p.operator_verdict(dict(operator, phase='provisioning')))

    def test_cached_http_readiness_cannot_replace_direct_clamav_proof(self):
        for mutation in ('missing_binding', 'false_binding', 'no_pings', 'failed_ping', 'missing_ping',
                         'sample_gap', 'truncated', 'bad_elapsed', 'slow_ping'):
            value = proof()
            if mutation == 'missing_binding':
                del value['clamav_endpoint_binding_verified']
            elif mutation == 'false_binding':
                value['clamav_endpoint_binding_verified'] = False
            elif mutation == 'no_pings':
                for row in value['samples']:
                    del row['clamav_ping']
            elif mutation == 'sample_gap':
                value['samples'] = [row for row in value['samples'] if row['monotonic_ns'] != 30 * NS]
            elif mutation == 'truncated':
                value['samples'] = value['samples'][:20]
            else:
                row = next(row for row in value['samples'] if row['monotonic_ns'] == 30 * NS)
                if mutation == 'failed_ping':
                    row['clamav_ping']['pong'] = False
                elif mutation == 'missing_ping':
                    del row['clamav_ping']
                elif mutation == 'bad_elapsed':
                    row['clamav_ping']['elapsed_ns'] += 1
                else:
                    row['clamav_ping']['ended_monotonic_ns'] += 2 * NS
                    row['clamav_ping']['elapsed_ns'] += 2 * NS
            result = p.verify(observations(), BASELINE, value)
            self.assertEqual(result['result'], 'blocked', (mutation, result))
        coverage = p.verify(observations(), BASELINE, proof())['direct_clamav_coverage']
        self.assertEqual(coverage['guest_interval_start_ns'], 26_500_000_000)
        self.assertEqual(coverage['guest_interval_end_ns'], 43_500_000_000)
        self.assertEqual(coverage['maximum_sample_gap_ns'], 2 * NS)

    def test_no_outage_old_boot_or_clock_uncertainty_cannot_pass(self):
        rows = observations()
        rows[1]['external_outage'] = False
        self.assertNotEqual(p.verify(rows, BASELINE, proof())['result'], 'pass')
        for changed in ('old_boot', 'uncertain', 'guest_step', 'controller_step'):
            value = proof()
            if changed == 'old_boot':
                value['boot_id'] = OLD
            elif changed == 'uncertain':
                value['correlation']['controller_finished_monotonic_ns'] += 31 * NS
            elif changed == 'guest_step':
                value['samples'][1]['realtime_ns'] += 2 * NS
            else:
                value['correlation']['controller_finished_realtime_ns'] += 2 * NS
            self.assertEqual(p.verify(observations(), BASELINE, value)['result'], 'blocked', changed)

    def test_old_ready_samples_or_old_login_are_not_post_reboot_proof(self):
        rows = observations()
        rows[2:5] = [sample(111), sample(116), sample(121)]
        self.assertNotEqual(p.verify(rows, BASELINE, proof())['result'], 'pass')
        rows = observations()
        for row in rows:
            if row.get('event') == 'sample':
                row['admin_login_monotonic_ns'] = 105 * NS
        self.assertNotEqual(p.verify(rows, BASELINE, proof())['result'], 'pass')

    def test_deadline_is_end_of_third_sample_and_failure_breaks_streak(self):
        rows = observations()
        rows[2:5] = [sample(209), sample(214), sample(219)]
        rows[-1].update(trigger_sample_started_monotonic_ns=209 * NS,
                        started_monotonic_ns=210 * NS, ended_monotonic_ns=211 * NS)
        self.assertEqual(p.verify(rows, BASELINE, proof())['result'], 'pass')
        rows[4]['ended_monotonic_ns'] += 1
        self.assertEqual(p.verify(rows, BASELINE, proof())['result'], 'fail')
        rows = observations()
        rows.insert(3, sample(152, False))
        self.assertEqual(p.verify(rows, BASELINE, proof())['result'], 'fail')

    def test_slow_or_failed_first_backup_is_not_erased_by_later_success(self):
        for field, value in [('result', 'fail'), ('available', False), ('archive_matches', False), ('elapsed_ns', 5 * NS + 1)]:
            rows = observations()
            rows[-1][field] = value
            self.assertEqual(p.verify(rows, BASELINE, proof())['result'], 'fail', field)
        rows = observations()
        rows[-1]['result'] = 'fail'
        rows.append(copy.deepcopy(observations()[-1]))
        self.assertNotEqual(p.verify(rows, BASELINE, proof())['result'], 'pass')

    def test_recorded_budget_failure_survives_missing_authenticated_proof(self):
        rows = observations()
        rows.append({'event': 'readiness_budget_exceeded', 'result': 'fail',
                     'budget_seconds': 120, 'monotonic_ns': 220 * NS})
        result = p.verify(rows, BASELINE, {})
        self.assertEqual(result['result'], 'fail')
        self.assertEqual(result['proof_status'], 'blocked')
        rows[-1]['monotonic_ns'] -= 1
        self.assertEqual(p.verify(rows, BASELINE, {})['result'], 'blocked')

    def test_policy_normalization_only_ignores_observational_counters(self):
        value = {'draft': False, 'persisted': True, 'rules': [{'name': 'rule', 'enabled': True, 'hitCount': 1}]}
        changed = copy.deepcopy(value)
        changed['rules'][0]['hitCount'] = 50
        self.assertEqual(p.policy_digest(value, 'deny'), p.policy_digest(changed, 'deny'))
        changed['rules'][0]['enabled'] = False
        self.assertNotEqual(p.policy_digest(value, 'deny'), p.policy_digest(changed, 'deny'))
        with self.assertRaises(ValueError):
            p.policy_digest(value, 'allow')

    def test_observer_keeps_pre_outage_samples_and_attempts_backup_once(self):
        class Clock:
            value = 100 * NS
            def __call__(self): return self.value
            def sleep(self, duration): self.value += round(duration * NS)
        class Client:
            calls = 0
            resets = 0
            def reset_session(self): self.resets += 1
            def backup(self, expected):
                self.calls += 1
                return {'event': 'first_ready_backup', 'result': 'fail', 'elapsed_ns': 6 * NS}
        clock, client, emitted = Clock(), Client(), []
        def sampler(client, baseline):
            second = clock.value // NS
            row = sample(second, healthy=second != 105, outage=second == 105)
            clock.value += NS
            return row
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / 'accepted.json'
            marker.write_text(json.dumps(acceptance()))
            result = p.observe(client, BASELINE, marker, emitted.append, clock, clock.sleep, sampler)
        self.assertEqual(result['reason'], 'pending_authenticated_boot_proof')
        self.assertEqual(client.calls, 1)
        self.assertEqual([row['started_monotonic_ns'] // NS for row in emitted if row['event'] == 'sample'], [100, 105, 110, 115, 120])
        self.assertEqual([row['result'] for row in emitted if row['event'] == 'first_ready_backup'], ['fail'])

    def test_late_recovery_is_measured_without_replacing_hard_budget_failure(self):
        class Clock:
            value = 100 * NS
            def __call__(self): return self.value
            def sleep(self, duration): self.value += round(duration * NS)
        class Client:
            calls = 0
            def reset_session(self): pass
            def backup(self, expected):
                self.calls += 1
                return {'event': 'first_ready_backup', 'result': 'pass', 'elapsed_ns': NS}
        clock, client, emitted = Clock(), Client(), []
        def sampler(client, baseline):
            second = clock.value // NS
            row = sample(second, healthy=second >= 500, outage=second == 105)
            clock.value += NS
            return row
        with tempfile.TemporaryDirectory() as temp:
            marker = Path(temp) / 'accepted.json'
            marker.write_text(json.dumps(acceptance()))
            result = p.observe(client, BASELINE, marker, emitted.append, clock, clock.sleep, sampler)
        self.assertEqual(result['result'], 'fail')
        self.assertTrue(result['measurement_complete'])
        self.assertEqual(result['observed_ready_monotonic_ns'], 511 * NS)
        failed = [row for row in emitted if row['event'] == 'readiness_budget_exceeded']
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]['monotonic_ns'], 220 * NS)
        self.assertEqual(client.calls, 1)
        self.assertEqual(p.verify(emitted, BASELINE, proof())['result'], 'fail')

    def test_operator_uses_pinned_readonly_ssh_closed_stdin_and_output_bound(self):
        config = {'ssh': 'fixture-ssh', 'key': 'private-key', 'known_hosts': 'known-hosts', 'alias': 'owned-vm'}
        process = mock.Mock()
        process.wait.return_value = 0
        process.poll.return_value = 0
        process.stdout = io.BytesIO(json.dumps({'schema_version': 1, 'phase': 'ready',
                                             'application_responding': True, 'management_available': True}).encode())
        with mock.patch.object(p.subprocess, 'Popen', return_value=process) as popen:
            self.assertTrue(p.operator_probe(config, '192.0.2.2', p.time.monotonic() + 4.5)['ok'])
            self.assertEqual(popen.call_args.kwargs['stdin'], p.subprocess.DEVNULL)
            self.assertIn('culvert-operator@192.0.2.2', popen.call_args.args[0])
            self.assertIn('StrictHostKeyChecking=yes', popen.call_args.args[0])
            self.assertEqual(popen.call_args.args[0][-1], 'status-json')
        process.stdout = io.BytesIO(b'x' * 65537)
        with mock.patch.object(p.subprocess, 'Popen', return_value=process), self.assertRaises(ValueError):
            p.operator_probe(config, '192.0.2.2', p.time.monotonic() + 4.5)
        process.kill.assert_called()


if __name__ == '__main__':
    unittest.main()
