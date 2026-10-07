"""Synthetic only: no console, guest, Docker or hypervisor calls."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('clamav_outage', Path(__file__).with_name('qualify-clamav-outage.py'))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class Fake:
    def __init__(self, fault=None):
        self.fault = fault
        self.running = fault != 'initial_stopped'
        self.stops = 0
        self.starts = 0
        self.rule = False
        self.closed = False
        self.events = []

    def prepare(self):
        self.events.append('prepare')
        m.need(self.running, 'sidecar initially stopped')
        return {'av_unavailable': 'closed'}

    def install_fixture(self):
        self.rule = True
        self.events.append('fixture')
        if self.fault == 'partial_rule':
            raise RuntimeError('mutation succeeded but reply failed')

    def wait_ready(self, expected):
        self.events.append('ready_up' if expected else 'ready_down')
        if not expected and self.fault == 'stale_ready':
            raise TimeoutError()
        m.need(self.running == expected, 'unexpected service state')
        return {'pass': True, 'http_status': 200 if expected else 503, 'clamav_status': 'ok' if expected else 'fail'}

    def probe(self, kind, body):
        self.events.append('probe_' + kind)
        if self.fault == 'always_deny':
            return 403, b'Blocked by policy', False
        if not self.running:
            if self.fault == 'fail_open' and kind == 'clean':
                return 200, body, True
            if self.fault == 'cached_av' and kind == 'eicar':
                return 403, b'Blocked by CLAMAV scan', False
            if self.fault == 'down_probe_exception':
                raise TimeoutError()
            return 403, b'Blocked: antivirus scanning is currently unavailable', True
        fetched = self.fault != 'cached_up'
        return (200, body, fetched) if kind == 'clean' else (403, b'Blocked by CLAMAV scan', fetched)

    def stop(self):
        self.events.append('stop')
        self.stops += 1
        self.running = False
        if self.fault == 'stop_timeout':
            raise TimeoutError()

    def restore(self):
        self.events.append('restore')
        self.starts += 1
        if self.fault == 'restart_failed':
            raise RuntimeError()
        self.running = True

    def cleanup_fixture(self):
        self.events.append('cleanup')
        self.rule = False
        if self.fault == 'policy_drift':
            raise ValueError('other rule changed; never overwrite it')
        return True

    def close(self):
        self.closed = True


class OutageTests(unittest.TestCase):
    def test_success_requires_live_clean_av_outage_and_recovery(self):
        b = Fake()
        r = m.qualify(b)
        self.assertEqual(r['result'], 'pass')
        self.assertEqual(set(r['phases']), {'before', 'down', 'recovered'})
        self.assertEqual(r['readiness']['down']['http_status'], 503)
        self.assertEqual((b.stops, b.starts), (1, 1))
        self.assertTrue(b.running and b.closed)
        self.assertFalse(b.rule)
        hashes = [v['body_sha256'] for phase in r['phases'].values() for v in phase]
        self.assertEqual(len(set(hashes)), 6)
        self.assertLess(b.events.index('ready_down'), b.events.index('restore'))

    def test_failopen_clean_is_not_hidden_by_blocked_eicar(self):
        b = Fake('fail_open')
        r = m.qualify(b)
        self.assertEqual(r['result'], 'fail')
        self.assertFalse(r['phases']['down'][0]['pass'])
        self.assertTrue(r['phases']['down'][1]['pass'])
        self.assertTrue(b.running and r['policy_restored'])

    def test_alwaysdeny_never_reaches_outage(self):
        b = Fake('always_deny')
        r = m.qualify(b)
        self.assertEqual(r['result'], 'fail')
        self.assertEqual(b.stops, 0)
        self.assertFalse(b.rule)

    def test_cached_body_or_cached_verdict_cannot_pass(self):
        for fault in ('cached_up', 'cached_av'):
            with self.subTest(fault=fault):
                b = Fake(fault)
                self.assertEqual(m.qualify(b)['result'], 'fail')
                self.assertTrue(b.running)
        with mock.patch.object(m, 'fresh_body', return_value=b'reused'):
            b = Fake()
            self.assertEqual(m.qualify(b)['result'], 'fail')
            self.assertEqual(b.stops, 0)

    def test_failed_stop_reply_and_probe_timeout_restore_sidecar(self):
        for fault in ('stop_timeout', 'down_probe_exception', 'stale_ready'):
            with self.subTest(fault=fault):
                b = Fake(fault)
                r = m.qualify(b)
                self.assertEqual(r['result'], 'fail')
                self.assertTrue(b.running and b.closed and not b.rule)
                self.assertEqual(b.starts, 1)

    def test_failed_restart_does_not_claim_cleanup_success(self):
        b = Fake('restart_failed')
        r = m.qualify(b)
        self.assertEqual(r['result'], 'fail')
        self.assertFalse(r['restored_running'])
        self.assertIn('sidecar_recovery_failed', r['errors'])
        self.assertFalse(b.rule)

    def test_initially_stopped_remains_stopped_no_mutation(self):
        b = Fake('initial_stopped')
        r = m.qualify(b)
        self.assertEqual(r['result'], 'fail')
        self.assertEqual((b.stops, b.starts), (0, 0))
        self.assertFalse(b.running or b.rule)

    def test_partial_policy_write_and_drift_fail_with_cleanup(self):
        for fault in ('partial_rule', 'policy_drift'):
            b = Fake(fault)
            r = m.qualify(b)
            self.assertEqual(r['result'], 'fail')
            self.assertTrue(b.closed and b.running)
            self.assertFalse(b.rule)

    def test_body_oracles_reject_generic_errors_and_wrong_clean_body(self):
        self.assertFalse(m.body_verdict('down', 'clean', 200, b'antivirus scanning is currently unavailable', b'x'))
        self.assertFalse(m.body_verdict('down', 'clean', 403, b'Blocked by policy', b'x'))
        self.assertFalse(m.body_verdict('before', 'clean', 200, b'other', b'x'))
        self.assertFalse(m.body_verdict('before', 'eicar', 403, b'antivirus scanning is currently unavailable', b'x'))

    def test_fresh_eicar_within_standard_128_byte_bound(self):
        a, b = m.fresh_body('eicar'), m.fresh_body('eicar')
        self.assertEqual(len(a[:68]), 68)
        self.assertLessEqual(len(a), 128)
        self.assertTrue(set(a[68:]).issubset({32, 9}))
        self.assertEqual(a[:68], b[:68])
        self.assertNotEqual(a, b)

    def test_policy_hash_preserves_rules_ignores_only_hit_statistics(self):
        a = {'draft': False, 'persisted': True, 'rules': [{'id': 'a', 'enabled': True, 'hitCount': 1}]}
        b = dict(a, rules=[{'id': 'a', 'enabled': True, 'hitCount': 100}])
        self.assertEqual(m.policy_identity(a), m.policy_identity(b))
        b['rules'][0]['enabled'] = False
        self.assertNotEqual(m.policy_identity(a), m.policy_identity(b))
        with self.assertRaises(ValueError):
            m.policy_identity(dict(a, draft=True))

    def test_restore_does_not_depend_on_failed_proxy(self):
        b = m.Guest({'operation': 'a' * 32})
        b.sidecar_id = 'sidecar'
        with mock.patch.object(b, 'sidecar_guard', side_effect=[False, True]) as guard:
            with mock.patch.object(m, 'command') as command, mock.patch.object(b, 'check_locks') as locks:
                b.restore()
        self.assertEqual(guard.call_args_list, [mock.call(require_proxy=False), mock.call(require_proxy=False)])
        command.assert_called_once_with(['docker', 'start', 'sidecar'], timeout=20)
        self.assertEqual(locks.call_count, 2)

    def test_cleanup_removes_only_unchanged_owned_rule(self):
        b = m.Guest({'operation': 'a' * 32})
        base = {'version': 1, 'draft': False, 'persisted': True, 'rules': [{'id': 'base', 'name': 'base'}]}
        b.before = base
        b.policy_sha = m.policy_identity(base)
        b.rule = {'name': b.rule_name, 'enabled': True}
        rule = dict(b.rule, id='0' * 26)
        with mock.patch.object(b, 'api', return_value=dict(base, rules=base['rules'] + [dict(rule, enabled=False)])) as api:
            with self.assertRaises(ValueError):
                b.cleanup_fixture()
            self.assertEqual(api.call_count, 1)
        b.default_before = {'defaultAction': 'deny'}
        current = dict(base, version=2, rules=base['rules'] + [rule])
        with mock.patch.object(b, 'api', side_effect=[current, {}, base, b.default_before, {'av_unavailable': 'closed'}]) as api:
            self.assertTrue(b.cleanup_fixture())
            self.assertEqual(api.call_args_list[1], mock.call('/api/policy?id=' + '0' * 26 + '&ifVersion=2', 'DELETE'))

    def test_pending_and_corrupt_maintenance_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            maint, state = root / 'maint', root / 'state'
            maint.mkdir()
            state.mkdir()
            m.maintenance_idle(maint, state)
            for path in (maint / 'host-shutdown.pending', state / 'stack-resume-on-boot'):
                path.touch()
                with self.assertRaises(ValueError):
                    m.maintenance_idle(maint, state)
                path.unlink()
            (maint / 'reconcile').mkdir()
            for name in ('operation.json', 'operation.corrupt.123'):
                path = maint / 'reconcile' / name
                path.touch()
                with self.assertRaises(ValueError):
                    m.maintenance_idle(maint, state)
                path.unlink()
            m.maintenance_idle(maint, state)

    def test_payload_compiles_and_credential_is_not_argv_or_result(self):
        cfg = {'operation': 'a' * 32, 'initial': 'SYNTHETIC_TEST_ONLY', 'helper_sha256': 'b' * 64}
        p = m.payload(cfg).decode()
        code = p.split("python3 - <<'CULVERT_AV_OUTAGE'\n", 1)[1].rsplit('\nCULVERT_AV_OUTAGE', 1)[0]
        compile(code, '<guest>', 'exec')
        self.assertNotIn(cfg['initial'], p)
        self.assertNotIn(cfg['initial'], json.dumps(m.qualify(Fake())))


def info(uid=0, gid=0, mode=0o40755, inode=1, links=1):
    return SimpleNamespace(st_uid=uid, st_gid=gid, st_mode=mode, st_ino=inode, st_dev=9, st_nlink=links)


class LockOwnerTests(unittest.TestCase):
    def test_only_exact_service_leaf_owner_schema_is_accepted(self):
        service = (999, 987)
        m.trusted_directory('/var/lib/culvert-maint', info(uid=999, gid=987, mode=0o40750), service)
        m.trusted_directory('/var/lib', info(), service)
        for value in (info(uid=998, gid=987, mode=0o40750), info(uid=999, gid=986, mode=0o40750),
                      info(uid=999, gid=987, mode=0o40770), info(uid=999, gid=987, mode=0o40755),
                      info(uid=999, gid=987, mode=0o120750), info(mode=0o40750)):
            with self.subTest(value=value):
                with self.assertRaises(m.CheckFailure):
                    m.trusted_directory('/var/lib/culvert-maint', value, service)
        for name in ('/', '/var', '/var/lib', '/run', '/var/lib/other'):
            with self.assertRaises(m.CheckFailure):
                m.trusted_directory(name, info(uid=999, gid=987, mode=0o40750), service)

    def test_lock_itself_stays_root_owned_single_link_regular(self):
        m.trusted_lock(info(mode=0o100644))
        for value in (info(uid=999, mode=0o100640), info(gid=987, mode=0o100644),
                      info(mode=0o100664), info(mode=0o120644), info(mode=0o100644, links=2)):
            with self.assertRaises(m.CheckFailure):
                m.trusted_lock(value)

    def test_descriptor_acquisition_and_replacement_fences(self):
        for replacement in ('during_flock', 'later_file', 'later_directory', None):
            with self.subTest(replacement=replacement):
                changed = {'file': False, 'directory': False}
                metadata = {i: info(inode=i) for i in range(1, 6)}
                metadata[4] = info(uid=999, gid=987, mode=0o40750, inode=4)
                metadata[5] = info(mode=0o100644, inode=5)
                def named(name, *, dir_fd, follow_symlinks):
                    self.assertFalse(follow_symlinks)
                    number = {'var': 2, 'lib': 3, 'culvert-maint': 4, 'host-maintenance.lock': 5}[name]
                    if (number == 5 and changed['file']) or (number == 4 and changed['directory']):
                        original = metadata[number]
                        return info(uid=original.st_uid, gid=original.st_gid, mode=original.st_mode, inode=100)
                    return metadata[number]
                def flock(fd, flags):
                    self.assertEqual(fd, 5)
                    if replacement == 'during_flock':
                        changed['file'] = True
                fake_fcntl = SimpleNamespace(flock=flock, LOCK_EX=2, LOCK_NB=4)
                with mock.patch.dict('sys.modules', {'fcntl': fake_fcntl}):
                    with mock.patch.multiple(m.os, O_DIRECTORY=0x10000, O_CLOEXEC=0x20000, O_NOFOLLOW=0x40000, create=True):
                        with mock.patch.object(m.os, 'open', side_effect=[1, 2, 3, 4, 5]) as opened:
                            with mock.patch.object(m.os, 'fstat', side_effect=metadata.__getitem__), mock.patch.object(m.os, 'stat', side_effect=named), mock.patch.object(m.os, 'close') as closed:
                                if replacement == 'during_flock':
                                    with self.assertRaises(m.CheckFailure) as failure:
                                        m.HeldLock('/var/lib/culvert-maint/host-maintenance.lock', (999, 987))
                                    self.assertEqual(failure.exception.code, 'lock_path_replaced')
                                else:
                                    held = m.HeldLock('/var/lib/culvert-maint/host-maintenance.lock', (999, 987))
                                    if replacement:
                                        changed['file' if replacement == 'later_file' else 'directory'] = True
                                        with self.assertRaises(m.CheckFailure):
                                            held.check()
                                    else:
                                        held.check()
                                    held.close()
                                self.assertEqual(closed.call_args_list, [mock.call(i) for i in (5, 4, 3, 2, 1)])
                                self.assertEqual(opened.call_args_list[-1].kwargs['dir_fd'], 4)
                                self.assertTrue(opened.call_args_list[-1].args[1] & m.os.O_NOFOLLOW)

    def test_fixed_stage_code_not_exception_text(self):
        b = Fake()
        def bad_prepare():
            b.stage = 'lock_agent'
            raise m.CheckFailure('SYNTHETIC_SECRET', 'maintenance_directory_identity')
        b.prepare = bad_prepare
        result = m.qualify(b)
        self.assertEqual(result['failure_details'], [{'stage': 'lock_agent', 'code': 'maintenance_directory_identity'}])
        self.assertNotIn('SYNTHETIC_SECRET', json.dumps(result))


class PriorAttemptTests(unittest.TestCase):
    def test_prior_failure_hash_owner_and_pre_mutation_are_bound(self):
        with tempfile.TemporaryDirectory() as temporary:
            sec = Path(temporary)
            directory = sec / 'clamav-outage'
            directory.mkdir()
            payload = b'FIXTURE ONLY'
            original = {'schema': 1, 'result': 'fail', 'helper_sha256': m.PRIOR_HELPER,
                        'operation': 'a' * 32, 'phases': {}, 'readiness': {},
                        'restored_running': False, 'policy_restored': True, 'errors': ['qualification_failed']}
            intent = {'owner_uuid': 'fixture-owner', 'controller_revision': m.PRIOR_CONTROLLER,
                      'source_sha': m.SOURCE, 'image_id': m.IMAGE, 'sidecar_image_id': m.SIDECAR,
                      'operation': original['operation'], 'payload_sha256': m.sha(payload)}
            (directory / 'payload.sh').write_bytes(payload)
            (directory / 'intent.json').write_text(json.dumps(intent))
            raw = json.dumps(original).encode()
            (directory / 'guest-result.json').write_bytes(raw)
            hashes = m.prior_failure(sec, m.sha(raw), 'fixture-owner')
            self.assertEqual(hashes['guest-result.json'], m.sha(raw))
            for expected, owner in [('0' * 64, 'fixture-owner'), (m.sha(raw), 'different-owner')]:
                with self.assertRaises(m.CheckFailure):
                    m.prior_failure(sec, expected, owner)
            changed = dict(original, identity={'prepare_completed': True})
            changed_raw = json.dumps(changed).encode()
            (directory / 'guest-result.json').write_bytes(changed_raw)
            with self.assertRaises(m.CheckFailure):
                m.prior_failure(sec, m.sha(changed_raw), 'fixture-owner')
            self.assertEqual((directory / 'payload.sh').read_bytes(), payload)


if __name__ == '__main__':
    unittest.main()
