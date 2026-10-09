import errno
import importlib.util
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest.mock import patch, Mock


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


w = load('disk-pressure-worker')
g = load('disk-pressure-guest')
c = load('disk-pressure-control')


class WorkerTests(unittest.TestCase):
    def test_lease_checks_pin_before_disclosing_nonce_and_requires_exact_permission(self):
        import hashlib
        connection = Mock()
        connection.sock.getpeercert.return_value = b'certificate'
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"permit":true}'
        config = {'host': '192.0.2.1', 'port': 12345, 'token': 'synthetic-private-nonce',
                  'certificate_sha256': '0' * 64}
        with patch.object(w.http.client, 'HTTPSConnection', return_value=connection):
            self.assertFalse(w.lease(config))
            connection.request.assert_not_called()
            config['certificate_sha256'] = hashlib.sha256(b'certificate').hexdigest()
            self.assertTrue(w.lease(config))
            response.read.return_value = b'{"permit":false}'
            self.assertFalse(w.lease(config))
            response.read.return_value = b'{"permit":true,"extra":"untrusted"}'
            self.assertFalse(w.lease(config))

    def test_paths_have_no_user_controlled_traversal(self):
        self.assertEqual(str(w.paths('a' * 32, 'blocks')[0]).replace('\\', '/'),
                         '/var/lib/culvert-lab-pressure-' + 'a' * 32 + '-blocks')
        for operation, mode in [('../etc', 'blocks'), ('a' * 32, '../'), ('A' * 32, 'inodes')]:
            with self.assertRaises(ValueError):
                w.paths(operation, mode)

    def test_blocks_require_real_enospc_and_shrink_probe_to_one_block(self):
        calls = []
        def allocate(fd, offset, count):
            calls.append((offset, count))
            if offset + count > 65536:
                raise OSError(errno.ENOSPC, 'synthetic')
        value = w.fill_blocks(123, allocate=allocate)
        self.assertEqual(value['result'], 'exhausted')
        self.assertEqual(value['allocated_bytes'], 65536)
        self.assertEqual(calls[-1][1], 4096)

    def test_non_space_error_is_not_success(self):
        for error in (errno.EIO, errno.EDQUOT, errno.EROFS):
            with self.subTest(error=error), self.assertRaises(OSError):
                w.fill_blocks(123, allocate=Mock(side_effect=OSError(error, 'synthetic')))

    def test_inode_cap_prevents_mutation_and_never_claims_exhaustion(self):
        with patch.object(w.os, 'open') as opening:
            result = w.fill_inodes(123, w.MAX_INODES + 1)
        opening.assert_not_called()
        self.assertEqual(result['result'], 'bounded_not_exhausted')

    def test_cleanup_validates_whole_tree_before_first_unlink(self):
        good = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
        for badname, badstat in [('unexpected', good), ('i000003', types.SimpleNamespace(
                st_mode=stat.S_IFLNK | 0o777, st_uid=0, st_nlink=1)),
                ('i000003', types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=2))]:
            with patch.object(w.os, 'listdir', return_value=['reserve', badname]), \
                    patch.object(w.os, 'stat', side_effect=lambda name, **kw: good if name == 'reserve' else badstat), \
                    patch.object(w.os, 'unlink') as unlinking, self.assertRaises(ValueError):
                w.release(123)
            unlinking.assert_not_called()

    def test_release_reserve_first_and_no_recursive_shell(self):
        good = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
        with patch.object(w.os, 'listdir', side_effect=[['blocks', 'reserve', 'i000001'], []]), \
                patch.object(w.os, 'stat', return_value=good), patch.object(w.os, 'unlink') as delete:
            w.release(123)
        self.assertEqual(delete.call_args_list[0].args, ('reserve',))
        self.assertEqual(delete.call_count, 3)

    def test_kill_and_reap_precede_release_even_on_lease_failure(self):
        # Exercise supervisor finally ordering without allocating or launching.
        order = []
        worker = Mock()
        worker.poll.return_value = None
        worker.kill.side_effect = lambda: order.append('kill')
        worker.wait.side_effect = lambda **kw: order.append('wait')
        root, control = Mock(), Mock()
        root.parent = Mock()
        control.__truediv__ = Mock(return_value=Mock(exists=Mock(return_value=False)))
        with patch.object(w.os, 'geteuid', create=True, return_value=0), \
                patch.object(w, 'paths', return_value=(root, control)), \
                patch.object(w, 'safe_directory', return_value=123), \
                patch.object(w, 'tmpfs_guard'), patch.object(w, 'root_guard', return_value={}), \
                patch.object(w.signal, 'signal'), \
                patch.object(w, 'lease', side_effect=[True, False]), \
                patch.object(w.os, 'O_NOFOLLOW', 0x20000, create=True), \
                patch.object(w.os, 'close'), patch.object(w.os, 'open', return_value=124), \
                patch.object(w.os, 'posix_fallocate', create=True), \
                patch.object(w.subprocess, 'Popen', return_value=worker), \
                patch.object(w, 'atomic_json'), \
                patch.object(w, 'release', side_effect=lambda fd: order.append('release')):
            w.supervise({'operation': 'a' * 32, 'mode': 'blocks', 'lease': {}})
        self.assertEqual(order, ['kill', 'wait', 'release'])


class VerdictTests(unittest.TestCase):
    def test_response_evidence_is_allowlisted_and_bounded_without_changing_response(self):
        backend = Mock()
        headers = [('Content-Type', 'application/octet-stream'), ('Set-Cookie', 'secret-canary'),
                   ('X-Culvert-Test', 'x' * 300)] * 10
        backend.request.return_value = (200, b'body', headers)
        original = backend.request
        g.bind_response_evidence(backend)
        self.assertEqual(backend.request(8080, 'http://192.0.2.1/nonce'), (200, b'body', headers))
        original.assert_called_once_with(8080, 'http://192.0.2.1/nonce', 'GET', None, False)
        self.assertTrue(backend.last_response_evidence['headers_truncated'])
        self.assertNotIn('secret-canary', str(backend.last_response_evidence))

    def test_exhaustion_must_still_be_present_at_samples(self):
        self.assertTrue(g.pressure_present('blocks', {'bytes_free': 4096}))
        self.assertFalse(g.pressure_present('blocks', {'bytes_free': 1024 ** 2}))
        self.assertTrue(g.pressure_present('inodes', {'inodes_free': 0}))
        self.assertFalse(g.pressure_present('inodes', {'inodes_free': 1}))

    def test_actual_delivery_is_fatal_even_if_origin_indicator_missing(self):
        self.assertEqual(g.classify('eicar', 200, b'body', b'body', False), 'eicar_delivered')

    def test_fail_open_and_always_deny_not_good_baseline(self):
        self.assertEqual(g.classify('clean', 403, b'denied', b'body', True), 'unexpected_response')
        self.assertEqual(g.classify('eicar', 200, b'body', b'body', True), 'eicar_delivered')
        self.assertEqual(g.classify('eicar', 403, b'Blocked by CLAMAV scan', b'body', False), 'unproven_origin')

    def test_response_cache_cannot_stand_in_for_actual_fresh_fetch(self):
        self.assertEqual(g.classify('clean', 200, b'expected', b'expected', False), 'unproven_origin')
        self.assertEqual(g.classify('clean', 200, b'old-body', b'new-body', True), 'unexpected_response')

    def test_stop_immediately_after_eicar_delivery(self):
        backend = Mock(payloads={}, fetched=set())
        backend.probe.return_value = (200, b'body', True)
        result = g.sample(backend, lambda kind: b'body', set(), False)
        self.assertFalse(result['pass'])
        self.assertEqual(backend.probe.call_count, 1)
        backend.request.assert_not_called()

    def test_ready_cannot_stay_good_between_two_clean_refusals(self):
        rows = [{'verdict': 'eicar_blocked'}, {'verdict': 'av_unavailable'}, {'verdict': 'av_unavailable'}]
        with patch.object(g, 'probe', side_effect=rows), patch.object(g, 'negative_control', return_value={'pass': True}), \
                patch.object(g, 'ready', return_value={
                'http_status': 200, 'status': 'ready', 'clamav_status': 'ok'}):
            value = g.sample(Mock(), Mock(), set(), False)
        self.assertFalse(value['readiness_truthful'])
        self.assertFalse(value['pass'])

    def test_unrelated_readiness_failure_cannot_hide_clamav_false_health(self):
        for code, status, clamav, expected in [(503, 'not_ready', 'ok', False),
                (503, 'not_ready', None, False), (500, 'not_ready', 'fail', False),
                (503, 'not_ready', 'fail', True)]:
            rows = [{'verdict': 'eicar_blocked'}, {'verdict': 'av_unavailable'}, {'verdict': 'av_unavailable'}]
            with self.subTest(code=code, clamav=clamav), \
                    patch.object(g, 'probe', side_effect=rows), \
                    patch.object(g, 'negative_control', return_value={'pass': True}), \
                    patch.object(g, 'ready', return_value={'http_status': code, 'status': status, 'clamav_status': clamav}):
                value = g.sample(Mock(), Mock(), set(), False)
            self.assertEqual(value['pass'], expected)

    def test_negative_control_distinguishes_policy_from_av_unavailability(self):
        backend = Mock()
        backend.request.return_value = (403, b'antivirus scanning is currently unavailable', [])
        self.assertFalse(g.negative_control(backend)['pass'])
        backend.request.return_value = (403, b'Default Deny No matching policy rule', [])
        self.assertTrue(g.negative_control(backend)['pass'])

    def test_eicar_delivery_still_releases_and_preserves_capture(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            root, control = directory / 'root', directory / 'control'
            root.mkdir()
            backend = Mock(command=Mock(), payloads={}, fetched=set())
            backend.probe.return_value = (200, b'body', True)
            worker = Mock()
            worker.paths.return_value = root, control
            worker.safe_directory.return_value = 123
            worker.root_guard.return_value = {'bytes_free': 0}
            supervisor = Mock()
            supervisor.poll.return_value = None
            capture = Mock()
            capture.close.return_value = {'fragments': 1}
            def launched(*unused, **kwargs):
                (control / 'armed.json').write_text('{}')
                return supervisor
            def waited(**kwargs):
                self.assertTrue((control / 'release').exists())
                root.rmdir()
                (control / 'released.json').write_text('{"released":true}')
            supervisor.wait.side_effect = waited
            actual_close = g.os.close
            with patch.object(g, 'network_pair', return_value=('192.0.2.1', '192.0.2.2')), \
                    patch.object(g.subprocess, 'Popen', side_effect=launched), \
                    patch.object(g.os, 'close', side_effect=lambda fd: None if fd == 123 else actual_close(fd)):
                value = g.phase({'operation': 'a' * 32, 'lease': {}}, 'blocks', backend, b'# fixture',
                                worker, Mock(return_value=capture), lambda kind: b'body', set())
            self.assertEqual(value['result'], 'fail')
            self.assertTrue(value['released'])
            self.assertTrue(value['root_pressure_directory_absent'])
            self.assertEqual(value['samples'][0]['probes'][0]['verdict'], 'eicar_delivered')
            capture.close.assert_called_once()
            self.assertEqual(backend.probe.call_count, 1)


class ControllerTests(unittest.TestCase):
    def test_full_disk_growth_reserved_not_only_current_sparse_usage(self):
        self.assertEqual(c.HEADROOM, 106 * c.GIB)
        self.assertEqual(c.required_reserve({'datastore_headroom_gib': 80}), 80 * c.GIB)
        self.assertEqual(c.required_reserve({'datastore_headroom_gib': 16}), 64 * c.GIB)

    def test_hardware_guard_rejects_other_resources_and_extra_disks(self):
        baseline = {'numCPU': 2, 'memoryMB': 4096, 'device': [{'capacityInKB': 40 * c.GIB // 1024}]}
        c.hardware_guard({'config': {'hardware': baseline}})
        for change in [{'numCPU': 4}, {'memoryMB': 8192}, {'device': []},
                       {'device': baseline['device'] * 2}, {'device': [{'capacityInBytes': 80 * c.GIB}]}]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                c.hardware_guard({'config': {'hardware': dict(baseline, **change)}})

    def test_stale_or_failed_capacity_never_extends_lease(self):
        server = object.__new__(c.LeaseServer)
        server.lab, server.rows, server.valid_until = Mock(), [], 1000
        server.lab.c = {'datastore_headroom_gib': 64}
        with patch.object(c, 'capacity', side_effect=RuntimeError), patch.object(c.time, 'monotonic', return_value=5):
            server.refresh()
        self.assertEqual(server.valid_until, 0)
        self.assertFalse(server.rows[-1]['permit'])
        with patch.object(c, 'capacity', return_value=65 * c.GIB):
            server.refresh()
        self.assertEqual(server.valid_until, 0)

    def test_embedded_guest_program_compiles_without_running_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'qualify-clamav-outage.py').write_text('# fixture guest\n# CONTROLLER:\ninvalid controller source')
            for name in ('disk-pressure-worker.py', 'disk-pressure-guest.py', 'disk-pressure-observe.py'):
                (root / name).write_bytes(Path(__file__).with_name(name).read_bytes())
            with patch.object(c, 'HERE', root):
                raw = c.payload({'operation': 'a' * 32}, {'source_sha': 's', 'image_id': 'i', 'clamav_sidecar_image_id': 'c'})
            source = raw.decode().split("python3 - <<'CULVERT_PRESSURE'\n", 1)[1].rsplit('\nCULVERT_PRESSURE', 1)[0]
            compile(source, '<synthetic pressure heredoc>', 'exec')


if __name__ == '__main__':
    unittest.main()
