"""Offline proc fixtures and script inspection; never runs the installer or VM."""
import ast
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sampler = load('boot_sampler_test', 'production-boot-sampler.py')
control = load('boot_sampler_control_test', 'production-boot-sampler-control.py')
BOOT = '11111111-1111-4111-8111-111111111111'


class SamplerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / 'pressure').mkdir()
        for name in ('cpu', 'io', 'memory'):
            (self.root / 'pressure' / name).write_text('some avg10=0.00 avg60=1.23 avg300=0.00 total=42\n')
        (self.root / 'stat').write_text('cpu 10 11 12 13 14 15 16 17 18 19\n')
        (self.root / 'diskstats').write_text('8 0 sda 1 2 3 4 5 6 7 8 9 10 11\n')
        (self.root / 'locks').write_text('')
        self.collector = sampler.Collector(self.root, clock=lambda: 0, boot_id=BOOT)

    def process(self, pid, comm, unit='unrelated.service'):
        base = self.root / str(pid)
        base.mkdir()
        (base / 'comm').write_text(comm)
        (base / 'stat').write_text(str(pid) + ' (' + comm + ') S ' + ' '.join(str(i) for i in range(1, 23)))
        (base / 'io').write_text('\n'.join(key + ': 123' for key in sampler.IO_FIELDS))
        (base / 'wchan').write_text('futex_wait_queue')
        (base / 'cgroup').write_text('0::/system.slice/' + unit)
        (base / 'cmdline').write_text('DO_NOT_READ_SYNTHETIC_CREDENTIAL')
        (base / 'environ').write_text('DO_NOT_READ_SYNTHETIC_ENVIRONMENT')
        return base

    def test_process_selection_and_counter_field_positions(self):
        self.process(100, 'containerd')
        self.process(101, 'bash', 'culvert-stack-resume.service')
        self.process(102, 'python3', 'cloud-init-local.service')
        self.process(103, 'bash')
        observation = self.collector.processes()
        self.assertEqual([p['pid'] for p in observation['processes']], [100, 101, 102])
        process = observation['processes'][0]
        self.assertEqual(process['stat']['minor_faults'], 7)
        self.assertEqual(process['stat']['user_ticks'], 11)
        self.assertEqual(process['stat']['start_ticks'], 19)
        self.assertEqual(observation['processes'][1]['unit'], 'culvert-stack-resume.service')
        encoded = json.dumps(observation)
        self.assertNotIn('DO_NOT_READ', encoded)
        self.assertNotIn('/system.slice/', encoded)
        self.assertNotIn('cmdline', encoded)
        self.assertNotIn('environ', encoded)

    def test_process_io_failure_is_observed_not_reported_as_zero(self):
        base = self.process(100, 'dockerd')
        (base / 'io').unlink()
        row = self.collector.processes()
        self.assertEqual(row['processes'], [])
        self.assertEqual(row['unavailable'], 1)

    def test_scan_count_time_and_selected_process_caps(self):
        self.process(100, 'dockerd')
        self.process(101, 'containerd')
        with patch.object(sampler, 'MAX_PIDS', 1):
            self.assertTrue(self.collector.processes()['scan_truncated'])
        with patch.object(sampler, 'MAX_PROCESSES', 1):
            self.assertEqual(len(self.collector.processes()['processes']), 1)
        self.collector.clock = iter([0, 1]).__next__
        self.assertTrue(self.collector.processes()['scan_truncated'])

    def test_sample_clock_identity_and_missing_pressure_are_explicit(self):
        (self.root / 'pressure' / 'io').unlink()
        row = self.collector.sample()
        self.assertEqual(row['boot_id'], BOOT)
        self.assertIsInstance(row['monotonic_ns'], int)
        self.assertIsInstance(row['realtime_ns'], int)
        self.assertEqual(row['iowait_ticks'], 14)
        self.assertEqual(row['pressure_cpu']['some']['total'], 42)
        self.assertEqual(row['errors'], ['pressure_io'])

    def test_pid_reuse_is_rejected(self):
        self.process(100, 'containerd')
        original = sampler.process_stat
        calls = []
        def changing(raw, pid):
            result = original(raw, pid)
            result['start_ticks'] += len(calls)
            calls.append(pid)
            return result
        with patch.object(sampler, 'process_stat', side_effect=changing):
            self.assertEqual(self.collector.processes()['processes'], [])

    def test_bounded_file_reads_and_invalid_counter_rows(self):
        path = self.root / 'large'
        path.write_bytes(b'x' * 20)
        with self.assertRaises(ValueError):
            sampler.bounded(path, 19)
        for method, value in [(sampler.pressure, 'some avg10=nan'),
                              (sampler.disks, '8 0 sda 1'),
                              (sampler.counters, 'read_bytes: 0')]:
            with self.subTest(method=method):
                with self.assertRaises(ValueError):
                    method(value)

    def test_lock_owner_matching_excludes_waiters_and_unavailable_is_not_false(self):
        lock = self.root / 'fixed-lock'
        lock.write_text('')
        inode = lock.stat().st_ino
        (self.root / 'locks').write_text(
            f'1: FLOCK ADVISORY WRITE 123 08:00:{inode} 0 EOF\n'
            f'1: -> FLOCK ADVISORY WRITE 999 08:00:{inode} 0 EOF\n'
            f'2: FLOCK ADVISORY WRITE 456 08:00:{inode + 1} 0 EOF\n')
        with patch.object(sampler, 'LOCK_PATHS', {'held': lock, 'missing': self.root / 'absent'}), \
                patch.object(sampler.os, 'major', return_value=8, create=True), \
                patch.object(sampler.os, 'minor', return_value=0, create=True):
            observed = self.collector.locks()
            self.assertEqual(observed['held'], {'available': True, 'held': True, 'holder_pids': [123]})
            self.assertEqual(observed['missing'], {'available': False, 'held': None, 'holder_pids': []})
            (self.root / 'locks').write_text('')
            self.assertEqual(self.collector.locks()['held'], {'available': True, 'held': False, 'holder_pids': []})
            (self.root / 'locks').unlink()
            self.assertFalse(self.collector.locks()['held']['available'])


class RecordingTests(unittest.TestCase):
    def test_runtime_requires_effective_tmpfs_not_just_a_parent_mount(self):
        root = '1 0 8:0 / / rw - ext4 /dev/sda rw\n'
        runtime = '2 1 0:1 / /run rw - tmpfs tmpfs rw\n'
        nested = '3 2 8:0 / /run/culvert-lab-boot-sampler rw - ext4 /dev/sda rw\n'
        self.assertFalse(sampler.runtime_tmpfs(root))
        self.assertTrue(sampler.runtime_tmpfs(root + runtime))
        self.assertFalse(sampler.runtime_tmpfs(root + runtime + nested))

    def test_two_second_cadence_stops_at_deadline(self):
        clock = [0]
        starts = []
        def sample():
            starts.append(clock[0])
            return {'kind': 'sample'}
        stream = io.BytesIO()
        sampler.record(stream, SimpleNamespace(sample=sample), {'kind': 'header'},
                       clock=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds), duration=5)
        self.assertEqual(starts, [0, 2, 4])
        self.assertEqual(clock[0], 5)
        self.assertEqual(json.loads(stream.getvalue().splitlines()[-1])['reason'], 'deadline')

    def test_byte_limit_keeps_complete_json_and_final_reason(self):
        stream = io.BytesIO()
        sampler.record(stream, SimpleNamespace(sample=lambda: {'data': 'x' * 600}), {'kind': 'header'},
                       clock=lambda: 0, sleep=lambda seconds: None, duration=5, limit=1024)
        self.assertLessEqual(len(stream.getvalue()), 1024)
        rows = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(rows[-1]['reason'], 'byte_limit')
        self.assertEqual(rows[-1]['samples'], 0)

    def test_missed_slots_do_not_trigger_catchup_burst(self):
        clock, starts = [0], []
        def sample():
            starts.append(clock[0])
            clock[0] += 3
            return {'kind': 'sample'}
        sampler.record(io.BytesIO(), SimpleNamespace(sample=sample), {}, clock=lambda: clock[0],
                       sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds), duration=8)
        self.assertEqual(starts, [0, 4])


class ClamAVTests(unittest.TestCase):
    config = {'schema': 1, 'address': '172.19.0.3', 'port': 3310, 'container_id': 'a' * 64}

    def test_endpoint_requires_fixed_port_container_identity_and_explicit_private_ipv4(self):
        self.assertEqual(sampler.parse_clamav_config(dict(self.config)), self.config)
        for delta in [{'address': '127.0.0.1'}, {'address': '169.254.1.1'}, {'address': '8.8.8.8'},
                      {'address': '::1'}, {'address': 'localhost'}, {'address': '0.0.0.0'},
                      {'port': 443}, {'port': True}, {'container_id': 'culvert-clamav'}, {'extra': 'field'}]:
            with self.subTest(delta=delta):
                with self.assertRaises(ValueError):
                    sampler.parse_clamav_config(dict(self.config, **delta))

    def test_endpoint_file_requires_root_private_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'clamav.json'
            path.write_text(json.dumps(self.config))
            for mode, uid, expected in [(stat.S_IFREG | 0o600, 0, True),
                                        (stat.S_IFREG | 0o644, 0, False),
                                        (stat.S_IFREG | 0o600, 1000, False),
                                        (stat.S_IFLNK | 0o600, 0, False)]:
                with self.subTest(mode=mode, uid=uid), patch.object(Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid)):
                    if expected:
                        self.assertEqual(sampler.load_clamav_config(path), self.config)
                    else:
                        with self.assertRaises(ValueError):
                            sampler.load_clamav_config(path)

    def ping(self, replies):
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.recv.side_effect = replies
        with patch.object(sampler.socket, 'create_connection', return_value=connection) as connect:
            result = sampler.clamav_ping(self.config)
        connect.assert_called_once_with(('172.19.0.3', 3310), timeout=0.25)
        connection.sendall.assert_called_once_with(b'nPING\n')
        self.assertTrue(all(0 < call.args[0] <= 0.25 for call in connection.settimeout.call_args_list))
        self.assertTrue(all(0 < call.args[0] <= 32 for call in connection.recv.call_args_list))
        return result

    def test_ping_accepts_only_complete_pong_and_handles_fragmentation(self):
        self.assertTrue(self.ping([b'PO', b'NG\n'])['pong'])
        self.assertTrue(self.ping([b'PONG\0'])['pong'])
        for replies in ([b'ERROR\n'], [b'PONG', b''], [b'x' * 32], [b'PONG\nextra']):
            with self.subTest(replies=replies):
                result = self.ping(replies)
                self.assertFalse(result['pong'])
                self.assertEqual(result['error'], 'unexpected_reply')
                self.assertNotIn('address', result)
                self.assertNotIn('container_id', result)

    def test_ping_timeout_and_refusal_are_explicit(self):
        self.assertEqual(self.ping([TimeoutError()])['error'], 'timeout')
        with patch.object(sampler.socket, 'create_connection', side_effect=ConnectionRefusedError()):
            result = sampler.clamav_ping(self.config)
        self.assertEqual(result['error'], 'connection_failed')
        self.assertFalse(result['pong'])
        self.assertGreaterEqual(result['elapsed_ns'], 0)


class GeneratorTests(unittest.TestCase):
    def generated_identity_guard(self):
        script = control.generate('install', BOOT, 'b' * 40, b'# synthetic', 'a' * 64)
        guest = script.split("python3 - <<'CULVERT_LAB_BOOT_SAMPLER'\n", 1)[1].rsplit('\nCULVERT_LAB_BOOT_SAMPLER', 1)[0]
        tree = ast.parse(guest)
        # Run only the actual emitted guard functions, never installer operations.
        functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                     and node.name in ('need', 'vmware_guest_identity')]
        self.assertEqual(len(functions), 2)
        namespace = {'uuid': control.uuid}
        exec(compile(ast.Module(body=functions, type_ignores=[]), '<generated identity guards>', 'exec'), namespace)
        return namespace['vmware_guest_identity'], tree

    def test_vmware_uuid_accepts_only_exact_or_guid_byte_order_alias(self):
        guard, _ = self.generated_identity_guard()
        owner = '564de9b1-cdf7-0472-e998-f3f50d80816d'
        swapped = 'b1e94d56-f7cd-7204-e998-f3f50d80816d'
        self.assertEqual(guard(owner, owner, 'VMware, Inc.'), 'exact')
        self.assertEqual(guard(owner, swapped, 'VMware, Inc.'), 'smbios-byte-swapped')
        for guest, vendor in [(swapped, 'QEMU'), (owner, 'QEMU'), (owner, ''),
                              (owner, 'VMware, Inc. spoof'),
                              ('b1e94d56-f7cd-7204-e998-f3f50d80816e', 'VMware, Inc.'),
                              ('564de9b1-cdf7-0472-98e9-f3f50d80816d', 'VMware, Inc.'),
                              ('00000000-0000-0000-0000-000000000000', 'VMware, Inc.'),
                              (owner.replace('-', ''), 'VMware, Inc.'),
                              ('not-a-uuid', 'VMware, Inc.')]:
            with self.subTest(guest=guest, vendor=vendor):
                with self.assertRaises(ValueError):
                    guard(owner, guest, vendor)

    def test_receipt_preserves_api_owner_and_records_guest_alias_separately(self):
        _, tree = self.generated_identity_guard()
        namespace = {'configuration': dict(owner_uuid=BOOT, source_sha='b'*40, sampler_sha256='c'*64,
                      unit_sha256='d'*64, accounting_sha256='e'*64, generator_sha256='f'*64),
                     'guest_uuid': '22222222-2222-4222-8222-222222222222',
                     'guest_vendor': 'VMware, Inc.', 'uuid_binding': 'smbios-byte-swapped'}
        nodes = [node for node in tree.body if
                 (isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'record' for t in node.targets))
                 or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                     and isinstance(node.value.func, ast.Attribute)
                     and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == 'record')]
        self.assertEqual(len(nodes), 2)
        exec(compile(ast.Module(body=nodes, type_ignores=[]), '<generated receipt identity>', 'exec'), namespace)
        self.assertEqual(namespace['record']['owner_uuid'], BOOT)
        self.assertEqual(namespace['record']['guest_product_uuid'], namespace['guest_uuid'])
        self.assertEqual(namespace['record']['uuid_binding'], 'smbios-byte-swapped')

    def test_generated_receipt_bytes_parse_as_json_with_actual_newline(self):
        # Evaluate only the real generated receipt-content expression, not the
        # installer. This catches double escaping across both source layers.
        script = control.generate('install', BOOT, 'b' * 40, b'# synthetic', 'a' * 64)
        guest = script.split("python3 - <<'CULVERT_LAB_BOOT_SAMPLER'\n", 1)[1].rsplit('\nCULVERT_LAB_BOOT_SAMPLER', 1)[0]
        tree = ast.parse(guest)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'write_new'
                 and isinstance(node.args[0], ast.Name) and node.args[0].id == 'receipt']
        self.assertEqual(len(calls), 1)
        record = {'source_sha': 'b' * 40, 'action': 'installed-for-subsequent-boots'}
        content = eval(compile(ast.Expression(calls[0].args[1]), '<receipt expression>', 'eval'),
                       {'json': json, 'record': record})
        self.assertEqual(json.loads(content), record)
        self.assertTrue(content.endswith(b'\n'))
        self.assertFalse(content.endswith(b'\\n'))

    def test_install_and_remove_scripts_bind_exact_sources_and_compile_without_execution(self):
        helper = Path(__file__).with_name('production-boot-sampler.py').read_bytes()
        for action in ('install', 'remove'):
            script = control.generate(action, BOOT, 'b' * 40, helper, 'a' * 64)
            guest = script.split("python3 - <<'CULVERT_LAB_BOOT_SAMPLER'\n", 1)[1].rsplit('\nCULVERT_LAB_BOOT_SAMPLER', 1)[0]
            compile(guest, '<generated lab installer>', 'exec')
            self.assertIn(hashlib.sha256(helper).hexdigest(), script)
            self.assertIn(hashlib.sha256(control.UNIT.encode()).hexdigest(), script)
            self.assertIn(hashlib.sha256(control.IO_ACCOUNTING.encode()).hexdigest(), script)
            self.assertIn('product_uuid', script)
            self.assertNotIn("run(['systemctl', 'start'", script)
            self.assertNotIn('rm -rf', script)
            self.assertNotIn("run(['systemctl', 'daemon-reexec'", script)

    def test_accounting_dropin_is_fixed_and_in_both_ownership_guards(self):
        self.assertEqual(control.IO_ACCOUNTING, '[Manager]\nDefaultIOAccounting=yes\n')
        self.assertIn('/etc/systemd/system.conf.d/90-culvert-lab-io.conf', control.GUEST)
        self.assertIn('(script, unit, accounting, clamav_config, receipt, enabled, runtime)', control.GUEST)
        self.assertIn("(accounting, configuration['accounting_sha256'])", control.GUEST)
        self.assertIn('accounting.unlink()', control.GUEST)

    def test_installer_only_inspects_narrow_clamav_network_identity(self):
        self.assertIn('{"id":{{json .Id}},"networks":{{json .NetworkSettings.Networks}}}', control.GUEST)
        self.assertIn('len(networks) == 1', control.GUEST)
        self.assertIn("network['NetworkID']]) == 'bridge'", control.GUEST)
        self.assertIn('write_new(clamav_config, endpoint_bytes, 0o600)', control.GUEST)
        self.assertIn("prior['clamav_config_sha256']", control.GUEST)
        self.assertNotIn('.Config.Env', control.GUEST)

    def test_unit_has_bounded_nonblocking_boot_order_and_no_service_dependencies(self):
        self.assertIn('Type=simple\n', control.UNIT)
        self.assertIn('DefaultDependencies=no\nAfter=local-fs.target\nBefore=sysinit.target shutdown.target', control.UNIT)
        self.assertIn('RuntimeMaxSec=915s', control.UNIT)
        self.assertIn('RuntimeDirectoryPreserve=yes', control.UNIT)
        self.assertIn('StandardOutput=null\nStandardError=null', control.UNIT)
        self.assertNotIn('Requires=', control.UNIT)
        self.assertNotIn('docker.service', control.UNIT)

    def test_generator_rejects_ambiguous_scope_and_oversized_source(self):
        for owner, source, helper in [('not-uuid', 'b' * 40, b'x'),
                                      (BOOT, 'branch-name', b'x'), (BOOT, 'b' * 40, b'x' * 65537)]:
            with self.subTest(owner=owner, source=source):
                with self.assertRaises(ValueError):
                    control.generate('install', owner, source, helper, 'a' * 64)


if __name__ == '__main__':
    unittest.main()
