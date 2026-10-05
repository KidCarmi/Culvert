"""Safety and evidence tests, not guest/hypervisor qualification."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('esxi_lab', Path(__file__).with_name('esxi-lab.py'))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)

OVF = b'''<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
 xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
 xmlns:r="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData">
 <References><File ovf:href="disk.vmdk"/></References>
 <DiskSection><Disk ovf:capacity="32" ovf:capacityAllocationUnits="byte * 2^30"/></DiskSection>
 <NetworkSection><Network ovf:name="VM Network"/></NetworkSection>
 <VirtualSystem><VirtualHardwareSection>
 <Item><r:ResourceType>3</r:ResourceType><r:VirtualQuantity>2</r:VirtualQuantity></Item>
 <Item><r:ResourceType>4</r:ResourceType><r:AllocationUnits>byte * 2^20</r:AllocationUnits><r:VirtualQuantity>4096</r:VirtualQuantity></Item>
 </VirtualHardwareSection></VirtualSystem></Envelope>'''


def scope(tmp):
    return dict(endpoint='https://esxi.invalid', host='/dc/host/esxi/esxi', datastore='/dc/datastore/lab',
                network='/dc/network/lab', folder='/dc/vm', pool='/dc/host/esxi/Resources',
                ova=str(tmp / 'candidate.ova'), ova_sha256=lab.ORIGINAL_SHA,
                source_sha=lab.ORIGINAL_SOURCE, image_id=lab.ORIGINAL_IMAGE,
                run_dir=str(tmp / 'run'), max_vms=1, max_vcpus=2, max_memory_mb=4096,
                max_disk_gib=32, datastore_headroom_gib=64, host_headroom_mb=4096,
                host_cpu_headroom_mhz=2000, guest_cidr='192.0.2.0/24')


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'test.ova'

    def archive(self, mutate=None):
        payload = [('candidate.ovf', OVF), ('disk.vmdk', b'synthetic disk - never booted')]
        manifest = ''.join(f'SHA256({n})= {hashlib.sha256(d).hexdigest()}\n' for n, d in payload).encode()
        members = payload + [('candidate.mf', manifest)]
        if mutate:
            members = mutate(members)
        with tarfile.open(self.path, 'w') as t:
            for name, data in members:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                t.addfile(info, io.BytesIO(data))
        return hashlib.sha256(self.path.read_bytes()).hexdigest()

    def test_complete_manifest_and_capacity(self):
        result = lab.verify_ova(self.path, self.archive())
        self.assertEqual(result['disk_bytes'], 32 * lab.GIB)
        self.assertEqual((result['cpus'], result['memory_mb']), (2, 4096))

    def test_wrong_outer_hash(self):
        self.archive()
        with self.assertRaisesRegex(lab.Refused, 'OVA SHA256'):
            lab.verify_ova(self.path, '0' * 64)

    def test_missing_manifest(self):
        sha = self.archive(lambda m: m[:2])
        with self.assertRaises(lab.Refused):
            lab.verify_ova(self.path, sha)

    def test_empty_manifest(self):
        sha = self.archive(lambda m: m[:2] + [('candidate.mf', b'')])
        with self.assertRaisesRegex(lab.Refused, 'every payload'):
            lab.verify_ova(self.path, sha)

    def test_uncovered_payload(self):
        sha = self.archive(lambda m: m + [('extra.vmdk', b'not covered')])
        with self.assertRaises(lab.Refused):
            lab.verify_ova(self.path, sha)

    def test_duplicate_member(self):
        sha = self.archive(lambda m: m + [m[0]])
        with self.assertRaisesRegex(lab.Refused, 'duplicate archive'):
            lab.verify_ova(self.path, sha)

    def test_path_traversal(self):
        sha = self.archive(lambda m: m + [('../outside', b'unsafe')])
        with self.assertRaisesRegex(lab.Refused, 'unsafe archive'):
            lab.verify_ova(self.path, sha)

    def test_malformed_manifest_never_silently_skipped(self):
        sha = self.archive(lambda m: m[:-1] + [('candidate.mf', m[-1][1] + b'SHA256(bad)= typo\n')])
        with self.assertRaisesRegex(lab.Refused, 'malformed'):
            lab.verify_ova(self.path, sha)

    def test_wrong_inner_hash(self):
        sha = self.archive(lambda m: [m[0], ('disk.vmdk', b'changed'), m[2]])
        with self.assertRaisesRegex(lab.Refused, 'manifest digest'):
            lab.verify_ova(self.path, sha)

    def test_symlink_member(self):
        self.archive()
        with tarfile.open(self.path, 'a') as t:
            link = tarfile.TarInfo('link')
            link.type = tarfile.SYMTYPE
            link.linkname = 'disk.vmdk'
            t.addfile(link)
        with self.assertRaisesRegex(lab.Refused, 'unsafe archive'):
            lab.verify_ova(self.path, hashlib.sha256(self.path.read_bytes()).hexdigest())


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.c = scope(Path(tempfile.gettempdir()).resolve())
        self.a = dict(cpus=2, memory_mb=4096, disk_bytes=32 * lab.GIB)
        self.ds = dict(accessible=True, maintenanceMode='normal', freeSpace=110 * lab.GIB)
        self.host = dict(runtime=dict(connectionState='connected', inMaintenanceMode=False),
                         hardware=dict(memorySize=32 * lab.GIB, numCpuCores=8, cpuMhz=2000),
                         quickStats=dict(overallMemoryUsage=4096, overallCpuUsage=2000))

    def test_scope_requires_all_limits(self):
        self.assertEqual(lab.validate_scope(self.c), self.c)
        del self.c['datastore_headroom_gib']
        with self.assertRaisesRegex(lab.Refused, 'missing scope'):
            lab.validate_scope(self.c)

    def test_no_credentials_in_endpoint(self):
        self.c['endpoint'] = 'https://root:secret@esxi.invalid'
        with self.assertRaises(lab.Refused):
            lab.validate_scope(self.c)

    def test_credential_modes_are_explicit(self):
        for mode in ('key', 'none'):
            self.c['credential_mode'] = mode
            lab.validate_scope(self.c)
        self.c['credential_mode'] = 'password-in-scope'
        with self.assertRaisesRegex(lab.Refused, 'credential_mode'):
            lab.validate_scope(self.c)

    def test_no_wildcard_scope(self):
        self.c['datastore'] = '/dc/datastore/*'
        with self.assertRaises(lab.Refused):
            lab.validate_scope(self.c)

    def test_full_disk_and_swap_reserved(self):
        r = lab.check_capacity(self.c, self.a, self.ds, self.host)
        self.assertEqual(r['datastore_reserve_bytes'], 38 * lab.GIB)
        self.ds['freeSpace'] = 100 * lab.GIB  # free now, but below 64 GiB after full growth
        with self.assertRaisesRegex(lab.Refused, 'datastore headroom'):
            lab.check_capacity(self.c, self.a, self.ds, self.host)

    def test_memory_headroom(self):
        self.host['quickStats']['overallMemoryUsage'] = 27000
        with self.assertRaisesRegex(lab.Refused, 'RAM headroom'):
            lab.check_capacity(self.c, self.a, self.ds, self.host)

    def test_cpu_headroom(self):
        self.host['quickStats']['overallCpuUsage'] = 12000
        with self.assertRaisesRegex(lab.Refused, 'CPU headroom'):
            lab.check_capacity(self.c, self.a, self.ds, self.host)


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.s = dict(owner='LOCAL-ESXI:test', name='culvert-esxi-test', uuid='unique',
                      ref={'value': 'vm-1'}, host_ref={'value': 'host-1'},
                      ds_ref={'value': 'ds-1'}, network_ref={'value': 'net-1'})
        self.vm = dict(name=self.s['name'], self=self.s['ref'],
                       config=dict(annotation=self.s['owner'], uuid=self.s['uuid']),
                       runtime=dict(host=self.s['host_ref']), datastore=[self.s['ds_ref']], network=[self.s['network_ref']])

    def test_owned_control(self):
        self.assertEqual(lab.assert_owned(self.vm, self.s, {}), self.vm)

    def test_refuses_same_name_replacement(self):
        self.vm['config']['uuid'] = 'unrelated'
        with self.assertRaisesRegex(lab.Refused, 'identity mismatch'):
            lab.assert_owned(self.vm, self.s, {})

    def test_refuses_missing_annotation_even_if_uuid_matches(self):
        self.vm['config']['annotation'] = ''
        with self.assertRaisesRegex(lab.Refused, 'ownership marker'):
            lab.assert_owned(self.vm, self.s, {})

    def test_refuses_host_datastore_network_drift_and_snapshots(self):
        for field, value in [('runtime', {'host': {'value': 'other'}}), ('datastore', []),
                             ('network', []), ('snapshot', {'root': 'snapshot-1'})]:
            vm = copy.deepcopy(self.vm)
            vm[field] = value
            with self.subTest(field=field), self.assertRaises(lab.Refused):
                lab.assert_owned(vm, self.s, {})


class EvidenceTests(unittest.TestCase):
    def test_raw_secrets_cannot_enter_allowlisted_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            cfg = p / 'scope.json'
            cfg.write_text(json.dumps(scope(p)))
            obj = lab.Lab(cfg)
            (obj.sec / 'admin-pass').write_text('sensitive-password')
            (obj.ev / 'console.log').write_text('BEGIN OPENSSH PRIVATE KEY sensitive-password')
            obj.record('probe', 'blocked', 'sensitive-password')
            obj.record('actual-restore', 'pass', 'synthetic test evidence')
            obj.collect()
            with tarfile.open(obj.run / 'esxi-evidence.tgz') as tf:
                self.assertEqual(tf.getnames(), ['results.json'])
                data = tf.extractfile('results.json').read()
                self.assertNotIn(b'sensitive-password', data)
                self.assertIn(b'not-run', data)
                self.assertIn(b'incomplete', data)
                restore = [r for r in json.loads(data)['results'] if r['check'] == 'actual-restore']
                self.assertEqual(restore, [dict(step='ESXi', check='actual-restore', result='pass')])

    def test_govc_errors_never_echo_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            cfg = p / 'scope.json'
            cfg.write_text(json.dumps(scope(p)))
            obj = lab.Lab(cfg)
            completed = subprocess.CompletedProcess([], 1, '', 'https://root:secret@esxi.invalid')
            with patch.object(subprocess, 'run', return_value=completed), self.assertRaises(lab.Refused) as e:
                obj.gov('about')
            self.assertNotIn('secret', str(e.exception))

    def test_stale_operation_lock_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            with lab.locked(p):
                with self.assertRaises(lab.Refused):
                    with lab.locked(p):
                        self.fail('concurrent mutation allowed')


class PrivateCleanupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        cfg = self.root / 'scope.json'
        cfg.write_text(json.dumps(scope(self.root)))
        self.obj = lab.Lab(cfg)
        self.outside = self.root / 'outside'
        self.outside.mkdir()
        (self.outside / 'keep').write_text('outside-synthetic-canary')
        (self.obj.sec / 'top-secret').write_text('synthetic-private-data')

    def test_nested_cleanup_keeps_root_and_outside(self):
        nested = self.obj.sec / 'go-cache' / 'aa'
        nested.mkdir(parents=True)
        (nested / 'compiled').write_text('synthetic-cache')
        restore = self.obj.sec / 'actual-restore' / 'payload'
        restore.mkdir(parents=True)
        (restore / 'backup').write_text('synthetic-backup')
        lab.cleanup_private_tree(self.obj.run, self.obj.sec)
        self.assertTrue(self.obj.sec.is_dir())
        self.assertEqual(list(self.obj.sec.iterdir()), [])
        self.assertEqual((self.outside / 'keep').read_text(), 'outside-synthetic-canary')

    def test_wrong_root_refused_before_any_deletion(self):
        with self.assertRaises(lab.Refused):
            lab.cleanup_private_tree(self.obj.run, self.outside)
        self.assertTrue((self.obj.sec / 'top-secret').exists())
        self.assertTrue((self.outside / 'keep').exists())

    def test_reparse_entry_refuses_whole_tree_before_deletion(self):
        unsafe = self.obj.sec / 'junction'
        unsafe.mkdir()
        original = Path.lstat

        def flagged(path):
            result = original(path)
            if path == unsafe:
                return SimpleNamespace(st_mode=result.st_mode, st_dev=result.st_dev, st_ino=result.st_ino,
                                       st_file_attributes=0x400)
            return result

        with patch.object(Path, 'lstat', flagged), self.assertRaises(lab.Refused):
            lab.cleanup_private_tree(self.obj.run, self.obj.sec)
        self.assertTrue((self.obj.sec / 'top-secret').exists())
        self.assertTrue(unsafe.is_dir())
        self.assertTrue((self.outside / 'keep').exists())

    def test_symlink_escape_refuses_whole_tree_before_deletion(self):
        link = self.obj.sec / 'escape'
        try:
            link.symlink_to(self.outside, target_is_directory=True)
        except OSError:
            self.skipTest('creating symlinks requires unavailable Windows privilege')
        with self.assertRaises(lab.Refused):
            lab.cleanup_private_tree(self.obj.run, self.obj.sec)
        self.assertTrue((self.obj.sec / 'top-secret').exists())
        self.assertTrue((self.outside / 'keep').exists())
        link.unlink()

    def test_deleted_vm_cleanup_failure_can_retry_without_vm_calls(self):
        self.obj.state = dict(deleted=True, phase='deleted')
        original = Path.unlink

        def refuse(path, *args, **kwargs):
            if path == self.obj.sec / 'top-secret':
                raise PermissionError('synthetic locked file')
            return original(path, *args, **kwargs)

        with patch.object(self.obj, 'vm') as vm, patch.object(self.obj, 'gov') as gov, \
                patch.object(self.obj, 'record') as record:
            with patch.object(Path, 'unlink', refuse), self.assertRaises(PermissionError):
                self.obj.down()
            record.assert_not_called()
            self.assertTrue((self.obj.sec / 'top-secret').exists())
            self.obj.down()
            vm.assert_not_called()
            gov.assert_not_called()
            record.assert_called_once_with('cleanup', 'pass', 'owned VM deletion confirmed; private run files removed')
        self.assertEqual(list(self.obj.sec.iterdir()), [])


class FakeTunnel:
    def __init__(self, exited=False):
        self.exited = exited
        self.reaped = False

    def poll(self):
        return 255 if self.exited else None

    def terminate(self):
        self.exited = True

    def wait(self, timeout):
        self.reaped = True
        return 255


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.now = 0
        self.procs = []
        self.addresses = []
        self.events = []

    def sleep(self, seconds):
        self.now += seconds

    def start(self, ip):
        self.addresses.append(ip)
        proc = FakeTunnel()
        self.procs.append(proc)
        return proc

    def supervisor(self, resolve=None, ready=None, timeout=10):
        return lab.TunnelSupervisor(resolve or (lambda timeout: '192.0.2.10'), self.start,
                                    ready or (lambda timeout: True), lambda *event: self.events.append(event),
                                    timeout=timeout, clock=lambda: self.now, sleep=self.sleep)

    def test_reconnects_after_reboot_and_dhcp_change(self):
        addresses = iter(('192.0.2.10', '192.0.2.11'))
        supervisor = self.supervisor(resolve=lambda timeout: next(addresses))
        supervisor.ensure()
        self.procs[0].exited = True  # real reboot drops the forwarding connection
        supervisor.ensure()
        self.assertEqual(self.addresses, ['192.0.2.10', '192.0.2.11'])
        self.assertTrue(self.procs[0].reaped)
        self.assertEqual(supervisor.connections, 2)
        self.assertEqual(self.events[-1][0], 'transport-reconnected')
        supervisor.close()
        self.assertTrue(all(p.reaped and p.exited for p in self.procs))

    def test_never_returning_guest_fails_with_deadline_and_cleanup(self):
        supervisor = self.supervisor(ready=lambda timeout: False)
        with self.assertRaisesRegex(lab.Refused, 'deadline exceeded'):
            supervisor.ensure()
        self.assertLessEqual(self.now, 10)
        self.assertTrue(all(p.reaped and p.exited for p in self.procs))
        self.assertEqual(self.events[-1][1], 'fail')
        self.assertEqual(supervisor.connections, 0)

    def test_living_unready_tunnel_is_not_counted_connected(self):
        supervisor = self.supervisor(ready=lambda timeout: False, timeout=1)
        with self.assertRaises(lab.Refused):
            supervisor.ensure()
        self.assertNotIn('pass', [r[1] for r in self.events])

    def test_out_of_scope_dhcp_address_never_starts_tunnel(self):
        def refused(timeout):
            raise lab.Refused('guest IP outside approved CIDR')
        supervisor = self.supervisor(resolve=refused)
        with self.assertRaises(lab.Refused):
            supervisor.ensure()
        self.assertEqual(self.procs, [])
        self.assertLessEqual(self.now, 10)

    def test_suite_budget_caps_reconnect_time(self):
        supervisor = self.supervisor(ready=lambda timeout: False, timeout=2400)
        with self.assertRaises(lab.Refused):
            supervisor.ensure(budget=3)
        self.assertLessEqual(self.now, 3)

    def test_stable_host_key_alias_and_strict_reconnect(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            cfg = p / 'scope.json'
            cfg.write_text(json.dumps(scope(p)))
            obj = lab.Lab(cfg)
            obj.state = {'name': 'culvert-esxi-owned'}
            for address in ('192.0.2.10', '192.0.2.11'):
                cmd = obj.ssh_command(address)
                self.assertIn('StrictHostKeyChecking=yes', cmd)
                self.assertIn('HostKeyAlias=culvert-esxi-owned', cmd)
                self.assertEqual(cmd[-1], 'culvert@' + address)
            self.assertIn('StrictHostKeyChecking=accept-new', obj.ssh_command('192.0.2.10', strict=False))

    def test_real_forwarding_process_loss_and_recovery(self):
        # Real child processes and loopback sockets, not SSH or a guest claim.
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        children = []
        def start(ip):
            code = ('import socket\n'
                    's=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n'
                    f's.bind(("127.0.0.1",{port}));s.listen()\n'
                    'while True:\n c,a=s.accept();c.sendall(b"ready");c.close()\n')
            proc = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            children.append(proc)
            return proc
        def ready(timeout):
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=timeout) as conn:
                    return conn.recv(5) == b'ready'
            except OSError:
                return False
        supervisor = lab.TunnelSupervisor(lambda timeout: '127.0.0.1', start, ready, lambda *args: None, timeout=5)
        try:
            supervisor.ensure()
            children[0].terminate()
            children[0].wait(timeout=3)
            supervisor.ensure()
            self.assertEqual(supervisor.connections, 2)
            self.assertTrue(ready(1))
        finally:
            supervisor.close()
        self.assertTrue(all(p.poll() is not None for p in children))


class ObservationTests(unittest.TestCase):
    def test_esxi_network_ref_with_spaces_is_valid_but_path_must_match(self):
        path = '/ha-datacenter/network/VM Network'
        listing = {'elements': [{'Path': path, 'Object': {'self': {
            'type': 'Network', 'value': 'HaNetwork-VM Network'}}}]}
        self.assertEqual(lab.network_ref(listing, path)['value'], 'HaNetwork-VM Network')
        with self.assertRaises(lab.Refused):
            lab.network_ref(listing, '/ha-datacenter/network/Other')
        listing['elements'].append(listing['elements'][0])
        with self.assertRaises(lab.Refused):
            lab.network_ref(listing, path)

    def test_ownership_refusal_prevents_console_or_guest_access(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            cfg = p / 'scope.json'
            cfg.write_text(json.dumps(scope(p)))
            obj = lab.Lab(cfg)
            with patch.object(obj, 'vm', side_effect=lab.Refused('ownership mismatch')), \
                 patch.object(obj, 'gov') as gov, patch.object(obj, 'guest_ip') as ip:
                with self.assertRaises(lab.Refused):
                    obj.inspect()
                gov.assert_not_called()
                ip.assert_not_called()

    def test_console_is_private_and_pending_firstboot_is_not_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            cfg = p / 'scope.json'
            cfg.write_text(json.dumps(scope(p)))
            obj = lab.Lab(cfg)
            obj.state = dict(name='owned-vm', path='/dc/vm/owned-vm')
            vm = dict(config=dict(firmware='bios', version='vmx-13', hardware={}),
                      runtime=dict(powerState='poweredOn'))
            guest = dict(complete=False, firstboot_cycle=False, instance_id='owned-vm')
            completed = subprocess.CompletedProcess([], 0, json.dumps(guest), '')
            with patch.object(obj, 'vm', return_value=vm), patch.object(obj, 'gov') as gov, \
                 patch.object(obj, 'guest_ip', return_value='192.0.2.10'), \
                 patch.object(subprocess, 'run', return_value=completed):
                obj.inspect()
            capture = Path(gov.call_args.args[1].removeprefix('-capture='))
            self.assertEqual(capture.parent, obj.sec)
            self.assertRegex(capture.name, r'^console-[0-9]+\.png$')
            rows = [json.loads(s) for s in (obj.ev / 'adapter.jsonl').read_text().splitlines()]
            self.assertFalse(any(r['result'] == 'fail' for r in rows))
            obj.collect()
            with tarfile.open(obj.run / 'esxi-evidence.tgz') as tf:
                self.assertEqual(tf.getnames(), ['results.json'])


class ImageArchiveTests(unittest.TestCase):
    def exercise(self, omit=False, corrupt=False):
        spec = importlib.util.spec_from_file_location('image_check', Path(__file__).with_name('image-archive-check.py'))
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        payloads = [b'{"architecture":"amd64","os":"linux"}', b'synthetic layer']
        descriptors = [dict(digest='sha256:' + hashlib.sha256(b).hexdigest(), size=len(b)) for b in payloads]
        manifest = json.dumps(dict(schemaVersion=2, config=descriptors[0], layers=descriptors[1:])).encode()
        manifest_sha = hashlib.sha256(manifest).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'image.tar.gz'
            with tarfile.open(path, 'w:gz') as tf:
                contents = [(manifest_sha, manifest)]
                if not omit:
                    contents += [(d['digest'].split(':')[1], b) for d, b in zip(descriptors, payloads)]
                if corrupt:
                    contents[-1] = (contents[-1][0], b'corrupted layer')
                for name, body in contents:
                    info = tarfile.TarInfo('blobs/sha256/' + name)
                    info.size = len(body)
                    tf.addfile(info, io.BytesIO(body))
            return checker.check(path, manifest_sha)

    def test_complete_selected_platform_closure(self):
        self.assertEqual(self.exercise()['result'], 'PASS')

    def test_manifest_only_export_cannot_pass(self):
        result = self.exercise(omit=True)
        self.assertEqual(result['result'], 'FAIL')
        self.assertEqual([d['role'] for d in result['missing']], ['config', 'layer'])

    def test_present_corrupt_blob_cannot_pass(self):
        result = self.exercise(corrupt=True)
        self.assertEqual(result['result'], 'FAIL')
        self.assertEqual(result['invalid'][0]['role'], 'layer')


class CredentialTests(unittest.TestCase):
    def test_environment_auth_stays_runtime_only(self):
        source = {'GOVC_USERNAME': 'synthetic', 'GOVC_PASSWORD': 'synthetic-test-only'}
        self.assertEqual(lab.credential_environment({}, source), source)

    def test_tls_exception_must_match_exact_endpoint(self):
        c = scope(Path(tempfile.gettempdir()).resolve())
        c.update(tls_insecure=True, tls_exception_endpoint='https://other.invalid')
        with self.assertRaisesRegex(lab.Refused, 'exact endpoint'):
            lab.validate_scope(c)
        c['tls_exception_endpoint'] = c['endpoint']
        lab.validate_scope(c)


if __name__ == '__main__':
    unittest.main()
