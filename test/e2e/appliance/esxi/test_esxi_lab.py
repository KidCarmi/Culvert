"""Safety and evidence tests, not guest/hypervisor qualification."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
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
            obj.collect()
            with tarfile.open(obj.run / 'esxi-evidence.tgz') as tf:
                self.assertEqual(tf.getnames(), ['results.json'])
                data = tf.extractfile('results.json').read()
                self.assertNotIn(b'sensitive-password', data)
                self.assertIn(b'not-run', data)
                self.assertIn(b'incomplete', data)

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


if __name__ == '__main__':
    unittest.main()
