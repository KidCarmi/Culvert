"""Offline guards only: no VM, account, credential, Docker or ESXi operations."""
import hashlib
import contextlib
import ast
import importlib.util
import json
from pathlib import Path
import ssl
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


controller = load('fresh_test_controller', 'fresh-recovery.py')
with mock.patch.dict(sys.modules, {'fcntl': SimpleNamespace(LOCK_EX=2, LOCK_NB=4)}):
    guest = load('fresh_test_guest', 'fresh-recovery-guest.py')


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='culvert-recovery-offline-')
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def transfer(self):
        return controller.Transfer('127.0.0.1', {'archive': self.root / 'archive'}, True, {'archive': 12})

    def test_restore_keeps_candidate_sha_separate_from_source_owner_record(self):
        identities = load('fresh_restore_identities', 'candidate-identities.py')
        scope = dict(identities.source_profile(identities.CD8), max_vms=1, endpoint='https://192.0.2.1')
        escrow = self.root / 'escrow'; escrow.mkdir()
        archive = escrow / 'recovery.tar.gz.enc'; archive.write_bytes(b'CVRTBK01synthetic')
        metadata = {'archive_sha256': controller.file_hash(archive), 'archive_bytes': archive.stat().st_size,
                    'source_sha': scope['source_sha'], 'image_id': scope['image_id']}
        owner = {'uuid': 'old-owned-uuid'}
        data = {'source-owned.json': owner, 'provenance.json': scope,
                'archive-metadata.json': metadata, 'ledger.json': {}, 'deletion.json': {}}
        (escrow / 'backup-passphrase').write_text('a' * 64)
        lab = SimpleNamespace(c=scope, run=self.root, guest_ip=mock.Mock(return_value='192.0.2.2'), vm=mock.Mock())
        args = SimpleNamespace(bind='192.0.2.1', scope=Path('synthetic'), escrow=escrow,
                               source_ledger=Path('ledger.json'), deletion_receipt=Path('deletion.json'), mode='restore')
        with mock.patch.object(controller.console.b.module, 'Lab', return_value=lab), \
             mock.patch.object(controller.console.b.module, 'validate_scope'), \
             mock.patch.object(controller.console.b.module, 'locked', return_value=contextlib.nullcontext()), \
             mock.patch.object(controller, 'private_escrow', return_value=escrow), \
             mock.patch.object(controller, 'verify_export'), \
             mock.patch.object(controller, 'verify_source_absent') as absent, \
             mock.patch.object(controller, 'read_json', side_effect=lambda path: data[path.name]), \
             mock.patch.object(controller, 'endpoint', return_value=contextlib.nullcontext(('test-pin', {}))), \
             mock.patch.object(controller.console, 'execute', side_effect=RuntimeError('offline-before-dispatch')) as execute:
            with self.assertRaisesRegex(RuntimeError, 'offline-before-dispatch'):
                controller.run(args)
        self.assertIs(absent.call_args.args[1], owner)
        payload = execute.call_args.args[2].decode()
        cfg = ast.literal_eval(payload.rsplit('\nmain(', 1)[1].split(')\nCULVERT_FRESH_RECOVERY_PY', 1)[0])
        self.assertEqual(cfg['source_sha'], identities.CD8)
        self.assertIsInstance(cfg['source_sha'], str)
        self.assertEqual(cfg['archive_sha256'], metadata['archive_sha256'])

    def test_transfer_rejects_wrong_peer_path_method_size_and_overwrite(self):
        transfer = self.transfer()
        path = transfer.paths['archive']
        for peer, resource, upload, size in (
            ('127.0.0.2', path, True, 5), ('127.0.0.1', path + '?x', True, 5),
            ('127.0.0.1', path, False, 5), ('127.0.0.1', path, True, 0),
            ('127.0.0.1', path, True, 13), ('127.0.0.1', path, True, True)):
            with self.subTest(peer=peer, resource=resource, upload=upload, size=size):
                with self.assertRaises(ValueError):
                    transfer.admit(peer, resource, upload, size)
        self.assertFalse(transfer.used)
        (self.root / 'archive').write_bytes(b'existing')
        with self.assertRaises(ValueError):
            transfer.admit('127.0.0.1', path, True, 5)
        self.assertEqual((self.root / 'archive').read_bytes(), b'existing')

    def test_transfer_consumes_nonce_before_interrupted_write(self):
        transfer = self.transfer()
        path = transfer.paths['archive']
        self.assertEqual(transfer.admit('127.0.0.1', path, True, 5), 'archive')
        with self.assertRaises(ValueError):
            transfer.admit('127.0.0.1', path, True, 5)
        self.assertFalse(transfer.completed)

    def test_actual_tls_listener_upload_and_one_use(self):
        transfer = self.transfer()
        tls = self.root / 'tls'
        tls.mkdir()
        with controller.endpoint(transfer, '127.0.0.1', tls) as (pin, urls):
            self.assertRegex(pin, r'^sha256//[A-Za-z0-9+/]{43}=$')
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(urllib.request.Request(urls['archive'], data=b'synthetic'), context=context, timeout=5) as response:
                self.assertEqual(response.status, 200)
            with self.assertRaises(urllib.error.HTTPError) as rejected:
                urllib.request.urlopen(urllib.request.Request(urls['archive'], data=b'again'), context=context, timeout=5)
            self.assertEqual(rejected.exception.code, 403)
        self.assertEqual(transfer.completed, {'archive'})
        self.assertEqual((self.root / 'archive').read_bytes(), b'synthetic')

    def test_guest_transfer_always_pins_and_bounds(self):
        value = guest.Guest.__new__(guest.Guest)
        value.cfg = {'pin': 'sha256//synthetic', 'urls': {'archive': 'https://192.0.2.1/nonce'}}
        value.run = mock.Mock()
        for upload in (True, False):
            value.transfer('archive', Path('/private/archive'), upload)
            args, kwargs = value.run.call_args
            argv = args[0]
            self.assertEqual(argv[argv.index('--pinnedpubkey') + 1], value.cfg['pin'])
            self.assertEqual(argv[argv.index('--max-time') + 1], '300')
            self.assertEqual(kwargs['timeout'], 310)
            self.assertIn('--data-binary' if upload else '--output', argv)

    def proof_fixture(self):
        source = {'uuid': 'source-uuid', 'path': '/owned/source', 'endpoint': 'https://192.0.2.1',
                  'owner': 'synthetic-owner', 'ref': {'type': 'VirtualMachine', 'value': 'vm-1'}}
        deleted = dict(source, deleted=True, phase='deleted')
        receipt = {'schema': 1, 'source_uuid': source['uuid'], 'source_path': source['path'],
                   'endpoint': 'https://192.0.2.1', 'source_disks_deleted': True,
                   'source_disk_paths': ['[owned] source/disk.vmdk'], 'one_vm_limit': 1}
        lab = SimpleNamespace(state={'uuid': 'fresh-uuid'}, c={'endpoint': receipt['endpoint'], 'max_vms': 1},
            gov=mock.Mock(return_value={'virtualMachines': []}),
            vm=mock.Mock(return_value={'config': {'hardware': {'device': [{'backing': {'fileName': '[owned] fresh/disk.vmdk'}}]}}}))
        return lab, source, deleted, receipt

    def test_proof_requires_deletion_ledger_and_live_inventory(self):
        controller.verify_source_absent(*self.proof_fixture())
        for variant in ('same-uuid', 'not-deleted', 'wrong-endpoint', 'disks-not-deleted', 'source-live', 'disk-reused', 'two-vms'):
            lab, source, deleted, receipt = self.proof_fixture()
            if variant == 'same-uuid': lab.state['uuid'] = source['uuid']
            elif variant == 'not-deleted': deleted['deleted'] = False
            elif variant == 'wrong-endpoint': receipt['endpoint'] = 'https://192.0.2.2'
            elif variant == 'disks-not-deleted': receipt['source_disks_deleted'] = False
            elif variant == 'source-live': lab.gov.return_value = {'virtualMachines': [{}]}
            elif variant == 'disk-reused': receipt['source_disk_paths'] = ['[owned] fresh/disk.vmdk']
            else: lab.c['max_vms'] = 2
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                controller.verify_source_absent(lab, source, deleted, receipt)

    def test_escrow_cannot_be_inside_or_contain_run(self):
        child = self.root / 'run'
        child.mkdir()
        for escrow, run in ((child, self.root), (self.root, child), (child, child)):
            with self.assertRaises(ValueError):
                controller.private_escrow(escrow, run)

    def test_complete_receipt_and_hashes_required(self):
        with self.assertRaises(ValueError):
            controller.verify_export(self.root)
        names = ('recovery.tar.gz.enc', 'recovery-secrets.json', 'archive-metadata.json',
                 'backup-passphrase', 'admin-pass', 'source-owned.json', 'provenance.json', 'source-observation.json')
        for name in names:
            (self.root / name).write_bytes(b'synthetic')
        receipt = {'schema': 1, 'result': 'pass', 'sha256': {name: hashlib.sha256(b'synthetic').hexdigest() for name in names}}
        (self.root / 'export-receipt.json').write_text(json.dumps(receipt))
        controller.verify_export(self.root)
        (self.root / 'recovery-secrets.json').write_bytes(b'changed')
        with self.assertRaises(ValueError):
            controller.verify_export(self.root)

    def test_stop_failure_never_restarts_or_commits(self):
        value = guest.Guest.__new__(guest.Guest)
        value.data = self.root / 'data'; value.data.mkdir()
        value.backup = self.root / 'backup'; value.backup.mkdir()
        value.work = self.root / 'work'; value.work.mkdir()
        value.uid = 1; value.gid = 1
        payload = b'CVRTBK01synthetic'
        value.cfg = {'archive_name': 'fixture.enc', 'archive_bytes': len(payload), 'archive_sha256': hashlib.sha256(payload).hexdigest()}
        def transfer(kind, path, unused_upload):
            path.write_bytes(payload if kind == 'archive' else json.dumps(dict.fromkeys(guest.SECRET_NAMES, 'SYNTHETIC')).encode())
        value.transfer = transfer
        value.dc = mock.Mock(side_effect=RuntimeError('synthetic stop failure'))
        with mock.patch.object(guest.os, 'chown', create=True), mock.patch.object(guest.os, 'chmod'):
            with self.assertRaises(RuntimeError):
                value.restore()
        value.dc.assert_called_once_with('stop')

    def test_policy_normalization_only_ignores_volatile_counters(self):
        normalize = controller.observation.normalized_rules
        self.assertEqual(normalize({'draft': False, 'persisted': True, 'rules': [{'name': 'rule', 'hitCount': 4, 'lastHit': 'now'}]}), [{'name': 'rule'}])
        for bad in ({'draft': True, 'persisted': True, 'rules': [{}]}, {'draft': False, 'persisted': False, 'rules': [{}]}):
            with self.assertRaises(ValueError): normalize(bad)


if __name__ == '__main__':
    unittest.main()
