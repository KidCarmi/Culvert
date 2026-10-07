"""Offline escrow contract tests; no VM calls or real credentials."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare_reset', Path(__file__).with_name('prepare-identity-reset.py'))
reset = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reset)


class ResetReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.escrow, self.private = self.root / 'escrow', self.root / 'run' / 'secrets'
        self.escrow.mkdir()
        (self.private / 'p1-regressions').mkdir(parents=True)
        self.scope = {'source_sha': reset.deletion.SOURCE, 'ova_sha256': reset.deletion.OVA,
                      'image_id': reset.IMAGE, 'max_vms': 1, 'endpoint': 'https://192.0.2.1'}
        self.owned = {'uuid': 'synthetic-uuid', 'name': 'synthetic-vm', 'path': '/test/vm/synthetic-vm',
                      'endpoint': self.scope['endpoint'], 'owner': 'synthetic-owner',
                      'ref': {'type': 'VirtualMachine', 'value': 'vm-1'},
                      'ds_ref': {'type': 'Datastore', 'value': 'ds-1'}}
        self.write_json('source-owned.json', self.owned)
        self.write_json('provenance.json', {key: self.scope[key] for key in ('source_sha', 'image_id', 'ova_sha256', 'endpoint')})
        archive = self.escrow / 'recovery.tar.gz.enc'
        archive.write_bytes(b'CVRTBK01synthetic encrypted archive fixture')
        self.write_json('archive-metadata.json', {'schema': 1, 'source_sha': self.scope['source_sha'],
                        'image_id': reset.IMAGE, 'archive_sha256': reset.fresh.file_hash(archive),
                        'archive_bytes': archive.stat().st_size, 'source_data_volume': 'test_data',
                        'source_backup_volume': 'test_backups'})
        self.write_json('recovery-secrets.json', {'CULVERT_CA_PASSPHRASE': 'synthetic-ca',
                        'CULVERT_LOG_PASSPHRASE': '', 'CULVERT_SESSION_SECRET': 'synthetic-session'})
        (self.escrow / 'backup-passphrase').write_text('a' * 64)
        (self.escrow / 'admin-pass').write_text('synthetic-admin-only')
        self.write_json('source-observation.json', {'schema': 1, 'admin_login': 'pass', 'ca_decryption': 'pass',
                        'agent': 'pass', 'ca_sha256': 'b' * 64, 'traffic': {'example.com': 200, 'example.org': 403},
                        'rules': [{'name': 'synthetic'}], 'categories': {'synthetic': {'category': 'test'}}})
        (self.private / 'p1-regressions' / 'identity-before.attempt.json').write_text(
            json.dumps({'status': 'pass', 'uuid': self.owned['uuid']}))
        self.seal()

    def write_json(self, name, value):
        (self.escrow / name).write_text(json.dumps(value))

    def seal(self):
        names = ('recovery.tar.gz.enc', 'recovery-secrets.json', 'archive-metadata.json', 'backup-passphrase',
                 'admin-pass', 'source-owned.json', 'provenance.json', 'source-observation.json')
        self.write_json('export-receipt.json', {'schema': 1, 'result': 'pass',
                        'sha256': {name: reset.fresh.file_hash(self.escrow / name) for name in names}})

    def ready(self):
        return reset.readiness(self.escrow, self.scope, self.owned, self.private)

    def test_verified_export_derives_exact_p1_contract_without_secrets(self):
        result = self.ready()
        self.assertTrue(result['backup_export_verified'] and result['escrow_export_verified'])
        self.assertEqual(result['uuid'], self.owned['uuid'])
        self.assertEqual(result['ova_sha256'], self.scope['ova_sha256'])
        self.assertEqual(result['export_receipt_sha256'], reset.fresh.file_hash(self.escrow / 'export-receipt.json'))
        self.assertNotIn('synthetic-admin-only', json.dumps(result))
        self.assertNotIn('synthetic-ca', json.dumps(result))

    def test_d698_and_legacy_profiles_do_not_reuse_source_or_export_identity(self):
        identities = reset.deletion.module('reset_test_identities', Path(__file__).with_name('candidate-identities.py'))
        for source in (identities.E2E3, identities.D698, identities.B579, identities.E2E3):
            profile = identities.source_profile(source)
            self.scope.update({key: profile[key] for key in ('source_sha', 'ova_sha256', 'image_id')})
            self.write_json('provenance.json', {key: self.scope[key] for key in ('source_sha', 'image_id', 'ova_sha256', 'endpoint')})
            metadata = json.loads((self.escrow / 'archive-metadata.json').read_bytes())
            metadata.update(source_sha=source, image_id=profile['image_id'])
            self.write_json('archive-metadata.json', metadata)
            self.seal()
            result = self.ready()
            self.assertEqual(result['source_sha'], source)
            self.assertEqual(result['image_id'], profile['image_id'])
            self.assertEqual(reset.deletion.campaigns.SOURCE, source)
            other = identities.B579 if source == identities.D698 else identities.D698
            metadata['source_sha'] = other
            self.write_json('archive-metadata.json', metadata)
            self.seal()
            with self.assertRaisesRegex(ValueError, 'archive metadata mismatch'):
                self.ready()

    def test_tampered_or_missing_export_is_refused(self):
        (self.escrow / 'admin-pass').write_text('changed')
        with self.assertRaises(ValueError):
            self.ready()
        (self.escrow / 'admin-pass').unlink()
        with self.assertRaises(ValueError):
            self.ready()

    def test_resealed_wrong_owner_or_incomplete_provenance_is_refused(self):
        original = copy.deepcopy(self.owned)
        for key in ('uuid', 'path', 'endpoint', 'owner', 'ds_ref'):
            other = dict(original, **{key: 'wrong'})
            self.write_json('source-owned.json', other)
            self.seal()
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.ready()
        self.write_json('source-owned.json', original)
        self.write_json('provenance.json', {'source_sha': self.scope['source_sha']})
        self.seal()
        with self.assertRaises(ValueError):
            self.ready()

    def test_invalid_secret_or_repeat_reset_is_refused(self):
        self.write_json('recovery-secrets.json', {'CULVERT_CA_PASSPHRASE': '', 'CULVERT_LOG_PASSPHRASE': '',
                                                'CULVERT_SESSION_SECRET': ''})
        self.seal()
        with self.assertRaises(ValueError):
            self.ready()
        self.write_json('recovery-secrets.json', {'CULVERT_CA_PASSPHRASE': 'fixture', 'CULVERT_LOG_PASSPHRASE': '',
                                                'CULVERT_SESSION_SECRET': ''})
        self.seal()
        (self.private / 'p1-regressions' / 'identity-reset.attempt.json').write_text('{}')
        with self.assertRaises(ValueError):
            self.ready()

    def test_confirmation_uses_separate_pass_and_retains_initial_blocked_result(self):
        initial = self.private / 'p1-regressions' / 'network-before.attempt.json'
        initial.write_text(json.dumps({'status': 'blocked', 'uuid': self.owned['uuid']}))
        confirmation = self.private / 'p1-regressions-confirmation'
        confirmation.mkdir()
        (confirmation / 'network-before.attempt.json').write_text(json.dumps(
            {'status': 'pass', 'uuid': self.owned['uuid'], 'campaign': 'confirmation'}))
        with self.assertRaises(ValueError):
            reset.readiness(self.escrow, self.scope, self.owned, self.private, 'confirmation')
        (confirmation / 'identity-before.attempt.json').write_text(json.dumps(
            {'status': 'pass', 'uuid': self.owned['uuid'], 'campaign': 'confirmation'}))
        result = reset.readiness(self.escrow, self.scope, self.owned, self.private, 'confirmation')
        self.assertEqual(result['campaign'], 'confirmation')
        self.assertEqual(result['initial_failure']['result'], 'blocked')
        self.assertEqual(json.loads(initial.read_text())['status'], 'blocked')


if __name__ == '__main__':
    unittest.main()
