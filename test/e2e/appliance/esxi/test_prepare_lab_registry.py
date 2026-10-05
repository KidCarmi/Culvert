"""Offline disposable-registry receipt tests; never contact Docker or a VM."""
import base64
import copy
import datetime
import hashlib
import importlib.util
import ipaddress
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


spec = importlib.util.spec_from_file_location('prepare_lab_registry', Path(__file__).with_name('prepare-lab-registry.py'))
registry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(registry)


class RegistryReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic registry test')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .add_extension(x509.SubjectAlternativeName([x509.DNSName('ghcr.io'), x509.DNSName('localhost'),
                                                          x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                .sign(key, hashes.SHA256()))
        cls.pem = cert.public_bytes(serialization.Encoding.PEM).decode()

    def fixture(self):
        baseline = json.dumps({'schemaVersion': 2, 'manifests': [], 'fixture': 'baseline'}).encode()
        target = json.dumps({'schemaVersion': 2, 'manifests': [], 'fixture': 'target'}).encode()
        digest = lambda data: 'sha256:' + hashlib.sha256(data).hexdigest()
        return {'schema': 1, 'source': registry.SOURCE, 'ova_sha256': registry.OVA,
                'baseline_digest': digest(baseline), 'target_digest': digest(target),
                'baseline_manifest_base64': base64.b64encode(baseline).decode(),
                'target_manifest_base64': base64.b64encode(target).decode(),
                'registry_port_bindings': {'443/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '443'}]},
                'target_never_started': True, 'temporary_container_removed': True, 'application_unchanged': True,
                'private_tls_key_exported': False, 'runtime_test_trust': ['/etc/docker/certs.d/localhost:443/ca.crt'],
                'registry_image_id': 'sha256:' + 'a' * 64, 'registry_repo_digests': ['registry@sha256:' + 'b' * 64],
                'public_ca_pem': self.pem}

    def test_exact_manifest_byte_binding(self):
        receipt = self.fixture()
        with patch.object(registry, 'BASELINE', receipt['baseline_digest']):
            target, certificate, fingerprint = registry.validate_receipt(receipt)
            self.assertEqual(target, receipt['target_digest'])
            self.assertEqual(certificate.decode(), self.pem)
            self.assertEqual(len(fingerprint), 64)
            for field in ('baseline_manifest_base64', 'target_manifest_base64'):
                bad = copy.deepcopy(receipt)
                bad[field] = base64.b64encode(b'{"schemaVersion":2}').decode()
                with self.assertRaises(ValueError):
                    registry.validate_receipt(bad)

    def test_missing_safety_evidence_and_broader_exposure_fail_closed(self):
        receipt = self.fixture()
        cases = [('source', 'old-source'), ('ova_sha256', '0' * 64),
                 ('target_digest', receipt['baseline_digest']), ('private_tls_key_exported', True),
                 ('target_never_started', False), ('temporary_container_removed', False),
                 ('application_unchanged', False), ('registry_repo_digests', []),
                 ('runtime_test_trust', ['/etc/ssl/certs/global-ca']),
                 ('registry_port_bindings', {'443/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '443'}]}),
                 ('public_ca_pem', self.pem + '\n-----BEGIN PRIVATE KEY-----\n')]
        with patch.object(registry, 'BASELINE', receipt['baseline_digest']):
            for field, value in cases:
                with self.subTest(field=field):
                    bad = copy.deepcopy(receipt)
                    bad[field] = value
                    with self.assertRaises(ValueError):
                        registry.validate_receipt(bad)

    def test_generated_guest_program_compiles_without_execution(self):
        compile(registry.GUEST, 'synthetic-guest-registry', 'exec')
        script = registry.guest_script().decode()
        self.assertIn(registry.SOURCE, script)
        self.assertIn(registry.BASELINE, script)
        self.assertIn('timeout --signal=TERM --kill-after=10s 1500s', script)


if __name__ == '__main__':
    unittest.main()
