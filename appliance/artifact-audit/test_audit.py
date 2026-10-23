import hashlib
import io
import json
from pathlib import Path
import tarfile
import struct
import tempfile
import unittest

import audit


def archive_bytes(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode='w') as archive:
        for name, value in entries:
            info = tarfile.TarInfo(name)
            info.size = len(value)
            archive.addfile(info, io.BytesIO(value))
    return output.getvalue()


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.audit = audit.Audit(Path(self.temp.name))

    def test_secret_indicators_never_include_matched_contents(self):
        value = b'password="SyntheticCanaryValue2345"\n-----BEGIN PRIVATE KEY-----\n'
        self.audit.scan_file(io.BytesIO(value), len(value), 'fixture/config')
        report = json.dumps(self.audit.findings)
        self.assertNotIn('SyntheticCanary', report)
        self.assertNotIn('BEGIN PRIVATE', report)
        self.assertEqual(len(self.audit.findings), 2)

    def test_every_oci_layer_including_whiteouted_secret_is_scanned(self):
        first = archive_bytes([('root/.aws/credentials', b'password="SyntheticRemovedValue2345"')])
        second = archive_bytes([('root/.aws/.wh.credentials', b'')])
        digests = [hashlib.sha256(layer).hexdigest() for layer in (first, second)]
        manifest = json.dumps({'layers': [{'digest': 'sha256:' + d} for d in digests]}).encode()
        image = archive_bytes([('blobs/sha256/' + digests[0], first), ('blobs/sha256/' + digests[1], second), ('blobs/sha256/manifest', manifest)])
        self.audit.scan_file(io.BytesIO(image), len(image), 'fixture/image.tar')
        self.assertEqual(self.audit.expected_layers, self.audit.scanned_layers - {'fixture/image.tar'})
        self.assertEqual(len(self.audit.expected_layers), 2)
        self.assertTrue(any(f['category'] == 'literal_credential_assignment_indicator' for f in self.audit.findings))
        self.assertEqual(self.audit.counts['whiteout_entries_retained'], 1)

    def test_archive_traversal_rejected_without_extraction(self):
        for name in ('../outside', '/absolute', 'C:/escape', 'a\\b'):
            with self.subTest(name=name), self.assertRaises(audit.Refused):
                data = archive_bytes([(name, b'fixture')])
                self.audit.scan_file(io.BytesIO(data), len(data), 'fixture/image.tar')
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])
        self.assertTrue(audit.valid_member('05c6:1234'))

    def test_short_file_and_budget_are_not_success(self):
        with self.assertRaises(audit.Refused):
            self.audit.scan_file(io.BytesIO(b'x'), 2, 'fixture')
        expired = audit.Audit(Path(self.temp.name), seconds=-1)
        with self.assertRaises(audit.Refused):
            expired.scan_file(io.BytesIO(b'x'), 1, 'fixture')

    def test_shadow_locked_is_not_flagged_but_usable_hash_is(self):
        for field, expected in [(b'!', False), (b'*', False), (b'!$6$fixture', False), (b'$6$fixture', True)]:
            fresh = audit.Audit(Path(self.temp.name))
            value = b'culvert:' + field + b':0:0:99999:7:::\n'
            fresh.scan_file(io.BytesIO(value), len(value), 'partition-1:/etc/shadow')
            self.assertEqual(any(f['category'] == 'usable_password_hash_in_pristine_shadow' for f in fresh.findings), expected)

    def test_paths_escape_control_characters_and_opaque_long_names(self):
        value = audit.safe_path('root/bad\nname/' + 'x' * 100)
        self.assertNotIn('\n', value)
        self.assertNotIn('x' * 100, value)
        self.assertIn('name-sha256', value)

    def test_duplicate_or_external_vmdk_parent_is_refused(self):
        for parent in (b'parentCID=12345678\n', b'parentCID=ffffffff\nparentCID=12345678\n'):
            header = bytearray(512)
            header[:4] = b'KDMV'
            struct.pack_into('<QQ', header, 28, 1, 1)
            descriptor = parent + b'createType="streamOptimized"\n'
            with self.assertRaises(audit.Refused):
                audit.validate_vmdk(io.BytesIO(header + descriptor.ljust(512, b'\x00')))

    def test_attestations_are_not_counted_as_filesystem_layers(self):
        value = {'layers': [{'mediaType': 'application/vnd.in-toto+json', 'digest': 'sha256:' + 'a' * 64}]}
        self.audit.container_metadata(json.dumps(value).encode(), 'image')
        self.assertEqual(self.audit.expected_layers, set())
        self.assertEqual(self.audit.counts['container_attestation_descriptors'], 1)

    def test_unquoted_setup_secret_indicator_never_reveals_value(self):
        value = b'CULVERT_SETUP_TOKEN=SyntheticCanaryValue2345\n'
        self.audit.scan_file(io.BytesIO(value), len(value), 'fixture/.env')
        self.assertTrue(any(f['category'] == 'literal_credential_assignment_indicator' for f in self.audit.findings))
        self.assertNotIn('SyntheticCanary', json.dumps(self.audit.findings))


if __name__ == '__main__':
    unittest.main()
