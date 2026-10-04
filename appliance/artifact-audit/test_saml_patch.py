import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

import raw_keys
import verify_saml_patch as patch

MODULE = Path(__file__).resolve().parents[2] / 'third_party/crewjam-saml'


class SamlPatchTests(unittest.TestCase):
    def test_exact_upstream_tree_and_only_build_tag_delta_without_module_cache(self):
        # No GOPATH/cache lookup or network request is part of verification.
        report = patch.verify_tree(MODULE)
        self.assertEqual(report['upstream_files_verified'], 235)
        data = (MODULE / 'xmlenc/fuzz.go').read_bytes()
        self.assertEqual(hashlib.sha256(data[len(patch.PREAMBLE):]).hexdigest(), patch.FIXTURE_SHA256)

    def test_unrecorded_source_change_and_manifest_rewrite_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / 'saml'
            shutil.copytree(MODULE, copy)
            path = copy / 'xmlenc/decrypt.go'
            path.write_bytes(path.read_bytes() + b'\n// unexpected change\n')
            with self.assertRaises(patch.InvalidPatch):
                patch.verify_tree(copy)
            manifest = copy / 'CULVERT-PROVENANCE.json'
            data = json.loads(manifest.read_text())
            data['upstream_files_sha256']['xmlenc/decrypt.go'] = hashlib.sha256(path.read_bytes()).hexdigest()
            manifest.write_text(json.dumps(data))
            with self.assertRaises(patch.InvalidPatch):
                patch.verify_tree(copy)

    def test_known_public_fixture_remains_detectable_and_is_rejected(self):
        data = (MODULE / 'xmlenc/fuzz.go').read_bytes()
        keys = raw_keys.parseable_keys(data)
        self.assertEqual([key['public_key_sha256'] for key in keys], [patch.FIXTURE_PUBLIC_SHA256])
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / 'synthetic-pe-prefix'
            binary.write_bytes(b'MZ' + b'\0' * 100 + data)
            with self.assertRaises(patch.InvalidPatch):
                patch.verify_binary(binary)

    def test_missing_constraint_is_rejected_without_changing_upstream_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / 'saml'
            shutil.copytree(MODULE, copy)
            fixture = copy / 'xmlenc/fuzz.go'
            fixture.write_bytes(fixture.read_bytes()[len(patch.PREAMBLE):])
            with self.assertRaises(patch.InvalidPatch):
                patch.verify_tree(copy)


if __name__ == '__main__':
    unittest.main()
