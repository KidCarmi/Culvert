"""Mutation tests for verify_ristretto_patch.py: each tamper must be refused."""
import shutil
import tempfile
import unittest
from pathlib import Path

import verify_ristretto_patch as v

ROOT = Path(__file__).resolve().parents[2]


class RistrettoPatchTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.mod = self.tmp / 'ristretto'
        shutil.copytree(ROOT / 'third_party' / 'ristretto', self.mod)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_shipped_tree_verifies(self):
        self.assertEqual(v.verify_tree(self.mod)['upstream_files_verified'], v.UPSTREAM_FILES)
        self.assertTrue(v.verify_replace(ROOT / 'go.mod'))

    def test_upstream_file_change_refused(self):
        p = self.mod / 'cache.go'
        p.write_bytes(p.read_bytes() + b'\n')
        with self.assertRaises(v.InvalidPatch):
            v.verify_tree(self.mod)

    def test_patch_reverted_refused(self):
        p = self.mod / 'z' / 'file_linux.go'
        p.write_bytes(p.read_bytes().replace(b'preallocate(m.Fd, oldSz, maxSz-oldSz)', b'error(nil)'))
        with self.assertRaises(v.InvalidPatch):
            v.verify_tree(self.mod)

    def test_extra_file_refused(self):
        (self.mod / 'z' / 'extra.go').write_text('package z\n')
        with self.assertRaises(v.InvalidPatch):
            v.verify_tree(self.mod)

    def test_missing_added_file_refused(self):
        (self.mod / 'z' / 'prealloc_linux.go').unlink()
        with self.assertRaises(v.InvalidPatch):
            v.verify_tree(self.mod)

    def test_replace_removed_refused(self):
        gomod = self.tmp / 'go.mod'
        gomod.write_text((ROOT / 'go.mod').read_text().replace('=> ./third_party/ristretto', '=> ./elsewhere'))
        with self.assertRaises(v.InvalidPatch):
            v.verify_replace(gomod)


if __name__ == '__main__':
    unittest.main()
