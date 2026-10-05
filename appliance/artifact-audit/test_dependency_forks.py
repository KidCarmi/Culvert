"""Mutation tests for verify_dependency_forks.py: each tamper must be refused, for every fork."""
import shutil
import tempfile
import unittest
from pathlib import Path

import verify_dependency_forks as v

ROOT = Path(__file__).resolve().parents[2]

# One upstream file, one patched file + a patch element, and one added file
# (if any) per fork, so every mutation class is exercised on both trees.
CASES = {
    'ristretto': {'upstream': 'cache.go', 'patched': 'z/file_linux.go',
                  'element': b'preallocate(m.Fd, oldSz, maxSz-oldSz)', 'added': 'z/prealloc_linux.go'},
    'badger': {'upstream': 'txn.go', 'patched': 'db.go', 'element': b'db.mt = next', 'added': None},
}


class DependencyForkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def fork(self, name):
        mod = self.tmp / name
        shutil.copytree(ROOT / 'third_party' / name, mod)
        return mod

    def refused(self, name, mod):
        with self.assertRaises(v.InvalidPatch):
            v.verify_tree(name, mod)

    def test_every_fork_is_covered(self):
        self.assertEqual(set(CASES), set(v.FORKS))

    def test_shipped_trees_verify(self):
        for name in v.FORKS:
            with self.subTest(fork=name):
                self.assertEqual(v.verify_tree(name, ROOT / 'third_party' / name)['upstream_files_verified'],
                                 v.FORKS[name]['files'])
                self.assertTrue(v.verify_replace(name, ROOT / 'go.mod'))

    def test_upstream_file_change_refused(self):
        for name, c in CASES.items():
            with self.subTest(fork=name):
                mod = self.fork(name)
                p = mod / c['upstream']
                p.write_bytes(p.read_bytes() + b'\n')
                self.refused(name, mod)

    def test_patch_reverted_refused(self):
        for name, c in CASES.items():
            with self.subTest(fork=name):
                mod = self.fork(name)
                p = mod / c['patched']
                p.write_bytes(p.read_bytes().replace(c['element'], b'error(nil)'))
                self.refused(name, mod)

    def test_extra_file_refused(self):
        for name in CASES:
            with self.subTest(fork=name):
                mod = self.fork(name)
                (mod / 'extra.go').write_text('package x\n')
                self.refused(name, mod)

    def test_missing_added_file_refused(self):
        mod = self.fork('ristretto')
        (mod / CASES['ristretto']['added']).unlink()
        self.refused('ristretto', mod)

    def test_missing_upstream_file_refused(self):
        for name, c in CASES.items():
            with self.subTest(fork=name):
                mod = self.fork(name)
                (mod / c['upstream']).unlink()
                self.refused(name, mod)

    def test_replace_removed_refused(self):
        for name in CASES:
            with self.subTest(fork=name):
                gomod = self.tmp / 'go.mod'
                gomod.write_text((ROOT / 'go.mod').read_text().replace(f'=> ./third_party/{name}\n', '=> ./elsewhere\n'))
                with self.assertRaises(v.InvalidPatch):
                    v.verify_replace(name, gomod)


if __name__ == '__main__':
    unittest.main()
