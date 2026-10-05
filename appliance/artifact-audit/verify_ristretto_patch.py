#!/usr/bin/env python3
"""Verify the local ristretto fork is upstream v2.2.0 plus exactly the F-DISK-1 patch.

Reads files only: no dependency cache modification and no network unless an
upstream zip is passed for a byte-for-byte inventory comparison.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile

MODULE = 'github.com/dgraph-io/ristretto/v2'
VERSION = 'v2.2.0'
COMMIT = '47ceb3b6852000bc497437af816dd68d4c5fa114'
MODULE_SUM = 'h1:bkY3XzJcXoMuELV8F+vS8kzNgicwQFAaGINAEJdWGOM='
MODULE_GO_MOD_SUM = 'h1:RZrm63UmcBAaYWC1DotLYBmTvgkrs0+XhBd7Npn7/zI='
ZIP_SHA256 = 'a556ffc80401dfaad3ae2420e6bd9e2ecc36dc28cd50717bf74c7caa4ada1af0'
UPSTREAM_TREE_SHA256 = '914986597869f0326a1eb6ff736efaf5880a5b69561071994a914b68a514ba21'
UPSTREAM_FILES = 103
MODIFIED = {'z/file.go', 'z/file_linux.go'}
ADDED = {'z/prealloc_linux.go', 'z/prealloc_other.go'}
LOCAL_FILES = {'CULVERT-PROVENANCE.json', 'CULVERT-PATCH.md', '.gitattributes'}
REQUIRED_MARKERS = {
    'z/file.go': [b'CULVERT PATCH (F-DISK-1', b'preallocate(fd, 0, fileSize)', b'os.Remove(filename)'],
    'z/file_linux.go': [b'CULVERT PATCH (F-DISK-1', b'preallocate(m.Fd, oldSz, maxSz-oldSz)'],
    'z/prealloc_linux.go': [b'unix.Fallocate(', b'unix.EOPNOTSUPP'],
}


class InvalidPatch(Exception):
    pass


def check(value, reason):
    if not value:
        raise InvalidPatch(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_tree(module, upstream_zip=None):
    prov = json.loads((module / 'CULVERT-PROVENANCE.json').read_text(encoding='utf-8'))
    for key, value in {'module': MODULE, 'version': VERSION, 'upstream_commit': COMMIT,
                       'module_sum': MODULE_SUM, 'module_go_mod_sum': MODULE_GO_MOD_SUM,
                       'module_zip_sha256': ZIP_SHA256}.items():
        check(prov.get(key) == value, f'upstream provenance mismatch: {key}')
    upstream = prov['upstream_files_sha256']
    check(len(upstream) == UPSTREAM_FILES, 'upstream file inventory mismatch')
    check(sha(json.dumps(upstream, sort_keys=True, separators=(',', ':')).encode()) == UPSTREAM_TREE_SHA256,
          'pinned upstream inventory changed')
    patch = prov['patch']
    check(set(patch['modified']) == MODIFIED and set(patch['added']) == ADDED, 'patch scope changed')
    actual = set()
    for path in module.rglob('*'):
        check(not path.is_symlink(), 'local dependency symlink refused')
        if path.is_file():
            actual.add(path.relative_to(module).as_posix())
    check(actual - LOCAL_FILES == set(upstream) | ADDED, 'local dependency inventory changed')
    for name, digest in upstream.items():
        safe = PurePosixPath(name)
        check(not safe.is_absolute() and '..' not in safe.parts, 'upstream path refused')
        data = (module / name).read_bytes()
        if name in MODIFIED:
            rec = patch['modified'][name]
            check(rec['upstream_sha256'] == digest, f'{name}: recorded upstream hash changed')
            check(sha(data) == rec['patched_sha256'], f'{name}: patched file differs from the recorded patch')
        else:
            check(sha(data) == digest, f'{name}: unrecorded upstream source change')
    for name, digest in patch['added'].items():
        check(sha((module / name).read_bytes()) == digest, f'{name}: added file differs from the recorded patch')
    for name, markers in REQUIRED_MARKERS.items():
        data = (module / name).read_bytes()
        for m in markers:
            check(m in data, f'{name}: required patch element {m.decode()!r} absent')
    if upstream_zip:
        with upstream_zip.open('rb') as source:
            check(hashlib.file_digest(source, 'sha256').hexdigest() == ZIP_SHA256, 'upstream zip hash mismatch')
        prefix = MODULE + '@' + VERSION + '/'
        with zipfile.ZipFile(upstream_zip) as archive:
            original = {e.filename[len(prefix):]: sha(archive.read(e))
                        for e in archive.infolist() if not e.is_dir() and e.filename.startswith(prefix)}
        check(original == upstream, 'upstream zip inventory mismatch')
    return {'upstream_files_verified': len(upstream), 'modified': sorted(MODIFIED), 'added': sorted(ADDED)}


def verify_replace(gomod):
    text = gomod.read_text(encoding='utf-8')
    check(f'replace {MODULE} => ./third_party/ristretto' in text, 'root go.mod no longer builds against the fork')
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[2]
    ap.add_argument('--module', type=Path, default=root / 'third_party' / 'ristretto')
    ap.add_argument('--gomod', type=Path, default=root / 'go.mod')
    ap.add_argument('--upstream-zip', type=Path)
    a = ap.parse_args(argv)
    try:
        result = verify_tree(a.module, a.upstream_zip)
        verify_replace(a.gomod)
    except (InvalidPatch, OSError, KeyError, ValueError) as exc:
        print(f'ristretto fork verification FAILED: {exc}', file=sys.stderr)
        return 1
    print(json.dumps({'ok': True, **result}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
