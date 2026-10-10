#!/usr/bin/env python3
"""Verify the exact local SAML build-tag patch and optional compiled key absence.

No dependency cache modification, artifact execution or private-key output.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

import raw_keys

MODULE = 'github.com/crewjam/saml'
VERSION = 'v0.5.1'
COMMIT = 'e3d0323a999e14876893e394b91573ba5e5cd453'
MODULE_SUM = 'h1:g+mfp0CrLuLRZCK793PgJcZeg5dS/0CDwoeAX2zcwNI='
MODULE_GO_MOD_SUM = 'h1:r0fDkmFe5URDgPrmtH0IYokva6fac3AUdstiPhyEolQ='
ZIP_SHA256 = 'bff7c71b64979df5f6aee5e59e42e89efe6cfcff8a401aeadad9514e19631294'
FIXTURE_SHA256 = 'f566e1e9b8b98d728fceab6c37e14fc9c0d8f046e80623c4e70c87eda905943b'
FIXTURE_PUBLIC_SHA256 = '7ea3450aa488c616e3b6c28a191ab4e7c61a4dafce2d172d4527c9a172a5736f'
UPSTREAM_TREE_SHA256 = '41582dd762962049c5809e6194c649d8fd4c8fad7c6568d425ffba6c0054e06f'
PREAMBLE = b'//go:build gofuzz\n// +build gofuzz\n\n'
LOCAL_FILES = {'CULVERT-PROVENANCE.json', 'CULVERT-PATCH.md', '.gitattributes'}


class InvalidPatch(Exception):
    pass


def check(value, reason):
    if not value:
        raise InvalidPatch(reason)


def verify_tree(module, upstream_zip=None):
    provenance = json.loads((module / 'CULVERT-PROVENANCE.json').read_text(encoding='utf-8'))
    for key, value in {'module': MODULE, 'version': VERSION, 'upstream_commit': COMMIT,
                       'module_sum': MODULE_SUM, 'module_go_mod_sum': MODULE_GO_MOD_SUM,
                       'module_zip_sha256': ZIP_SHA256}.items():
        check(provenance.get(key) == value, 'upstream provenance mismatch')
    expected = provenance['upstream_files_sha256']
    check(len(expected) == 235, 'upstream file inventory mismatch')
    check(hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(',', ':')).encode()).hexdigest() == UPSTREAM_TREE_SHA256,
          'pinned upstream inventory changed')
    actual = set()
    for path in module.rglob('*'):
        check(not path.is_symlink(), 'local dependency symlink refused')
        if path.is_file():
            actual.add(path.relative_to(module).as_posix())
    check(actual - LOCAL_FILES == set(expected), 'local dependency inventory changed')
    patch = provenance['patch']
    check(patch['path'] == 'xmlenc/fuzz.go' and patch['prepend'].encode() == PREAMBLE,
          'patch mechanism changed')
    check(patch['upstream_sha256'] == FIXTURE_SHA256, 'upstream fixture changed')
    for name, digest in expected.items():
        safe = PurePosixPath(name)
        check(not safe.is_absolute() and '..' not in safe.parts and '\\' not in name and ':' not in name,
              'upstream path refused')
        data = (module / name).read_bytes()
        if name == 'xmlenc/fuzz.go':
            check(data.startswith(PREAMBLE), 'required build constraint absent')
            check(hashlib.sha256(data).hexdigest() == patch['patched_sha256'], 'patched file hash mismatch')
            data = data[len(PREAMBLE):]
        check(hashlib.sha256(data).hexdigest() == digest, 'unrecorded upstream source change')
    if upstream_zip:
        with upstream_zip.open('rb') as source:
            check(hashlib.file_digest(source, 'sha256').hexdigest() == ZIP_SHA256, 'upstream zip hash mismatch')
        prefix = MODULE + '@' + VERSION + '/'
        with zipfile.ZipFile(upstream_zip) as archive:
            original = {entry.filename[len(prefix):]: hashlib.sha256(archive.read(entry)).hexdigest()
                        for entry in archive.infolist() if not entry.is_dir() and entry.filename.startswith(prefix)}
        check(original == expected, 'upstream zip inventory mismatch')
    return {'upstream_files_verified': len(expected), 'functional_delta': 'gofuzz_build_constraint_only'}


def verify_binary(binary):
    size = binary.stat().st_size
    check(0 < size <= 1024**3, 'binary size refused')
    with binary.open('rb') as source:
        prefix = source.read(4)
        check(prefix[:2] == b'MZ' or prefix == b'\x7fELF', 'expected compiled PE or ELF executable')
        source.seek(0)
        report = raw_keys.sweep(source, size, seconds=120)
    check(not any(row['public_key_sha256'] == FIXTURE_PUBLIC_SHA256 for row in report['parseable_private_keys']),
          'known upstream SAML fuzz key remains in executable')
    return {'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'known_saml_fuzz_key_present': False,
            'other_parseable_pem_occurrences': len(report['parseable_private_keys'])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--module', type=Path, default=Path(__file__).resolve().parents[2] / 'third_party/crewjam-saml')
    parser.add_argument('--upstream-zip', type=Path)
    parser.add_argument('--binary', type=Path)
    args = parser.parse_args()
    try:
        report = verify_tree(args.module, args.upstream_zip)
        if args.binary:
            report.update(verify_binary(args.binary))
    except Exception:
        print('SAML patch or artifact verification failed; no key material reported.')
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
