#!/usr/bin/env python3
"""Verify each local dependency fork is its pinned upstream module plus exactly
the recorded F-DISK-1 patch (third_party/<fork>/CULVERT-PATCH.md).

Reads files only: no dependency cache modification and no network unless an
upstream zip is passed for a byte-for-byte inventory comparison.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys
import zipfile

LOCAL_FILES = {'CULVERT-PROVENANCE.json', 'CULVERT-PATCH.md', '.gitattributes'}

FORKS = {
    'ristretto': {
        'module': 'github.com/dgraph-io/ristretto/v2',
        'version': 'v2.2.0',
        'commit': '47ceb3b6852000bc497437af816dd68d4c5fa114',
        'module_sum': 'h1:bkY3XzJcXoMuELV8F+vS8kzNgicwQFAaGINAEJdWGOM=',
        'module_go_mod_sum': 'h1:RZrm63UmcBAaYWC1DotLYBmTvgkrs0+XhBd7Npn7/zI=',
        'zip_sha256': 'a556ffc80401dfaad3ae2420e6bd9e2ecc36dc28cd50717bf74c7caa4ada1af0',
        'tree_sha256': '914986597869f0326a1eb6ff736efaf5880a5b69561071994a914b68a514ba21',
        'files': 103,
        'modified': {'z/file.go', 'z/file_linux.go'},
        'added': {'z/prealloc_linux.go', 'z/prealloc_other.go', 'z/prealloc_linux_test.go'},
        'markers': {
            'z/file.go': [b'CULVERT PATCH (F-DISK-1', b'preallocate(fd, 0, fileSize)', b'os.Remove(filename)'],
            'z/file_linux.go': [b'CULVERT PATCH (F-DISK-1', b'preallocate(m.Fd, oldSz, maxSz-oldSz)'],
            'z/prealloc_linux.go': [b'var fallocate = unix.Fallocate', b'unix.EOPNOTSUPP', b'return zeroFill(f, off, size)'],
        },
    },
    'badger': {
        'module': 'github.com/dgraph-io/badger/v4',
        'version': 'v4.9.6',
        'commit': 'fbd8d2eefad8be8757249767255faf989945b599',
        'module_sum': 'h1:IQqMPVGLNCQr1b4Mu8lHkYm/xyqFRsyKaFEtyLi9CCQ=',
        'module_go_mod_sum': 'h1:Xa9dAupjbwAacupWFCpa6YEn9E1PjBXkfZYr2I/8aWg=',
        'zip_sha256': 'f1b41e7c0114195c44ac816fba9d17dcbaf20a0587c1216e0d7ebe499a647bce',
        'tree_sha256': 'c8b3ad195cfb132f9f43c6ca9124bd8539474af672cb5025d4389ccaf8819485',
        'files': 161,
        'modified': {'db.go', 'value.go', 'memtable.go', 'table/table.go', 'logger.go', 'levels.go'},
        'added': {'table/culvert_fileid_test.go', 'culvert_flushstop_test.go'},
        'markers': {
            'db.go': [b'CULVERT PATCH (F-DISK-1', b'next, err := db.newMemTable()', b'db.mt = next', b'next.DecrRef()',
                      b'case <-lc.HasBeenClosed():', b'db.keepUnflushed(mt)', b'memtable not flushed (kept in its WAL',
                      b'db.flushClosing.Store(true)', b'if db.flushClosing.Load()', b'for _, mt := range pending', b'rest := append([]*memTable(nil), db.imm[i:len(db.imm)-1]...)'],
            'value.go': [b'CULVERT PATCH (F-DISK-1', b'vlog.writableLogOffset.Store(endOffset - n)'],
            'memtable.go': [b'CULVERT PATCH (scanner)', b'strconv.ParseUint(file.Name()[:fsz-len(memFileExt)], 10, 31)'],
            'table/table.go': [b'CULVERT PATCH (scanner)', b'strconv.ParseUint(name, 10, 32)', b'id == math.MaxUint32'],
            'logger.go': [b'CULVERT PATCH (scanner)', b'opt.Logger.Errorf("%s", logLine(format, v...))'],
        },
    },
    'rekor-tiles': {
        'module': 'github.com/sigstore/rekor-tiles/v2',
        'version': 'v2.3.0',
        'commit': 'fa390b1c17f9685f7a164da2c06e82dc295cfdca',
        'module_sum': 'h1:HhMgH61UP0t899V8Fjt7pz1YdgOBptbaQdnCF+79cdc=',
        'module_go_mod_sum': 'h1:DEFiKSyQ4nF75QRVNdOPaIH3cmvMkO2B6xDZjNYngPc=',
        'zip_sha256': '5b8f617e17ceb7684643daf95facbb020cfd302d4178e0a0d9d9a8239e59bd48',
        'tree_sha256': '6e7e5b7a7e300dbafcb7a936b0e964a030d09dc97849c5256c56380e4e544b11',
        'files': 144,
        'modified': set(),
        'added': set(),
        # The gateway handler file (CVE-2026-37236), plus four TEST-ONLY files
        # that embed private test keys (not vendored: no key material here).
        'removed': {'pkg/generated/protobuf/rekor_service.pb.gw.go', 'pkg/client/read/read_test.go',
                    'pkg/note/note_test.go', 'tests/testdata/pki/ed25519-priv-key.pem',
                    'internal/signerverifier/file_test.go'},
        'markers': {},
        # Every module that links rekor-tiles builds against the fork.
        'replaced_in': {'go.mod': './third_party/rekor-tiles',
                        'cmd/culvert-maint/go.mod': '../../third_party/rekor-tiles',
                        'pkg/releaseproof/go.mod': '../../third_party/rekor-tiles'},
    },
}


class InvalidPatch(Exception):
    pass


def check(value, reason):
    if not value:
        raise InvalidPatch(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def verify_tree(name, module, upstream_zip=None):
    cfg = FORKS[name]
    prov = json.loads((module / 'CULVERT-PROVENANCE.json').read_text(encoding='utf-8'))
    for key, value in {'module': cfg['module'], 'version': cfg['version'], 'upstream_commit': cfg['commit'],
                       'module_sum': cfg['module_sum'], 'module_go_mod_sum': cfg['module_go_mod_sum'],
                       'module_zip_sha256': cfg['zip_sha256']}.items():
        check(prov.get(key) == value, f'{name}: upstream provenance mismatch: {key}')
    upstream = prov['upstream_files_sha256']
    check(len(upstream) == cfg['files'], f'{name}: upstream file inventory mismatch')
    check(sha(json.dumps(upstream, sort_keys=True, separators=(',', ':')).encode()) == cfg['tree_sha256'],
          f'{name}: pinned upstream inventory changed')
    patch = prov['patch']
    removed = cfg.get('removed', set())
    check(set(patch['modified']) == cfg['modified'] and set(patch['added']) == cfg['added']
          and set(patch.get('removed', {})) == removed, f'{name}: patch scope changed')
    actual = set()
    for path in module.rglob('*'):
        check(not path.is_symlink(), f'{name}: local dependency symlink refused')
        if path.is_file():
            actual.add(path.relative_to(module).as_posix())
    local = LOCAL_FILES - set(upstream)  # an upstream .gitattributes is upstream content
    check(actual - local == (set(upstream) - removed) | cfg['added'], f'{name}: local dependency inventory changed')
    for rel, digest in upstream.items():
        safe = PurePosixPath(rel)
        check(not safe.is_absolute() and '..' not in safe.parts, f'{name}: upstream path refused')
        if rel in removed:
            check(patch['removed'][rel] == digest, f'{name}/{rel}: recorded upstream hash changed')
            check(not (module / rel).exists(), f'{name}/{rel}: a removed file is present')
            continue
        data = (module / rel).read_bytes()
        if rel in cfg['modified']:
            rec = patch['modified'][rel]
            check(rec['upstream_sha256'] == digest, f'{name}/{rel}: recorded upstream hash changed')
            check(sha(data) == rec['patched_sha256'], f'{name}/{rel}: patched file differs from the recorded patch')
        else:
            check(sha(data) == digest, f'{name}/{rel}: unrecorded upstream source change')
    for rel, digest in patch['added'].items():
        check(sha((module / rel).read_bytes()) == digest, f'{name}/{rel}: added file differs from the recorded patch')
    for rel, markers in cfg['markers'].items():
        data = (module / rel).read_bytes()
        for m in markers:
            check(m in data, f'{name}/{rel}: required patch element {m.decode()!r} absent')
    if upstream_zip:
        with upstream_zip.open('rb') as source:
            check(hashlib.file_digest(source, 'sha256').hexdigest() == cfg['zip_sha256'], f'{name}: upstream zip hash mismatch')
        prefix = cfg['module'] + '@' + cfg['version'] + '/'
        with zipfile.ZipFile(upstream_zip) as archive:
            original = {e.filename[len(prefix):]: sha(archive.read(e))
                        for e in archive.infolist() if not e.is_dir() and e.filename.startswith(prefix)}
        check(original == upstream, f'{name}: upstream zip inventory mismatch')
    return {'upstream_files_verified': len(upstream), 'modified': sorted(cfg['modified']), 'added': sorted(cfg['added'])}


def verify_replace(name, root):
    for rel, target in FORKS[name].get('replaced_in', {'go.mod': f'./third_party/{name}'}).items():
        text = (root / rel).read_text(encoding='utf-8')
        check(f'replace {FORKS[name]["module"]} => {target}\n' in text,
              f'{rel} no longer builds against the {name} fork')
    return True


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parents[2]
    ap.add_argument('--root', type=Path, default=root)
    ap.add_argument('--upstream-zip', action='append', default=[], metavar='FORK=ZIP',
                    help='compare a fork with its upstream module zip, e.g. badger=/path/v4.9.6.zip')
    a = ap.parse_args(argv)
    zips = dict(z.split('=', 1) for z in a.upstream_zip)
    out = {}
    try:
        check(set(zips) <= set(FORKS), 'unknown fork in --upstream-zip')
        for name in sorted(FORKS):
            out[name] = verify_tree(name, a.root / 'third_party' / name, Path(zips[name]) if name in zips else None)
            verify_replace(name, a.root)
    except (InvalidPatch, OSError, KeyError, ValueError) as exc:
        print(f'dependency fork verification FAILED: {exc}', file=sys.stderr)
        return 1
    print(json.dumps({'ok': True, **out}, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
