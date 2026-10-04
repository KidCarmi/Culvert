#!/usr/bin/env python3
"""Freeze committed qualification sources before any owned-VM operation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[4]


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True,
                          capture_output=True, text=True, timeout=30).stdout.strip()


def verify(path, root=ROOT):
    manifest = json.loads(Path(path).read_text(encoding='utf-8'))
    if manifest.get('schema') != 1 or not re.fullmatch(r'[0-9a-f]{40}', manifest.get('revision', '')):
        raise ValueError('invalid controller freeze')
    if git(root, 'rev-parse', 'HEAD') != manifest['revision']:
        raise ValueError('controller revision changed')
    if git(root, 'status', '--porcelain', '--untracked-files=no'):
        raise ValueError('tracked controller checkout changed')
    files = manifest.get('files', {})
    if not files or 'test/e2e/appliance/esxi/controller-freeze.py' not in files:
        raise ValueError('incomplete controller freeze')
    for name, expected in files.items():
        target = root / name
        if not target.resolve().is_relative_to(root.resolve()) or target.is_symlink():
            raise ValueError('controller path outside checkout')
        if hashlib.sha256(target.read_bytes()).hexdigest() != expected:
            raise ValueError('controller source bytes changed')
    for item in manifest.get('external_inputs', []):
        if hashlib.sha256(Path(item['path']).read_bytes()).hexdigest() != item['sha256']:
            raise ValueError('external controller input changed')
    return manifest


def create(path, external=(), root=ROOT):
    if git(root, 'status', '--porcelain'):
        raise ValueError('commit all controller changes before freezing')
    names = git(root, 'ls-files', 'test/e2e/appliance', 'test/e2e/release-proof-fixture').splitlines()
    manifest = {'schema': 1, 'revision': git(root, 'rev-parse', 'HEAD'),
                'files': {name: hashlib.sha256((root/name).read_bytes()).hexdigest() for name in names},
                'external_inputs': [{'path': str(Path(p).resolve()),
                                     'sha256': hashlib.sha256(Path(p).read_bytes()).hexdigest()} for p in external]}
    with Path(path).open('x', encoding='utf-8') as output:
        json.dump(manifest, output, indent=2)
        output.write('\n')
    verify(path, root)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['create', 'verify'])
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--external', action='append', default=[])
    args = parser.parse_args()
    result = create(args.manifest, args.external) if args.action == 'create' else verify(args.manifest)
    print('Controller frozen at ' + result['revision'])


if __name__ == '__main__':
    main()
