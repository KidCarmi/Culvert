#!/usr/bin/env python3
"""Read-only OCI archive closure check for an explicitly identified manifest."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import tarfile


def sha256(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        h.update(block)
    return h.hexdigest()


def check(path, manifest_sha256):
    if not re.fullmatch(r'[0-9a-f]{64}', manifest_sha256):
        raise ValueError('a full lowercase selected-platform manifest SHA256 is required')
    with path.open('rb') as f:
        archive_sha = sha256(f)
    result = dict(archive_sha256=archive_sha, archive_bytes=path.stat().st_size,
                  manifest_sha256=manifest_sha256, missing=[], invalid=[])
    with tarfile.open(path) as tf:
        members = {}
        for member in tf.getmembers():
            name = member.name.removeprefix('./')
            if name in members:
                raise ValueError('duplicate normalized archive member')
            members[name] = member
        selected = 'blobs/sha256/' + manifest_sha256
        member = members.get(selected)
        if not member or not member.isfile() or member.size > 4 * 1024 * 1024:
            raise ValueError('selected manifest missing, not regular, or oversized')
        raw = tf.extractfile(member).read()
        if hashlib.sha256(raw).hexdigest() != manifest_sha256:
            raise ValueError('selected manifest digest mismatch')
        manifest = json.loads(raw)
        descriptors = [('config', manifest['config'])] + [('layer', d) for d in manifest['layers']]
        for role, descriptor in descriptors:
            digest = descriptor['digest']
            if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
                raise ValueError('unsupported descriptor digest')
            name = 'blobs/sha256/' + digest.split(':')[1]
            blob = members.get(name)
            if blob is None:
                result['missing'].append(dict(role=role, digest=digest))
            elif (not blob.isfile() or blob.size != descriptor['size'] or
                  sha256(tf.extractfile(blob)) != digest.split(':')[1]):
                result['invalid'].append(dict(role=role, digest=digest))
    result['result'] = 'FAIL' if result['missing'] or result['invalid'] else 'PASS'
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive', type=Path)
    p.add_argument('--manifest-sha256', required=True)
    args = p.parse_args()
    result = check(args.archive, args.manifest_sha256)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['result'] == 'PASS' else 1)
