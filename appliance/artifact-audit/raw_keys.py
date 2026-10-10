#!/usr/bin/env python3
"""Read-only raw VMDK sweep for complete parseable unencrypted PEM private keys.

Reports offsets, algorithms and PUBLIC-key fingerprints only. No key material.
Does not reconstruct fragmented/deleted files or decode arbitrary encodings.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import time
import warnings

BLOCK = re.compile(rb'-----BEGIN (RSA PRIVATE KEY|EC PRIVATE KEY|DSA PRIVATE KEY|OPENSSH PRIVATE KEY|PRIVATE KEY)-----\r?\n[A-Za-z0-9+/=\r\n]{32,32768}-----END \1-----')


def parseable_keys(data, base=0):
    from cryptography.hazmat.primitives import serialization
    rows = []
    for match in BLOCK.finditer(data):
        try:
            loader = serialization.load_ssh_private_key if match[1] == b'OPENSSH PRIVATE KEY' else serialization.load_pem_private_key
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                key = loader(match[0], password=None)
            public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        except Exception:
            continue
        rows.append({'offset': base + match.start(), 'algorithm': type(key).__name__,
                     'public_key_sha256': hashlib.sha256(public).hexdigest()})
    return rows


def sweep(source, size, seconds=1200):
    if not 0 <= size <= 64 * 1024**3:
        raise ValueError('disk size limit')
    deadline = time.monotonic() + seconds
    position, tail = 0, b''
    found = {}
    while position < size:
        if time.monotonic() > deadline:
            raise ValueError('time limit')
        data = source.read(min(4 * 1024**2, size - position))
        if not data:
            raise ValueError('short disk')
        window = tail + data
        if b'-----BEGIN ' in window:
            for row in parseable_keys(window, position - len(tail)):
                found[row['offset']] = row
        if len(found) > 10000:
            raise ValueError('finding limit')
        tail = window[-65536:]
        position += len(data)
    return {'status': 'raw_sweep_complete', 'bytes_read': position, 'parseable_private_keys': list(found.values())}


def main():
    from dissect.hypervisor.disk.vmdk import VMDK
    from audit import private_workspace, validate_vmdk
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vmdk', required=True, type=Path)
    parser.add_argument('--vmdk-sha256', required=True)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    private_workspace(args.vmdk.parent)
    report = {'status': 'incomplete'}
    try:
        with args.vmdk.open('rb') as source:
            if hashlib.file_digest(source, 'sha256').hexdigest() != args.vmdk_sha256:
                raise ValueError('disk hash mismatch')
            source.seek(0)
            # Only a known hash verified disk from audit.py may reach this tool.
            validate_vmdk(source)
            disk = VMDK(source)
            report = sweep(disk, disk.size)
    except Exception:
        report['failure'] = 'raw_sweep_refused_or_incomplete'
    report['vmdk_sha256'] = args.vmdk_sha256
    report['tool_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with args.report.open('x', encoding='utf-8') as out:
        json.dump(report, out, indent=2)
    print(json.dumps({'status': report['status'], 'parseable_private_keys': len(report.get('parseable_private_keys', []))}))
    return 0 if report['status'] == 'raw_sweep_complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
