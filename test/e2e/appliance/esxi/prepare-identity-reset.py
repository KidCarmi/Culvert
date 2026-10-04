#!/usr/bin/env python3
"""Derive P1 reset readiness from complete, privately escrowed recovery evidence.

Controller files only: no guest, hypervisor or network operations. Run after
fresh-recovery export and identity-before; publish once into external escrow.
"""
import argparse
import importlib.util
from pathlib import Path
import re
import sys


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('reset_deletion', HERE / 'delete-exported-source.py')
deletion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deletion)
fresh = deletion.module('reset_fresh_recovery', HERE / 'fresh-recovery.py')
IMAGE = 'sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47'
require = deletion.require


def readiness(escrow, scope, owned, private):
    require(scope['source_sha'] == deletion.SOURCE and scope['ova_sha256'] == deletion.OVA
            and scope['image_id'] == IMAGE and scope['max_vms'] == 1, 'exact one-VM candidate scope required')
    require(owned.get('uuid') and owned.get('deleted') is not True
            and owned.get('endpoint') == scope['endpoint'], 'current owned source required')
    receipt = fresh.verify_export(escrow)  # Verify every exported file before reading its contents.
    source = fresh.read_json(escrow / 'source-owned.json')
    fields = ('uuid', 'path', 'name', 'endpoint', 'owner', 'ref', 'ds_ref')
    require(all(source.get(key) and source[key] == owned.get(key) for key in fields)
            and source.get('deleted') is not True, 'export source ownership or UUID mismatch')
    provenance = fresh.read_json(escrow / 'provenance.json')
    require(provenance == {key: scope[key] for key in ('source_sha', 'image_id', 'ova_sha256', 'endpoint')},
            'complete exact candidate provenance required')
    archive = escrow / 'recovery.tar.gz.enc'
    metadata = fresh.read_json(escrow / 'archive-metadata.json')
    require(metadata.get('schema') == 1 and metadata.get('source_sha') == scope['source_sha']
            and metadata.get('image_id') == scope['image_id']
            and metadata.get('archive_sha256') == receipt['sha256'][archive.name]
            and metadata.get('archive_bytes') == archive.stat().st_size > 8
            and all(isinstance(metadata.get(key), str) and metadata[key]
                    for key in ('source_data_volume', 'source_backup_volume')), 'archive metadata mismatch')
    with archive.open('rb') as stream:
        require(stream.read(8) == b'CVRTBK01', 'encrypted archive header absent')
    secrets = fresh.read_json(escrow / 'recovery-secrets.json')
    require(set(secrets) == {'CULVERT_CA_PASSPHRASE', 'CULVERT_LOG_PASSPHRASE', 'CULVERT_SESSION_SECRET'}
            and secrets['CULVERT_CA_PASSPHRASE']
            and all(isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_+/.=@:-]{0,4096}', value)
                    for value in secrets.values()), 'recoverable private configuration missing')
    require(re.fullmatch(r'[a-f0-9]{64}', fresh.read_private_text(escrow / 'backup-passphrase')),
            'backup passphrase missing or invalid')
    admin = fresh.read_private_text(escrow / 'admin-pass')
    require(admin and not any(c in admin for c in ('\x00', '\r', '\n')), 'admin recovery credential missing')
    observation = fresh.read_json(escrow / 'source-observation.json')
    require(observation.get('schema') == 1 and observation.get('admin_login') == 'pass'
            and observation.get('ca_decryption') == 'pass' and observation.get('agent') == 'pass'
            and re.fullmatch(r'[a-f0-9]{64}', observation.get('ca_sha256', ''))
            and observation.get('traffic') == {'example.com': 200, 'example.org': 403}
            and observation.get('rules') and observation.get('categories'), 'source recovery baseline incomplete')
    p1 = private / 'p1-regressions'
    before = fresh.read_json(p1 / 'identity-before.attempt.json')
    require(before.get('status') == 'pass' and before.get('uuid') == owned['uuid'], 'identity baseline incomplete')
    require(not (p1 / 'identity-reset.attempt.json').exists(), 'identity reset already attempted')
    return {'schema': 1, 'uuid': owned['uuid'], 'source_path': owned['path'], 'endpoint': scope['endpoint'],
            'source_sha': scope['source_sha'], 'image_id': scope['image_id'], 'ova_sha256': scope['ova_sha256'],
            'backup_export_verified': True, 'escrow_export_verified': True,
            'export_receipt_sha256': fresh.file_hash(escrow / 'export-receipt.json'),
            'archive_sha256': receipt['sha256'][archive.name],
            'historical_encrypted_log_recovery': 'blocked: supported archive excludes logs'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--escrow', type=Path, required=True)
    args = parser.parse_args()
    try:
        adapter = fresh.console.b.module
        lab = adapter.Lab(args.scope)
        adapter.validate_scope(lab.c)
        escrow = fresh.private_escrow(args.escrow, lab.run)
        target = escrow / 'identity-reset-readiness.json'
        with adapter.locked(lab.run):
            deletion.atomic_new(target, readiness(escrow, lab.c, lab.state, lab.sec))
        print('PASS: private recovery export verified; identity-reset-readiness.json published in escrow.')
        return 0
    except Exception:
        print('BLOCKED: reset readiness not established; preserve private export and inspect prerequisites.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
