#!/usr/bin/env python3
"""Create TEST-ONLY signed requests using the candidate's unmodified Go fixture.

Requires a direct child of an existing private run/secrets directory, containing
only optional parent-prepared ca.crt and target-digest files before generation.
No registry or VM calls are made. Install ca.crt separately after generation;
neither this trust configuration nor the ephemeral signer belongs in the OVA.
"""
import argparse
import base64
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
from types import SimpleNamespace


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
SOURCES = ROOT / 'test/e2e/release-proof-fixture'
SOURCE_REVISION = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
SOURCE_HASHES = {
    'main.go': '33034e5994cc9ae7a2b9e9f98a418ffd48165b2de39cfa26fbc620c25d80330e',
    'request.py': 'fbf7e9df27c190b47155ccbff93b3581cd0342f33cf8c8dbce943a57be49c771',
}
REF = re.compile(r'^(ghcr\.io/[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)+)@sha256:[a-f0-9]{64}$')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_refs(baseline, target):
    left, right = REF.fullmatch(baseline), REF.fullmatch(target)
    require(left and right and left.group(1) == right.group(1), 'distinct pinned refs in one ghcr.io repository required')
    require(baseline != target and len(baseline) <= 330 and len(target) <= 330,
            'distinct bounded baseline and target refs required')


def private_parent(directory):
    require(not directory.is_symlink(), 'fixture directory link refused')
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,63}', directory.name), 'fixture directory name refused')
    parent = directory.parent.resolve(strict=True)
    require(parent.name == 'secrets' and directory.absolute().parent == parent,
            'fixture must be a direct child of the existing private secrets directory')
    spec = importlib.util.spec_from_file_location('fixture_bootstrap', HERE / 'bootstrap-checks.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.private_directory(SimpleNamespace(sec=parent, run=parent.parent))
    if directory.exists():
        require(directory.is_dir(), 'fixture output is not a directory')
        for entry in directory.iterdir():
            require(entry.name in ('ca.crt', 'target-digest') and entry.is_file() and not entry.is_symlink(),
                    'fixture directory contains existing evidence or unexpected files')


def verify_sources():
    provenance = {'source_revision': SOURCE_REVISION, 'files': {}}
    for name, expected in SOURCE_HASHES.items():
        require(hashlib.sha256((SOURCES / name).read_bytes()).hexdigest() == expected,
                'fixture source bytes mismatch')
        provenance['files'][name] = {'sha256': expected}
    return provenance


def run_checked(command, *, environment=None, payload=None):
    result = subprocess.run(command, input=payload, capture_output=True, timeout=180,
                            env=environment, cwd=SOURCES)
    require(result.returncode == 0, 'fixture subprocess failed; no fixture retry permitted')
    return result.stdout


def write_new(path, data):
    with path.open('xb') as output:
        output.write(data)


def signed_request(directory, request, prior=None):
    command = [sys.executable, str(SOURCES / 'request.py'), '--proofs', str(directory / 'proofs.json')]
    if prior:
        command += ['--prior', prior]
    raw = run_checked(command, payload=json.dumps(request).encode())
    require(len(raw) <= 65536, 'generated request exceeds bound')
    parsed = json.loads(raw)
    require(parsed['image_ref'] == request['image_ref'] and 'release_proof' in parsed,
            'generated request identity mismatch')
    require(('prior_release_proof' in parsed) == bool(prior), 'generated prior proof mismatch')
    return raw


def generate(directory, baseline, target, registry_address):
    directory = directory.absolute()
    validate_refs(baseline, target)
    address = ipaddress.ip_address(registry_address)
    require(address.version == 4 and str(address) == registry_address and not address.is_unspecified
            and not address.is_multicast, 'explicit IPv4 registry address required')
    private_parent(directory)
    provenance = verify_sources()
    if (directory / 'target-digest').exists():
        observed = (directory / 'target-digest').read_text().strip().removeprefix('sha256:')
        require(observed == target.rsplit(':', 1)[1], 'prepared registry target digest mismatch')
    directory.mkdir(mode=0o700, exist_ok=True)
    evidence_directory = directory / 'signed-evidence'
    environment = dict(os.environ, GOWORK='off', GOENV='off', GOFLAGS='', GO111MODULE='off',
                       GOTOOLCHAIN='go1.26.8', GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0')
    run_checked(['go', 'run', str(SOURCES / 'main.go'), '-output', str(evidence_directory),
                 '-ref', 'baseline=' + baseline, '-ref', 'target=' + target], environment=environment)
    # Go creates a fresh directory and never serializes the ephemeral private key.
    for name in ('keyring.json', 'proofs.json', 'proof-baseline.json', 'proof-target.json'):
        write_new(directory / name, (evidence_directory / name).read_bytes())
    run_id = secrets.token_hex(12)
    unsigned = {'image_ref': target, 'pre_backup': False, 'rollback_on_failure': True,
                'idempotency_key': 'esxi-unsigned-' + run_id}
    apply = dict(unsigned, idempotency_key='esxi-apply-' + run_id)
    rollback = {'mode': 'image', 'image_ref': baseline, 'idempotency_key': 'esxi-rollback-' + run_id}
    write_new(directory / 'apply-unsigned.json', (json.dumps(unsigned) + '\n').encode())
    write_new(directory / 'apply-signed.json', signed_request(directory, apply, baseline))
    write_new(directory / 'rollback-signed.json', signed_request(directory, rollback))
    write_new(directory / 'source-provenance.json', (json.dumps(provenance, indent=2) + '\n').encode())
    proof = json.loads((directory / 'proof-baseline.json').read_text())
    index = json.loads(base64.b64decode(proof['index'], validate=True))
    report = ('TEST-ONLY ESXi signed lifecycle fixture; never part of the deliverable OVA.\n'
              f'Source revision: {SOURCE_REVISION}\n'
              'Source: test/e2e/release-proof-fixture/main.go and request.py (exact Git bytes).\n'
              'Compiler: go1.26.8; signing key generated freshly in memory and never saved.\n'
              f'Baseline: {baseline}\nTarget: {target}\nRegistry address: {registry_address}\n'
              'Target construction: docker create baseline (never started), docker commit\n'
              '--change LABEL org.culvert.lab-target=1, remove temporary container, push.\n'
              'Baseline registry manifest bytes were checked against the retained OVA index.\n'
              f'Proof generated: {index["generated_at"]}\nProof expires: {index["expires_at"]}\n'
              'Trust changes, applied after boot only: registry CA, ghcr.io hosts mapping,\n'
              'agent release_trust_keys pointing to this fixture PUBLIC keyring.\n'
              'ca.crt is supplied separately by registry preparation; no private key belongs here.\n')
    write_new(directory / 'fixture.txt', report.encode())
    # Publish refs last: incomplete requests must not look ready to the shared lab.
    write_new(directory / 'refs.env',
              f'BASELINE_REF={baseline}\nTARGET_REF={target}\nREGISTRY_ADDR={registry_address}\n'.encode())
    return directory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--baseline', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--registry-address', required=True)
    args = parser.parse_args()
    try:
        generate(args.directory, args.baseline, args.target, args.registry_address)
    except Exception:
        print('Signed fixture preparation refused or incomplete; preserve output and inspect locally; no overwrite.', file=sys.stderr)
        return 90
    print('TEST-ONLY signed fixture generated from ' + SOURCE_REVISION + '; registry CA must be supplied separately.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
