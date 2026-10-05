#!/usr/bin/env python3
"""Capture private authenticated guest evidence and bind post-hoc boot proof."""
import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('production_evidence_console', HERE / 'console-priv.py')
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def unpack_sampler(payload):
    if payload.get('result') not in ('ok', 'active_snapshot') or payload.get('encoding') != 'gzip+base64':
        raise ValueError('sampler missing or truncated')
    encoded = base64.b64decode(payload['data'], validate=True)
    if len(encoded) > 8 * 1024 * 1024:
        raise ValueError('compressed sampler bound')
    with gzip.GzipFile(fileobj=io.BytesIO(encoded)) as stream:
        raw = stream.read(8 * 1024 * 1024 + 1)
    if (len(raw) != payload['uncompressed_bytes'] or len(raw) > 8 * 1024 * 1024
            or hashlib.sha256(raw).hexdigest() != payload['sha256']):
        raise ValueError('sampler content identity mismatch')
    return [json.loads(line) for line in raw.splitlines()]


def capture(lab, args, directory):
    raw, errors, receipt = [directory / (args.mode + x) for x in ('.json', '.stderr', '-receipt.json')]
    if any(p.exists() for p in (raw, errors, receipt)):
        raise ValueError('observation already exists; choose separate cycle/label')
    source = (HERE / 'production-recovery-collect.py').read_bytes()
    payload = b"set +x\nset -euo pipefail\npython3 - --mode " + args.mode.encode() + b" <<'CULVERT_PRODUCTION_COLLECT'\n" + source + b'\nCULVERT_PRODUCTION_COLLECT\n'
    start_mono, start_real = time.monotonic_ns(), time.time_ns()
    with raw.open('xb') as output, errors.open('xb') as err:
        result = subprocess.run([sys.executable, str(HERE / 'console-priv.py'), '--scope', str(args.scope),
            '--bind', args.bind, '--timeout', '240'], input=payload, stdout=output, stderr=err, timeout=420)
    end_mono, end_real = time.monotonic_ns(), time.time_ns()
    record = {'schema': 1, 'cycle_id': args.cycle, 'mode': args.mode, 'exit_code': result.returncode,
              'controller_started_monotonic_ns': start_mono, 'controller_finished_monotonic_ns': end_mono,
              'controller_started_realtime_ns': start_real, 'controller_finished_realtime_ns': end_real,
              'guest_source_sha256': hashlib.sha256(source).hexdigest(), 'raw_sha256': sha(raw),
              'controller_revision': json.loads(Path(lab.c['controller_manifest']).read_text())['revision']}
    console.b.module.atomic_json(receipt, record)
    if result.returncode != 0:
        raise ValueError('authenticated observation failed')
    observation = json.loads(raw.read_bytes())
    if observation['identity']['source_revision'] != lab.c['source_sha'] or observation['identity']['source_dirty'] is not False:
        raise ValueError('guest source changed')
    print('Authenticated ' + args.mode + ' observation retained privately.')


def proof(lab, args, directory):
    reports = {}
    receipts = {}
    for mode in ('full', 'correlation'):
        raw = directory / (mode + '.json')
        record = json.loads((directory / (mode + '-receipt.json')).read_bytes())
        if record['exit_code'] != 0 or record['raw_sha256'] != sha(raw) or record['cycle_id'] != args.cycle:
            raise ValueError('transport receipt mismatch')
        receipts[mode] = record
        reports[mode] = json.loads(raw.read_bytes())
    full, correlation = reports['full'], reports['correlation']
    identity = correlation['identity']
    if full['identity']['boot_id'] != identity['boot_id']:
        raise ValueError('collection spans different boots')
    if any(r['identity']['source_revision'] != lab.c['source_sha'] or r['identity']['source_dirty'] is not False for r in reports.values()):
        raise ValueError('source mismatch')
    commands = {row['name']: row for row in full['full']['commands']}
    state = commands['culvert_state']
    if state['result'] != 'ok' or json.loads(state['output'])['image_id'] != lab.c['image_id']:
        raise ValueError('image identity mismatch')
    clamav_state = commands['culvert-clamav_state']
    config = full['full']['clamav_probe_configuration']
    if clamav_state['result'] != 'ok' or config['result'] != 'ok':
        raise ValueError('ClamAV endpoint identity unavailable')
    clamd = json.loads(clamav_state['output'])
    endpoint = config['configuration']
    networks = list(clamd['networks'].values())
    if (endpoint['container_id'] != clamd['id'] or endpoint['port'] != 3310
            or len(networks) != 1 or endpoint['address'] != networks[0]['IPAddress']):
        raise ValueError('ClamAV endpoint changed since sampler installation')
    rows = unpack_sampler(full['full']['sampler'])
    installation = full['full']['sampler_installation_receipt']
    if installation['result'] != 'ok' or not rows or rows[0].get('kind') != 'header':
        raise ValueError('sampler installation binding absent')
    installed = installation['receipt']
    sampler_sha = sha(HERE / 'production-boot-sampler.py')
    if (installed['sampler_sha256'] != sampler_sha or rows[0].get('sampler_sha256') != sampler_sha
            or installed['generator_sha256'] != sha(HERE / 'production-boot-sampler-control.py')
            or installed['source_sha'] != lab.c['source_sha']
            or installed['owner_uuid'] != lab.state['uuid'].lower()
            or installed['clamav_config_sha256'] != config['sha256']
            or installed['clamav_endpoint'] != endpoint):
        raise ValueError('sampler source or endpoint differs from owned frozen installation')
    samples = [r for r in rows if r.get('kind') == 'sample']
    if len(samples) < 2 or any(r['boot_id'] != identity['boot_id'] for r in samples):
        raise ValueError('sampler boot mismatch')
    clock = identity['clock']
    if clock['bracket_ns'] > 1_000_000:
        raise ValueError('guest clock bracket too wide')
    c = {k: v for k, v in receipts['correlation'].items() if k.startswith('controller_') and k.endswith('_ns')}
    c.update(guest_monotonic_ns=clock['monotonic_before_ns'], guest_realtime_ns=clock['realtime_ns'])
    result = {'schema': 1, 'cycle_id': args.cycle, 'boot_id': identity['boot_id'],
              'source_sha': lab.c['source_sha'], 'image_id': lab.c['image_id'], 'correlation': c,
              'clamav_endpoint_binding_verified': True,
              'samples': [{k: r[k] for k in ('boot_id', 'monotonic_ns', 'realtime_ns', 'clamav_ping')} for r in samples],
              'authenticated_transport_receipts': {m: sha(directory / (m + '-receipt.json')) for m in receipts}}
    output = directory / 'authenticated-boot-proof.json'
    with output.open('x') as f:
        json.dump(result, f, indent=2)
    print('Boot proof bound to private authenticated transport receipts; timing verdict remains separate.')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('capture', 'proof'))
    p.add_argument('--scope', type=Path, required=True)
    p.add_argument('--bind')
    p.add_argument('--cycle', required=True)
    p.add_argument('--mode', choices=('full', 'correlation'), default='correlation')
    args = p.parse_args()
    try:
        if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', args.cycle):
            raise ValueError('invalid cycle')
        lab = console.b.module.Lab(args.scope)
        console.b.private_directory(lab)
        lab.vm(timeout=30)
        directory = lab.sec / 'production-recovery' / args.cycle
        directory.mkdir(parents=True, exist_ok=True)
        if args.action == 'capture':
            if not args.bind:
                raise ValueError('bind required')
            capture(lab, args, directory)
        else:
            proof(lab, args, directory)
        return 0
    except Exception:
        print('Production evidence blocked; retain private observation, do not infer PASS.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
