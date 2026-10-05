#!/usr/bin/env python3
"""Additive, read-only proof for an unchanged early-initrd LAB campaign.

Uses the original campaign guards and supported journal output. Failed built-in
verification records remain intact and are explicitly referenced by hash.
"""
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import re
import sys
from types import SimpleNamespace
import uuid

HERE = Path(__file__).resolve().parent
EARLY_HASH = 'c8f65b25136480516160ef81bbaa2e2234cd2eaede7a9637280efa34b0347d6a'
EARLY_NAME = 'test/e2e/appliance/esxi/production-early-readahead.py'
SELF_NAME = 'test/e2e/appliance/esxi/production-early-journal-proof.py'
JOURNAL_COMMAND = ['journalctl', '-b', '-k', '-o', 'short-monotonic', '--no-pager']


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def freeze_guard(manifest, early_path, self_path):
    need(manifest['files'].get(EARLY_NAME) == EARLY_HASH == sha(early_path), 'original campaign helper bytes differ')
    need(manifest['files'].get(SELF_NAME) == sha(self_path), 'additive verifier not frozen')


def private_file(path, root, limit):
    need(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink()
         and not (hasattr(path, 'is_junction') and path.is_junction())
         and path.is_file() and path.stat().st_size <= limit, 'bounded private file required')


def prior_failure(directory, campaign, owner):
    need(directory.name.startswith('operation-') and str(uuid.UUID(directory.name[10:])) == directory.name[10:],
         'canonical failed verification operation required')
    need(not (directory / 'complete.json').exists(), 'prior operation was completed')
    paths = [directory / name for name in ('intent.json', 'payload.sh', 'guest-result.json')]
    for path in paths:
        private_file(path, directory.parent, 1024 * 1024)
    intent = json.loads(paths[0].read_bytes())
    need(intent.get('action') == 'verify' and intent.get('profile') in ('A', 'B')
         and intent.get('campaign') == campaign and intent.get('owner_uuid') == owner
         and intent.get('operation') == directory.name[10:] and intent.get('generator_sha256') == EARLY_HASH,
         'failed verification belongs to another campaign')
    # Require the specific observed command failure, not an arbitrary ambiguous
    # mutation. Contents remain private and are never repeated in public output.
    raw = paths[2].read_bytes()
    need(b'dmesg' in raw and b'mutually exclusive' in raw, 'expected built-in dmesg failure absent')
    return {'operation': intent['operation'], 'profile': intent['profile'],
            'files_sha256': {p.name: sha(p) for p in paths}, 'disposition': 'retained_failed_builtin_verification'}


PROOF_GUEST = r'''
def journal_proof(c):
    globals()['tempfile'] = __import__('tempfile')
    need(os.geteuid() == 0, 'authenticated root required')
    ra = {}; exec(base64.b64decode(c['ra_guest_b64']), ra)
    for directory in (pathlib.Path('/boot'), pathlib.Path('/var/lib')):
        ra['trusted_dir'](directory)
    observed, prior, rc = immutable_guard(c, ra)
    parent = pathlib.Path('/var/lib/culvert-lab-early-read-ahead-campaigns')
    state = campaign_state(parent, c['campaign'])
    ra['trusted_dir'](parent, 0o700); ra['trusted_dir'](state, 0o700)
    record = receipt_guard(c, state)
    need(record['active'] == c['profile'] and record['exported'] is True, 'active exported profile differs')
    expected_value = 1024 if c['profile'] == 'B' else 128
    need(observed['effective'] == expected_value, 'effective readahead differs')
    boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    need(str(uuid.UUID(boot)) == boot and boot != record['before_boot'], 'new canonical boot not proven')
    receipt_sha = file_hash(state / 'receipt.json')
    active = pathlib.Path('/boot/initrd.img-' + c['kernel'])
    expected = {'sha256': c['original_sha'], 'bytes': c['original_bytes']} if c['profile'] == 'original' else record['stages'][c['profile']]
    need(active.stat().st_size == expected['bytes'] and file_hash(active) == expected['sha256'], 'active bytes differ')
    command = ['journalctl', '-b', '-k', '-o', 'short-monotonic', '--no-pager']
    text = bounded(command, timeout=30, limit=4 * 1024**2)
    need(bool(text.strip()) and '-- No entries --' not in text, 'current boot kernel journal empty')
    if c['profile'] == 'original':
        need('CULVERT_LAB_EARLY_RA ' not in text, 'original boot contains fixture marker')
        marker = {'original_initrd_hash_verified': True, 'fixture_marker_absent': True}
    else:
        marker = verify_boot_marker(text, c['campaign'], expected_value, boot)
    # Repeat the existing immutable and receipt guards after journal capture.
    # No directory, operation record, campaign receipt or boot file is written.
    observed_after, _, _ = immutable_guard(c, ra)
    need(receipt_guard(c, state) == record and file_hash(state / 'receipt.json') == receipt_sha,
         'campaign changed during proof')
    need(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot
         and observed_after['boot_id'] == boot and observed_after['effective'] == expected_value,
         'boot or effective value changed during proof')
    result = {'schema': 1, 'result': 'pass', 'action': 'supplemental_journal_proof',
              'campaign': c['campaign'], 'owner_uuid': c['owner_uuid'], 'profile': c['profile'],
              'source_sha': c['source_sha'], 'image_id': c['image_id'], 'kernel': c['kernel'],
              'boot_id': boot, 'campaign_generator_sha256': c['generator_sha256'],
              'verifier_sha256': c['verifier_sha256'], 'receipt_sha256': receipt_sha,
              'active_initrd_sha256': expected['sha256'], 'active_initrd_bytes': expected['bytes'],
              'effective_read_ahead_kb': expected_value, 'preserved_boot_files': record['preserved'],
              'prior_failed_verification': c['prior_failed_verification'], 'marker': marker,
              'journal_command': command, 'journal_sha256': hashlib.sha256(text.encode()).hexdigest(),
              'journal': text, 'journal_truncated': False, 'journal_exit_code': 0}
    print(json.dumps(result, sort_keys=True))
'''


def payload(early, config):
    python = early.GUEST + '\n' + early.COMMON + '\n' + PROOF_GUEST + '\njournal_proof(' + repr(config) + ')\n'
    return ("#!/usr/bin/env bash\nset +x\nset -euo pipefail\numask 077\ntimeout 180s python3 - <<'CULVERT_EARLY_JOURNAL_PROOF'\n"
            + python + 'CULVERT_EARLY_JOURNAL_PROOF\n').encode('ascii')


def run(args):
    need(all(str(uuid.UUID(v)) == v for v in (args.campaign, args.ra_campaign)), 'canonical campaign IDs required')
    need(re.fullmatch(r'[a-f0-9]{64}', args.ra_generator), 'root-rule generator hash required')
    bind = ipaddress.IPv4Address(args.bind)
    need(not bind.is_unspecified and not bind.is_multicast and not bind.is_loopback, 'reachable bind IP required')
    console = load('early_journal_console', 'console-priv.py')
    lab = console.b.module.Lab(args.scope)
    console.b.private_directory(lab); console.b.module.validate_scope(lab.c)
    need(lab.c.get('controller_manifest'), 'frozen controller required')
    frozen = load('early_journal_freeze', 'controller-freeze.py')
    manifest = frozen.verify(Path(lab.c['controller_manifest']))
    freeze_guard(manifest, HERE / 'production-early-readahead.py', Path(__file__))
    early = load('early_journal_campaign', 'production-early-readahead.py')
    ra = load('early_journal_ra', 'production-readahead-control.py')
    need(lab.c['source_sha'] == early.SOURCE and lab.c['image_id'] == early.IMAGE and lab.c['max_vms'] == 1,
         'exact one-VM candidate required')
    private_file(args.facts, lab.sec, 4 * 1024**2)
    root_uuid = early.private_facts(json.loads(args.facts.read_bytes()))
    campaign_dir = lab.sec / 'early-read-ahead' / args.campaign
    need(campaign_dir.is_dir() and not campaign_dir.is_symlink()
         and not (hasattr(campaign_dir, 'is_junction') and campaign_dir.is_junction())
         and campaign_dir.resolve().is_relative_to(lab.sec.resolve()), 'existing private campaign required')
    failure_dir = campaign_dir / ('operation-' + args.failed_verification)
    need(str(uuid.UUID(args.failed_verification)) == args.failed_verification, 'failed verification UUID required')
    failure = prior_failure(failure_dir, args.campaign, lab.state['uuid'])
    with console.b.module.locked(lab.run):
        lab.vm(timeout=30)
        operation = str(uuid.uuid4())
        config = dict(schema=1, action='verify', profile=args.profile, campaign=args.campaign,
                      operation=operation, owner_uuid=lab.state['uuid'], source_sha=early.SOURCE,
                      image_id=early.IMAGE, kernel=early.KERNEL, root_uuid=root_uuid,
                      original_sha=early.ORIGINAL_SHA, original_bytes=early.ORIGINAL_BYTES,
                      generator_sha256=EARLY_HASH, ra_campaign=args.ra_campaign, ra_generator=args.ra_generator,
                      ra_guest_b64=base64.b64encode(ra.GUEST.encode()).decode(),
                      verifier_sha256=sha(Path(__file__)), prior_failed_verification=failure)
        attempt = campaign_dir / ('journal-proof-' + operation)
        attempt.mkdir()
        body = payload(early, config)
        (attempt / 'payload.sh').write_bytes(body)
        (attempt / 'intent.json').write_text(json.dumps({'config_sha256': hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest(),
                                                       'controller_revision': manifest['revision'], 'prior_failure': failure}) + '\n')
        output = io.BytesIO(); writer = io.TextIOWrapper(output, encoding='utf-8', write_through=True)
        with contextlib.redirect_stdout(writer):
            rc = console.execute(lab, SimpleNamespace(bind=args.bind, timeout=180, nowait=False, as_user=False), body)
        raw = output.getvalue()
        (attempt / 'guest-result.json').write_bytes(raw)
        need(rc == 0 and 0 < len(raw) <= 8 * 1024**2, 'authenticated proof transport failed')
        result = json.loads(raw)
        need(result.get('result') == 'pass' and result.get('action') == 'supplemental_journal_proof'
             and result.get('campaign') == args.campaign and result.get('profile') == args.profile
             and result.get('campaign_generator_sha256') == EARLY_HASH
             and result.get('verifier_sha256') == config['verifier_sha256']
             and result.get('prior_failed_verification') == failure, 'proof binding differs')
        need(prior_failure(failure_dir, args.campaign, lab.state['uuid']) == failure, 'prior evidence changed')
        complete = {'result': 'pass', 'controller_revision': manifest['revision'],
                    'payload_sha256': hashlib.sha256(body).hexdigest(), 'guest_result_sha256': hashlib.sha256(raw).hexdigest(),
                    'prior_failed_verification': failure}
        (attempt / 'complete.json').write_text(json.dumps(complete, sort_keys=True) + '\n')
    print(json.dumps({'result': 'pass', 'action': 'supplemental_journal_proof', 'profile': args.profile,
                      'operation': operation, 'proof_sha256': complete['guest_result_sha256'],
                      'builtin_failure_preserved': True, 'qualification': 'service recovery gates remain separate'}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--campaign', required=True)
    parser.add_argument('--ra-campaign', required=True)
    parser.add_argument('--ra-generator', required=True)
    parser.add_argument('--facts', type=Path, required=True)
    parser.add_argument('--profile', choices=('A', 'B', 'original'), required=True)
    parser.add_argument('--failed-verification', required=True, help='retained built-in verify operation UUID')
    try:
        run(parser.parse_args()); return 0
    except Exception:
        print('Supplemental journal proof blocked; retain private evidence and original failure.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
