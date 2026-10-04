#!/usr/bin/env python3
"""Validate the stopped b579 campaign and extract its exact shared reboot tail."""
import argparse
import hashlib
import json
from pathlib import Path

SHARED = 'f6bdb3fdc01c9a4f2132dad8cceb302147a419eef2cb0645d9685c11d3ce705c'
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
OVA = '1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def tail(source):
    require(hashlib.sha256(source).hexdigest() == SHARED, 'unexpected shared lifecycle source')
    text = source.decode('utf-8').replace('\r\n', '\n')
    start = '    # The reboot ends the console session; the next privileged call logs in again.\n'
    end = '# ── signed update + rollback (step 6c), TEST-ONLY trust'
    require(text.count(start) == 1 and text.count(end) == 1, 'ambiguous lifecycle boundaries')
    body = text.split(start, 1)[1].split(end, 1)[0]
    require(body.rstrip().endswith('}'), 'incomplete lifecycle function')
    return ('post_os_tail() {\n  local c rc pass\n  pass="$(cat "$SEC/admin-pass")"\n'
            '  if gate 7 reboot; then\n' + start + body)


def validate(scope, run):
    require(scope['source_sha'] == SOURCE and scope['ova_sha256'] == OVA, 'wrong candidate')
    ev = run / 'evidence'
    rows = [json.loads(x) for x in (ev / 'checks.jsonl').read_text().splitlines()]
    required = {'firstboot-steps', 'console-login', 'image-identity', 'admin-login',
                'agent-backup', 'backup-listed', 'restore-dry-run', 'restore-complete',
                'unsigned-apply-refused', 'signed-apply', 'signed-rollback', 'os-update'}
    require(required <= {r['check'] for r in rows if r['result'] == 'pass'}, 'earlier lifecycle incomplete')
    require(not any(r['result'] == 'fail' for r in rows), 'earlier lifecycle failure requires review')
    require(rows[-1]['check'] == 'os-update' and rows[-1]['result'] == 'pass', 'unexpected stop boundary')
    require(not any(r['step'] == '8' or r['check'] == 'reboot' for r in rows), 'reboot already evaluated')
    for name in ('07-reboot.txt', 'timing-maintenance.jsonl', 'checks-post-os-resume.jsonl'):
        require(not (ev / name).exists(), 'resume/reboot already dispatched')
    for name in ('07-check-after-update.txt', 'esxi-boot-id-before.txt', '09-post-backup-mutation-name.txt'):
        require((ev / name).stat().st_size > 0, 'missing completed phase evidence')
    initial = json.loads((run / 'secrets/p1-regressions/network-before.attempt.json').read_text())
    owner = json.loads((run / 'owned.json').read_text())
    require(initial['status'] == 'blocked' and initial['uuid'] == owner['uuid'], 'wrong original P1 attempt')
    return {'schema': 1, 'source': SOURCE, 'ova_sha256': OVA, 'uuid': owner['uuid'],
            'initial_network_attempt': 'blocked; retained unchanged',
            'resumed_phase': 'confirmatory network test then reboot/persistence only',
            'prior_checks_sha256': hashlib.sha256((ev / 'checks.jsonl').read_bytes()).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope', type=Path, required=True)
    p.add_argument('--shared', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    scope = json.loads(a.scope.read_text())
    run = Path(scope['run_dir'])
    record = validate(scope, run)
    body = tail(a.shared.read_bytes())
    with a.output.open('x', encoding='utf-8', newline='\n') as out:
        out.write(body)
    with (run / 'evidence/post-os-resume-validation.json').open('x', encoding='utf-8') as out:
        json.dump(record, out, indent=2)


if __name__ == '__main__':
    main()
