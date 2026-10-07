#!/usr/bin/env python3
"""Validate an explicitly reviewed stopped campaign and extract its exact reboot tail."""
import argparse
import base64
import importlib.util
import hashlib
import json
from pathlib import Path

SHARED = 'f6bdb3fdc01c9a4f2132dad8cceb302147a419eef2cb0645d9685c11d3ce705c'
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
OVA = '1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775'
D698 = 'd698a69c5192588d5ed3a85a9f7cd9009fb59b31'
D698_SHARED = {
    '45dae2a8b04de0b46df9cd1c2f2a4ddb8002147944b011f250d49a66a674aa3e',  # exact LF
    '1707bebac0d227a06dc53d345b7baf181d4cac238d20c8a30bac72c70631d105',  # exact CRLF
}



def require(ok, message):
    if not ok:
        raise ValueError(message)


def tail(source, candidate=SOURCE):
    allowed = D698_SHARED if candidate == D698 else {SHARED} if candidate == SOURCE else set()
    require(hashlib.sha256(source).hexdigest() in allowed, 'unexpected shared lifecycle source')
    text = source.decode('utf-8').replace('\r\n', '\n')
    start = '    # The reboot ends the console session; the next privileged call logs in again.\n'
    end = '# ── signed update + rollback (step 6c), TEST-ONLY trust'
    require(text.count(start) == 1 and text.count(end) == 1, 'ambiguous lifecycle boundaries')
    body = text.split(start, 1)[1].split(end, 1)[0]
    require(body.rstrip().endswith('}'), 'incomplete lifecycle function')
    return ('post_os_tail() {\n  local c rc pass\n  pass="$(cat "$SEC/admin-pass")"\n'
            '  if gate 7 reboot; then\n' + start + body)


def d698_failure_binding(run):
    """Admit only the retained authenticated post-rollback route-gap failure.

    The subsequent guest confirmation separately verifies the original baseline,
    source, boot, netplan and real rollback trace before any new fault injection.
    """
    private = run / 'secrets'
    original = private / 'p1-regressions'
    require(not (private / 'p1-regressions-confirmation').exists(), 'confirmation already attempted')
    require(not (original / 'network-before.json').exists(), 'original network exercise already passed')
    records = list(original.glob('console-transport-*.json'))
    require(len(records) == 1, 'ambiguous original transport')
    path = records[0]
    require(not path.is_symlink() and path.stat().st_size <= 1024 * 1024, 'bounded original transport required')
    record = json.loads(path.read_bytes())
    require(record.get('exit') == 1 and 'exception' not in record, 'original probe did not complete with guest failure')
    outputs = {}
    for name in ('stdout', 'stderr'):
        value = record[name]
        require(value.get('truncated') is False, 'truncated original transport')
        outputs[name] = base64.b64decode(value['base64'], validate=True)
        require(len(outputs[name]) == value['bytes'], 'original transport length mismatch')
    output = outputs['stdout']
    require(outputs['stderr'] == b'' and output.startswith(b'Traceback (most recent call last):\n')
            and b'File "p1-guest-checks.py", line 219, in network_before\n' in output
            and output.endswith(b'ValueError: one default IPv4 route required\n'),
            'original failure is not the reviewed post-rollback route gap')
    result = b'1\n' + output
    matches = [p for p in private.glob('transport-*/result') if not p.is_symlink()
               and p.is_file() and p.stat().st_size == len(result) and p.read_bytes() == result]
    require(matches, 'original failure lacks authenticated console result')
    matched = sorted(matches)[0]
    return {'transport_record': str(path.relative_to(private)),
            'transport_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'authenticated_result': str(matched.relative_to(private)),
            'authenticated_result_sha256': hashlib.sha256(result).hexdigest(),
            'initial_attempt_sha256': hashlib.sha256((original / 'network-before.attempt.json').read_bytes()).hexdigest()}


def validate(scope, run, continuation=False):
    source = scope['source_sha']
    if source == D698:
        spec = importlib.util.spec_from_file_location('resume_identities', Path(__file__).with_name('candidate-identities.py'))
        identities = importlib.util.module_from_spec(spec); spec.loader.exec_module(identities)
        identities.scope_profile(scope)
        require(scope.get('max_vms') == 1 and not continuation,
                'd698 supports only the first explicit confirmation, with one VM')
    else:
        require(source == SOURCE and scope['ova_sha256'] == OVA, 'wrong candidate')
    ev = run / 'evidence'
    rows = [json.loads(x) for x in (ev / 'checks.jsonl').read_text().splitlines()]
    required = {'firstboot-steps', 'console-login', 'image-identity', 'admin-login',
                'agent-backup', 'backup-listed', 'restore-dry-run', 'restore-complete',
                'unsigned-apply-refused', 'signed-apply', 'signed-rollback', 'os-update'}
    require(required <= {r['check'] for r in rows if r['result'] == 'pass'}, 'earlier lifecycle incomplete')
    require(not any(r['result'] == 'fail' for r in rows), 'earlier lifecycle failure requires review')
    require(rows[-1]['check'] == 'os-update' and rows[-1]['result'] == 'pass', 'unexpected stop boundary')
    require(not any(r['step'] == '8' or r['check'] == 'reboot' for r in rows), 'reboot already evaluated')
    suffix = '-continuation' if continuation else ''
    for name in ('07-reboot.txt', 'timing-maintenance.jsonl', 'checks-post-os-resume' + suffix + '.jsonl'):
        require(not (ev / name).exists(), 'resume/reboot already dispatched')
    if continuation:
        previous = [json.loads(x) for x in (ev/'checks-post-os-resume.jsonl').read_text().splitlines()]
        require(len(previous) == 1 and previous[0]['check'] == 'post-os-resume'
                and previous[0]['result'] == 'info', 'earlier resume progressed beyond precheck')
        require((ev/'post-os-resume-boot-id.txt').read_bytes() == (ev/'esxi-boot-id-before.txt').read_bytes(),
                'earlier resume identity changed')
        attempt = json.loads((run/'secrets/p1-regressions-confirmation/network-before.attempt.json').read_text())
        require(attempt['status'] == 'blocked' and attempt['campaign'] == 'confirmation', 'wrong precheck boundary')
    for name in ('07-check-after-update.txt', 'esxi-boot-id-before.txt', '09-post-backup-mutation-name.txt'):
        require((ev / name).stat().st_size > 0, 'missing completed phase evidence')
    initial = json.loads((run / 'secrets/p1-regressions/network-before.attempt.json').read_text())
    owner = json.loads((run / 'owned.json').read_text())
    require(initial['status'] == 'blocked' and initial['uuid'] == owner['uuid'], 'wrong original P1 attempt')
    binding = d698_failure_binding(run) if source == D698 else None
    return {'schema': 1, 'source': source, 'ova_sha256': scope['ova_sha256'], 'uuid': owner['uuid'],
            'retained_failure_binding': binding,
            'qualification_scope': ('superseded candidate measurement only; no production acceptance'
                                    if source == D698 else 'historical b579 continuation'),
            'initial_network_attempt': 'blocked; retained unchanged',
            'resumed_phase': 'confirmatory network test then reboot/persistence only',
            'prior_checks_sha256': hashlib.sha256((ev / 'checks.jsonl').read_bytes()).hexdigest()}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope', type=Path, required=True)
    p.add_argument('--shared', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--continue-undispatched', action='store_true')
    a = p.parse_args()
    scope = json.loads(a.scope.read_text())
    run = Path(scope['run_dir'])
    record = validate(scope, run, a.continue_undispatched)
    suffix = '-continuation' if a.continue_undispatched else ''
    shared = a.shared.read_bytes()
    body = tail(shared, scope['source_sha'])
    record['shared_raw_sha256'] = hashlib.sha256(shared).hexdigest()
    with a.output.open('x', encoding='utf-8', newline='\n') as out:
        out.write(body)
    with (run / ('evidence/post-os-resume-validation' + suffix + '.json')).open('x', encoding='utf-8') as out:
        json.dump(record, out, indent=2)


if __name__ == '__main__':
    main()
