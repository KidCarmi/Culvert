#!/usr/bin/env python3
"""One-shot P1 regression stages on the single explicitly approved LAB VM.

No stage runs implicitly. Failed/ambiguous stages keep their attempt markers.
The parent controls lifecycle ordering and exported backup/escrow verification.
"""
import argparse
import base64
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import traceback
import uuid


HERE = Path(__file__).resolve().parent
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
OVA = '1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775'
RESET_HASH = 'fd53277fd2fc55afc79b70c8d00570b80e3ca938fc39edfa938fd81f8464d71a'
NET_HASH = '1007fc7f5f140c6e946f1f34617b02820d8c78d8d9786d50045865e05d862ff3'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


campaigns = load_module('p1_campaigns', HERE / 'p1-campaign.py')


def save_new(path, value):
    with path.open('x', encoding='utf-8') as out:
        json.dump(value, out, indent=2)


def read_record(path):
    require(path.stat().st_size <= 1024 * 1024, 'oversized evidence')
    return json.loads(path.read_text(encoding='utf-8'))


def captured(value):
    raw = value or b''
    return {'bytes': len(raw), 'base64': base64.b64encode(raw[:1024 * 1024]).decode(),
            'truncated': len(raw) > 1024 * 1024}


def transport(args, script, nowait=False):
    timeout = 360 if args.campaign == 'confirmation' else 240
    command = [sys.executable, str(HERE / 'console-priv.py'), '--scope', str(args.scope),
               '--bind', args.bind, '--timeout', str(timeout)]
    if nowait:
        command.append('--nowait')
    diagnostic = {'timeout_seconds': timeout + 120, 'exit': None}
    try:
        result = subprocess.run(command, input=script, capture_output=True, timeout=timeout + 120)
        diagnostic.update(exit=result.returncode, stdout=captured(result.stdout), stderr=captured(result.stderr))
    except Exception as exc:
        diagnostic.update(exception=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
        if isinstance(exc, subprocess.TimeoutExpired):
            diagnostic.update(stdout=captured(exc.stdout), stderr=captured(exc.stderr))
        raise
    finally:
        if getattr(args, 'evidence_path', None) is not None:
            save_new(args.evidence_path / ('console-transport-' + str(time.time_ns()) + '.json'), diagnostic)
    require(result.returncode == 0, 'authenticated console probe refused or failed; no retry')
    require(len(result.stdout) <= 1024 * 1024, 'probe evidence exceeded bound')
    return result.stdout


def probe(args, action, private_input=None):
    source = base64.b64encode((HERE / 'p1-guest-checks.py').read_bytes()).decode()
    # Private credentials, when needed, exist only in private transport input.
    guest_timeout = 330 if args.campaign == 'confirmation' else 220
    payload = (f"timeout --signal=TERM --kill-after=5s {guest_timeout}s python3 - <<'CULVERT_P1_PROBE'\nimport base64,json\n"
               "namespace={'__name__':'culvert_p1_guest'}\n"
               f"exec(compile(base64.b64decode({source!r}), 'p1-guest-checks.py', 'exec'), namespace)\n"
               f"namespace.update(SOURCE={SOURCE!r}, NET_HASH={NET_HASH!r}, RESET_HASH={RESET_HASH!r})\n"
               f"print(json.dumps(namespace['main']({action!r}, {private_input!r}, {args.campaign!r})))\n"
               "CULVERT_P1_PROBE\n")
    observation = json.loads(transport(args, payload.encode()))
    require(observation.get('schema') == 1, 'probe schema unavailable')
    return observation


def valid_identity(value):
    try:
        key = value['ssh_public'].split()
        return (value['source'] == SOURCE and str(uuid.UUID(value['boot_id'])) == value['boot_id']
                and re.fullmatch(r'[a-f0-9]{32}', value['machine_id']) is not None
                and len(key) >= 2 and key[0] == 'ssh-ed25519'
                and len(base64.b64decode(key[1], validate=True)) == 51)
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def validate_identity(before, after):
    try:
        left, right = before['identity'], after['identity']
        return (before['phase'] == 'identity-before-reset' and after['phase'] == 'identity-after-reset'
                and valid_identity(left) and valid_identity(right)
                and left['machine_id'] != right['machine_id']
                and left['boot_id'] != right['boot_id']
                and left['ssh_public'].split()[:2] != right['ssh_public'].split()[:2]
                and after['operator_keys_empty'] is True
                and after['old_password'] == {'service': 'login', 'pam_status': 7, 'password_prompts': 1})
    except (KeyError, TypeError, AttributeError):
        return False


def validate_network(before, after):
    try:
        return (before['phase'] == 'network-before-reboot' and after['phase'] == 'network-after-reboot'
                and before.get('campaign', 'initial') == after.get('campaign', 'initial')
                and (before.get('campaign', 'initial') == 'initial' or valid_confirmation(before))
                and before['source'] == after['source'] == SOURCE and before['helper_exit'] != 0
                and before['injection_sequence'] == ['generate', 'apply', 'real-apply-succeeded-inject-71', 'generate', 'apply', 'real-rollback-apply-succeeded']
                and before['health'] is True and after['health'] is True
                and before['before'] == after['before']
                and valid_identity(before['before']['identity']) and valid_identity(before['after']['identity'])
                and valid_identity(after['after']['identity'])
                and before['after']['identity']['boot_id'] != after['after']['identity']['boot_id']
                and before['before']['identity']['machine_id'] == before['after']['identity']['machine_id'] == after['after']['identity']['machine_id']
                and before['before']['netplan'] == before['after']['netplan'] == after['after']['netplan']
                and before['before']['network'] == before['after']['network'] == after['after']['network'])
    except (KeyError, TypeError):
        return False


def valid_confirmation(value):
    try:
        convergence, initial = value['convergence'], value['initial_failure']
        samples = convergence['observations']
        tail = samples[-3:]
        return (value['campaign'] == 'confirmation' and initial['source_unchanged'] is True
                and all(re.fullmatch(r'[a-f0-9]{64}', initial[key]) for key in
                        ('original_baseline_sha256', 'original_trace_sha256'))
                and convergence['result'] == 'stable' and convergence['max_seconds'] == 60
                and 4 <= convergence['elapsed_seconds'] <= 60 and len(samples) >= 3
                and convergence['immediate_match'] is samples[0]['matches']
                and all(type(row['matches']) is bool and 0 <= row['elapsed_seconds'] <= 60 for row in samples)
                and all(left['elapsed_seconds'] <= right['elapsed_seconds'] for left, right in zip(samples, samples[1:]))
                and all(row['matches'] is True for row in tail)
                and tail[-1]['elapsed_seconds'] - tail[0]['elapsed_seconds'] >= 4)
    except (KeyError, TypeError, IndexError):
        return False


def operator_command(lab, pin, key):
    return ['ssh', '-F', 'none', '-i', str(key), '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
            '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=publickey',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + str(pin),
            '-o', 'GlobalKnownHostsFile=none', '-o', 'HostKeyAlias=' + lab.state['name'],
            '-o', 'ConnectTimeout=10', 'culvert-operator@' + lab.guest_ip(timeout=30), 'status-json']


def prove_operator(lab, pin, key, refused=False, evidence=None):
    diagnostic = {'ssh_executable': shutil.which('ssh'), 'stdin': 'DEVNULL', 'timeout_seconds': 60,
                  'expected_refusal': refused, 'exit': None, 'timed_out': False}
    start = time.monotonic()
    try:
        result = subprocess.run(operator_command(lab, pin, key), capture_output=True,
                                stdin=subprocess.DEVNULL, timeout=60)
        diagnostic.update(exit=result.returncode, stdout=captured(result.stdout), stderr=captured(result.stderr))
    except Exception as exc:
        diagnostic.update(exception=type(exc).__name__, error=str(exc), traceback=traceback.format_exc())
        if isinstance(exc, subprocess.TimeoutExpired):
            diagnostic.update(timed_out=True, stdout=captured(exc.stdout), stderr=captured(exc.stderr))
        raise
    finally:
        diagnostic['elapsed_seconds'] = round(time.monotonic() - start, 3)
        if evidence is not None:
            save_new(evidence / ('operator-probe-' + str(time.time_ns()) + '.json'), diagnostic)
    if refused:
        require(result.returncode == 255 and b'Permission denied (publickey)' in result.stderr
                and b'Host key verification failed' not in result.stderr,
                'old operator key refusal not established')
    else:
        require(result.returncode == 0 and isinstance(json.loads(result.stdout), dict), 'operator networking unavailable')


def external_health(lab):
    # No auth token, ambient proxy, redirects or TLS policy changes for this probe.
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://' + lab.guest_ip(timeout=30) + ':8080/health', timeout=10) as result:
        require(result.status == 200, 'external application health unavailable')


def power_state(lab, wanted, timeout=180):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if lab.vm(timeout=15)['runtime']['powerState'] == wanted:
            return
        time.sleep(3)
    raise ValueError('required owned VM power transition not observed')


def run(args, lab, boot, private):
    action = args.action
    if action == 'network-before':
        # Establish controller-visible access BEFORE the deliberate network mutation.
        prove_operator(lab, lab.sec / 'known_hosts', lab.sec / 'id_ed25519', evidence=private)
        external_health(lab)
        before_ip = lab.guest_ip(timeout=30)
        payload = {'boot_id': args.continuation['boot_id']} if args.continuation else None
        observation = probe(args, action, payload)
        save_new(private / 'network-before.json', observation)
        require(observation.get('campaign') == args.campaign
                and (args.campaign == 'initial' or valid_confirmation(observation)), 'confirmation convergence proof incomplete')
        require(before_ip == lab.guest_ip(timeout=30), 'owned IP changed')
        prove_operator(lab, lab.sec / 'known_hosts', lab.sec / 'id_ed25519', evidence=private)
        external_health(lab)
    elif action == 'network-after':
        campaigns.effective_stage(lab.sec, args.campaign, 'network-before', lab.state['uuid'])
        observation = probe(args, action)
        save_new(private / 'network-after.json', observation)
        require(validate_network(read_record(private / 'network-before.json'), observation), 'network persistence not proven')
        require(lab.guest_ip(timeout=30) == observation['before']['network']['address'].split('/')[0], 'owned IP changed')
        prove_operator(lab, lab.sec / 'known_hosts', lab.sec / 'id_ed25519', evidence=private)
        external_health(lab)
    elif action == 'identity-before':
        require(read_record(private / 'network-after.attempt.json')['status'] == 'pass', 'network regression incomplete')
        observation = probe(args, action)
        save_new(private / 'identity-before.json', observation)
        password = (lab.sec / 'bootstrap-console-password').read_bytes()
        require(password and len(password) <= 256, 'prior console credential unavailable')
        with (private / 'old-console-password').open('xb') as out:
            out.write(password)
        for name in ('known_hosts', 'id_ed25519.pub'):
            with (private / ('old-' + name)).open('xb') as out:
                out.write((lab.sec / name).read_bytes())
    elif action == 'identity-reset':
        require(read_record(private / 'identity-before.attempt.json')['status'] == 'pass', 'identity baseline incomplete')
        # Contract owned by the parent backup/escrow exporter: same VM, exact OVA,
        # verified external copies. An arbitrary backup path is not a readiness flag.
        require(args.escrow_evidence is not None, 'verified external backup/escrow evidence required')
        escrow = read_record(args.escrow_evidence)
        require(escrow.get('uuid') == lab.state['uuid'] and escrow.get('ova_sha256') == OVA
                and escrow.get('campaign', 'initial') == args.campaign
                and escrow.get('backup_export_verified') is True and escrow.get('escrow_export_verified') is True,
                'backup/escrow readiness contract not satisfied')
        save_new(private / 'export-readiness.json', escrow)
        script = ("set -euo pipefail\n"
                  f"test \"$(sha256sum /opt/culvert-appliance/bin/culvert-appliance-reset-identity | cut -d' ' -f1)\" = {RESET_HASH}\n"
                  "printf 'y\\n' | /opt/culvert-appliance/bin/culvert-appliance-reset-identity\n").encode()
        transport(args, script, nowait=True)
        power_state(lab, 'poweredOff')
        save_new(private / 'poweroff-observed.json', {'uuid': lab.state['uuid'], 'state': 'poweredOff'})
    elif action == 'identity-power-on':
        require(read_record(private / 'identity-reset.attempt.json')['status'] == 'pass', 'automatic poweroff not proven')
        with boot.module.locked(lab.run):
            require(lab.vm(timeout=15)['runtime']['powerState'] == 'poweredOff', 'unexpected current power state')
            lab.gov('vm.power', '-on', lab.state['path'], json_output=False)
            power_state(lab, 'poweredOn')
    elif action == 'identity-bootstrap':
        require(read_record(private / 'identity-power-on.attempt.json')['status'] == 'pass', 'fresh boot not dispatched')
        transport_module = load_module('p1_console_priv', HERE / 'console-priv.py')
        with boot.module.locked(lab.run):
            old = (private / 'old-console-password').read_bytes()
            require((lab.sec / 'bootstrap-console-password').read_bytes() == old, 'old credential file changed')
            # Preserve the actual old file; Bootstrap creates a fresh exclusive file.
            (lab.sec / 'bootstrap-console-password').rename(private / 'old-console-password-original')
            flow = boot.Bootstrap(lab, transport_module.Keyboard(lab), initial_timeout=900,
                                  capture_prefix='p1-identity-fresh')
            password = flow.authenticate()
            require(password.encode('ascii') != old, 'fresh console password reused')
    elif action == 'identity-after':
        require(read_record(private / 'identity-bootstrap.attempt.json')['status'] == 'pass', 'new PAM bootstrap incomplete')
        encoded = base64.b64encode((private / 'old-console-password').read_bytes()).decode()
        observation = probe(args, action, encoded)
        save_new(private / 'identity-after.json', observation)
        require(validate_identity(read_record(private / 'identity-before.json'), observation), 'fresh identities not proven')
        public = observation['identity']['ssh_public'].split()
        require(len(public) >= 2 and public[0] == 'ssh-ed25519'
                and len(base64.b64decode(public[1], validate=True)) == 51, 'fresh SSH host key invalid')
        # Pin came through the authenticated local console, never ssh-keyscan.
        pin = private / 'fresh-known-hosts'
        with pin.open('x', encoding='ascii') as out:
            out.write(lab.state['name'] + ' ' + ' '.join(public[:2]) + '\n')
        prove_operator(lab, pin, lab.sec / 'id_ed25519', refused=True, evidence=private)
        external_health(lab)
    else:
        raise ValueError('unknown regression stage')


def main():
    global SOURCE, OVA, RESET_HASH, NET_HASH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--escrow-evidence', type=Path)
    parser.add_argument('--campaign', choices=tuple(campaigns.NAMES), default='initial')
    parser.add_argument('--continue-undispatched', action='store_true')
    parser.add_argument('--continuation-proof', type=Path)
    parser.add_argument('action', choices=['network-before', 'network-after', 'identity-before', 'identity-reset',
                                         'identity-power-on', 'identity-bootstrap', 'identity-after'])
    args = parser.parse_args()
    args.continuation = None
    boot = load_module('p1_bootstrap', HERE / 'bootstrap-checks.py')
    lab = boot.module.Lab(args.scope)
    marker, created, stage_lock, private, lock_owned = None, False, None, None, False
    try:
        boot.module.validate_scope(lab.c)
        profile = load_module('p1_candidate_identities', HERE / 'candidate-identities.py').scope_profile(lab.c)
        SOURCE, OVA = profile['source_sha'], profile['ova_sha256']
        RESET_HASH, NET_HASH = profile['reset_helper_sha256'], profile['network_helper_sha256']
        campaigns.SOURCE = SOURCE
        require(lab.c['source_sha'] == SOURCE and lab.c['ova_sha256'] == OVA
                and lab.c.get('credential_mode') == 'none', 'exact default-import candidate required')
        boot.private_directory(lab)
        lab.vm(timeout=15)
        initial = campaigns.initial_failure(lab.sec, lab.state['uuid'], args.campaign)
        private = campaigns.directory(lab.sec, args.campaign)
        private.mkdir(exist_ok=True)
        require(not private.is_symlink(), 'private regression directory link refused')
        args.evidence_path = private
        stage_lock = private / 'stage.lock'
        stage_lock.mkdir()
        lock_owned = True
        if args.continue_undispatched:
            require(args.action == 'network-before' and args.continuation_proof is not None,
                    'only network-before supports verified undispatched continuation')
            args.continuation = campaigns.continuation_binding(lab.sec, args.campaign, lab.state['uuid'],
                                                                args.continuation_proof)
        else:
            require(args.continuation_proof is None, 'proof requires explicit continuation flag')
        marker = private / (args.action + ('.continuation-attempt.json' if args.continue_undispatched else '.attempt.json'))
        require(not marker.exists(), 'prior stage attempt exists; no retry')
        save_new(marker, {'status': 'started', 'uuid': lab.state['uuid'], 'campaign': args.campaign,
                          'initial_failure': initial, 'continuation': args.continuation})
        created = True
        run(args, lab, boot, private)
        current = read_record(marker)
        current['status'] = 'pass'
        boot.module.atomic_json(marker, current)
        label = 'p1-' + ('confirmation-' if args.campaign == 'confirmation' else '') + args.action
        if args.continue_undispatched:
            label += '-undispatched-continuation'
        lab.record(label, 'pass', 'one-shot real guest regression evidence retained privately')
        print('PASS: ' + args.campaign + ' ' + args.action)
        return 0
    except Exception as exc:
        if private is not None and private.is_dir() and not private.is_symlink():
            save_new(private / ('controller-exception-' + str(time.time_ns()) + '.json'),
                     {'type': type(exc).__name__, 'error': str(exc), 'traceback': traceback.format_exc(),
                      'action': args.action, 'campaign': args.campaign,
                      'undispatched_continuation': args.continue_undispatched})
        if created:
            # Preserve an existing result when duplicate invocation was refused.
            current = read_record(marker)
            if current.get('status') == 'started':
                current['status'] = 'blocked'
                boot.module.atomic_json(marker, current)
        print('BLOCKED: ' + args.action + '; private evidence retained; no retry.', file=sys.stderr)
        return 90
    finally:
        if lock_owned:
            stage_lock.rmdir()


if __name__ == '__main__':
    sys.exit(main())
