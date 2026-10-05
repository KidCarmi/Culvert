#!/usr/bin/env python3
"""Disposable-guest P1 probes, invoked only through authenticated local console.

All output is private evidence. No service policy or product source is changed.
The PATH shim delegates to real netplan, then injects one failed return value.
"""
import base64
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
NET_HASH = '1007fc7f5f140c6e946f1f34617b02820d8c78d8d9786d50045865e05d862ff3'
RESET_HASH = 'fd53277fd2fc55afc79b70c8d00570b80e3ca938fc39edfa938fd81f8464d71a'
STATE = Path('/var/lib/culvert-lab-p1')
ORIGINAL_STATE = STATE
CONFIRMATION_STATE = Path('/var/lib/culvert-lab-p1-confirmation')
INJECTION_SEQUENCE = ['generate', 'apply', 'real-apply-succeeded-inject-71', 'generate', 'apply', 'real-rollback-apply-succeeded']
NETPLAN = Path('/etc/netplan/60-culvert.yaml')
BIN = Path('/opt/culvert-appliance/bin')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def command(argv, timeout=60, env=None, data=None):
    result = subprocess.run(argv, input=data, capture_output=True, timeout=timeout, env=env)
    require(result.returncode == 0, 'required guest command failed')
    require(len(result.stdout) <= 1024 * 1024, 'guest output exceeded bound')
    return result.stdout.decode('utf-8').strip()


def identity():
    return {'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'machine_id': Path('/etc/machine-id').read_text().strip(),
            'ssh_public': Path('/etc/ssh/ssh_host_ed25519_key.pub').read_text().strip(),
            'source': json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_text())['source']['git_commit']}


def image_guard():
    require(os.geteuid() == 0, 'authenticated local root required')
    require(identity()['source'] == SOURCE, 'candidate source mismatch')
    for name, expected in [('culvert-net', NET_HASH), ('culvert-appliance-reset-identity', RESET_HASH)]:
        require(hashlib.sha256((BIN / name).read_bytes()).hexdigest() == expected, 'installed helper differs from candidate')


def file_state(path):
    require(not path.is_symlink(), 'network symlink refused')
    if not path.exists():
        return {'exists': False}
    require(path.is_file() and path.stat().st_size <= 65536, 'network input refused')
    return {'exists': True, 'mode': path.stat().st_mode & 0o777,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def network():
    routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'default']))
    require(len(routes) == 1, 'one default IPv4 route required')
    route = routes[0]
    iface, gateway = route['dev'], route['gateway']
    require((Path('/sys/class/net') / iface / 'device').exists(), 'physical management interface required')
    data = json.loads(command(['ip', '-j', '-4', 'addr', 'show', 'dev', iface]))
    addresses = [a for a in data[0]['addr_info'] if a['scope'] == 'global']
    require(len(addresses) == 1, 'one management address required')
    address = str(ipaddress.ip_interface(addresses[0]['local'] + '/' + str(addresses[0]['prefixlen'])))
    require(ipaddress.ip_address(gateway) in ipaddress.ip_interface(address).network, 'on-link gateway required')
    return {'interface': iface, 'address': address, 'gateway': gateway}


def bounded_file(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536,
            'original network evidence unavailable')
    return path.read_bytes()


def confirmation_prevalidation(before):
    """Read, never replace, the failed initial attempt's guest evidence."""
    require(not ORIGINAL_STATE.is_symlink(), 'original evidence directory link refused')
    baseline = bounded_file(ORIGINAL_STATE / 'network-before.json')
    trace = bounded_file(ORIGINAL_STATE / 'netplan-shim' / 'trace')
    require(not (ORIGINAL_STATE / 'network-injection-passed.json').exists(),
            'confirmation requires the original unpassed fault exercise')
    require(json.loads(baseline) == before, 'source identity, boot, network or netplan changed since initial exercise')
    require(trace.decode().splitlines() == INJECTION_SEQUENCE, 'original real apply and rollback evidence incomplete')
    return {'original_baseline_sha256': hashlib.sha256(baseline).hexdigest(),
            'original_trace_sha256': hashlib.sha256(trace).hexdigest(),
            'original_availability': 'failed immediate assertion; retained unchanged',
            'source_unchanged': True}


def observe_network(expected, deadline):
    """Capture both route and address data, even during a default-route gap."""
    result = {'routes': None, 'addresses': None, 'errors': []}
    for label, argv in [('routes', ['ip', '-j', '-4', 'route', 'show', 'default']),
                        ('addresses', ['ip', '-j', '-4', 'addr', 'show', 'dev', expected['interface']])]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result['errors'].append(label + ': observation deadline reached')
            continue
        try:
            result[label] = json.loads(command(argv, timeout=min(2, remaining)))
        except (ValueError, subprocess.TimeoutExpired):
            result['errors'].append(label + ': command failed, timed out or returned invalid JSON')
    result['matches'] = False
    try:
        routes, interfaces = result['routes'], result['addresses']
        require(not result['errors'] and len(routes) == 1 and len(interfaces) == 1, 'route/address inventory incomplete')
        addresses = [a for a in interfaces[0]['addr_info'] if a['scope'] == 'global']
        require(len(addresses) == 1, 'management address missing or ambiguous')
        address = str(ipaddress.ip_interface(addresses[0]['local'] + '/' + str(addresses[0]['prefixlen'])))
        actual = {'interface': routes[0]['dev'], 'gateway': routes[0]['gateway'], 'address': address}
        result['matches'] = actual == expected and interfaces[0]['ifname'] == expected['interface']
    except (ValueError, KeyError, TypeError, IndexError):
        pass
    return result


def wait_network_stable(expected, state, clock=time.monotonic, pause=time.sleep, observe=observe_network):
    """At most 60 seconds; three consecutive matches spanning at least 4s.

    Durable JSONL retains every transient, including samples before a timeout.
    A successful confirmation does not assert zero outage after netplan returns.
    """
    start = clock()
    deadline, consecutive, stable_since, samples = start + 60, 0, None, []
    with (state / 'rollback-network-observations.jsonl').open('x', encoding='utf-8', newline='\n') as out:
        while clock() < deadline:
            sample = observe(expected, deadline)
            now = clock()
            sample['elapsed_seconds'] = round(now - start, 3)
            samples.append(sample)
            out.write(json.dumps(sample) + '\n'); out.flush(); os.fsync(out.fileno())
            if sample['matches']:
                consecutive += 1
                stable_since = now if stable_since is None else stable_since
            else:
                consecutive, stable_since = 0, None
            if consecutive >= 3 and now - stable_since >= 4 and now <= deadline:
                return {'result': 'stable', 'max_seconds': 60, 'stable_samples': consecutive,
                        'elapsed_seconds': round(now - start, 3), 'observations': samples,
                        'immediate_match': samples[0]['matches'],
                        'availability_claim': 'bounded convergence only; transient gaps and initial failure retained'}
            if now >= deadline:
                break
            pause(min(2, deadline - now))
    raise ValueError('management network did not converge within 60 seconds; observations retained')


def reachable():
    require(command(['curl', '-fsS', '--max-time', '10', '-o', '/dev/null', '-w', '%{http_code}',
                     'http://127.0.0.1:8080/health']) == '200', 'local application health failed')
    # ARP/neighbour reachability and a real route probe, without assuming ICMP.
    command(['ip', '-4', 'route', 'get', network()['gateway']])
    return True


def network_before(campaign='initial', continuation=None):
    image_guard()
    before = {'identity': identity(), 'network': network(), 'netplan': file_state(NETPLAN)}
    if continuation is not None:
        require(campaign == 'confirmation' and set(continuation) == {'boot_id'}
                and before['identity']['boot_id'] == continuation['boot_id'], 'undispatched observation boot changed')
    initial = confirmation_prevalidation(before) if campaign == 'confirmation' else None
    STATE.mkdir(mode=0o700, exist_ok=campaign == 'initial')
    require(not STATE.is_symlink(), 'guest campaign directory link refused')
    if initial is not None:
        with (STATE / 'initial-failure-preserved.json').open('x') as out:
            json.dump(initial, out)
    record = STATE / 'network-before.json'
    with record.open('x') as out:
        json.dump(before, out)
    os.chmod(record, 0o600)
    shim = STATE / 'netplan-shim'
    shim.mkdir(mode=0o700)
    trace = shim / 'trace'
    wrapper = shim / 'netplan'
    wrapper.write_text('''#!/usr/bin/env bash
set -euo pipefail
here=${0%/*}
printf '%s\\n' "$*" >>"$here/trace"
if [[ $# == 1 && $1 == apply && ! -e $here/injected ]]; then
  : >"$here/injected"
  /usr/sbin/netplan apply
  printf 'real-apply-succeeded-inject-71\\n' >>"$here/trace"
  exit 71
fi
if [[ $# == 1 && $1 == apply ]]; then
  /usr/sbin/netplan apply
  printf 'real-rollback-apply-succeeded\\n' >>"$here/trace"
  exit 0
fi
exec /usr/sbin/netplan "$@"
''', encoding='utf-8')
    wrapper.chmod(0o700)
    env = {'PATH': str(shim) + ':/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C'}
    result = subprocess.run([str(BIN / 'culvert-net'), 'static', before['network']['address'],
                             before['network']['gateway']], env=env, capture_output=True, timeout=180)
    # A refused validation or real apply failure cannot masquerade as injected failure.
    events = trace.read_text().splitlines()
    with (STATE / 'network-command-result.json').open('x') as out:
        json.dump({'exit': result.returncode, 'trace': events,
                   'stdout_base64': base64.b64encode(result.stdout[:65536]).decode(),
                   'stderr_base64': base64.b64encode(result.stderr[:65536]).decode()}, out)
    require(events == INJECTION_SEQUENCE,
            'real apply/failure/rollback sequence not established')
    require(result.returncode != 0, 'failed static apply incorrectly succeeded')
    require(file_state(NETPLAN) == before['netplan'], 'previous netplan not restored exactly')
    convergence = wait_network_stable(before['network'], STATE) if campaign == 'confirmation' else None
    require(network() == before['network'], 'management address or route changed')
    reachable()
    after = {'schema': 1, 'phase': 'network-before-reboot', 'source': SOURCE,
             'before': before, 'after': {'identity': identity(), 'network': network(), 'netplan': file_state(NETPLAN)},
             'injection_sequence': events, 'helper_exit': result.returncode, 'health': True,
             'campaign': campaign, 'convergence': convergence, 'initial_failure': initial}
    with (STATE / 'network-injection-passed.json').open('x') as out:
        json.dump(after, out)
    # Remove only this fixed scratch shim after proof. On failure preserve it for inspection;
    # it is never on the global PATH, so normal services cannot inherit it.
    shutil.rmtree(shim)
    return after


def network_after(campaign='initial'):
    image_guard()
    before = json.loads((STATE / 'network-before.json').read_text())
    require((STATE / 'network-injection-passed.json').is_file(), 'successful fault exercise missing')
    require(before['identity']['boot_id'] != identity()['boot_id'], 'actual reboot not observed')
    require(before['identity']['machine_id'] == identity()['machine_id'], 'unexpected OS identity change')
    require(file_state(NETPLAN) == before['netplan'], 'rollback configuration changed across reboot')
    require(network() == before['network'], 'management network changed across reboot')
    reachable()
    return {'schema': 1, 'phase': 'network-after-reboot', 'source': SOURCE, 'before': before, 'campaign': campaign,
            'after': {'identity': identity(), 'network': network(), 'netplan': file_state(NETPLAN)}, 'health': True}


def pam_old_password(password):
    """One real login-service PAM authentication; no account/session is opened."""
    require(password and len(password) <= 256 and '\x00' not in password, 'invalid old credential input')
    pam, libc = ctypes.CDLL('libpam.so.0'), ctypes.CDLL(None)
    class Message(ctypes.Structure):
        _fields_ = [('style', ctypes.c_int), ('message', ctypes.c_char_p)]
    class Response(ctypes.Structure):
        _fields_ = [('response', ctypes.c_void_p), ('code', ctypes.c_int)]
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(Message)),
                                    ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)
    libc.calloc.argtypes, libc.calloc.restype = [ctypes.c_size_t, ctypes.c_size_t], ctypes.c_void_p
    libc.strdup.argtypes, libc.strdup.restype = [ctypes.c_char_p], ctypes.c_void_p
    exchanges = []
    def conversation(count, messages, result, unused):
        if count < 1 or count > 16:
            return 19  # PAM_CONV_ERR
        array = ctypes.cast(libc.calloc(count, ctypes.sizeof(Response)), ctypes.POINTER(Response))
        if not array:
            return 5  # PAM_BUF_ERR
        for index in range(count):
            style = messages[index].contents.style
            exchanges.append(style)
            if style == 1 and exchanges.count(1) != 1:
                return 19  # Never replay the old credential if PAM prompts again.
            if style in (1, 2):
                value = password if style == 1 else 'culvert'
                array[index].response = libc.strdup(value.encode())
            elif style not in (3, 4):
                return 19
        result[0] = array
        return 0
    callback = callback_type(conversation)
    class Conversation(ctypes.Structure):
        _fields_ = [('callback', callback_type), ('data', ctypes.c_void_p)]
    conv, handle = Conversation(callback, None), ctypes.c_void_p()
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Conversation), ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_authenticate.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_set_item.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    require(pam.pam_start(b'login', b'culvert', ctypes.byref(conv), ctypes.byref(handle)) == 0, 'PAM initialization failed')
    require(pam.pam_set_item(handle, 3, ctypes.cast(ctypes.c_char_p(b'/dev/tty1'), ctypes.c_void_p)) == 0,
            'PAM console identity unavailable')
    code = pam.pam_authenticate(handle, 0)
    pam.pam_end(handle, code)
    require(code == 7 and exchanges.count(1) == 1, 'old password was not refused by one password-based PAM check')
    return {'service': 'login', 'pam_status': code, 'password_prompts': exchanges.count(1)}


def identity_before():
    image_guard()
    require(Path('/var/lib/culvert-appliance/state/complete.done').exists(), 'first boot incomplete')
    keys = Path('/etc/ssh/culvert-authorized-keys/culvert-operator')
    require(keys.is_file() and keys.stat().st_size > 0, 'old operator authorization missing')
    return {'schema': 1, 'phase': 'identity-before-reset', 'identity': identity(),
            'operator_keys_sha256': hashlib.sha256(keys.read_bytes()).hexdigest()}


def identity_after(old_password):
    image_guard()
    keys = Path('/etc/ssh/culvert-authorized-keys/culvert-operator')
    require(keys.is_file() and keys.read_bytes() == b'', 'fresh default import retained operator authorization')
    require(Path('/var/lib/culvert-appliance/state/access.done').is_file(), 'operator keys were not re-imported')
    require(Path('/var/lib/culvert-appliance/state/complete.done').is_file(), 'fresh first boot incomplete')
    return {'schema': 1, 'phase': 'identity-after-reset', 'identity': identity(),
            'operator_keys_empty': True, 'old_password': pam_old_password(old_password)}


def main(action, private_input=None, campaign='initial'):
    global STATE
    require(campaign in ('initial', 'confirmation'), 'unknown guest P1 campaign')
    STATE = CONFIRMATION_STATE if campaign == 'confirmation' else ORIGINAL_STATE
    if action == 'network-before':
        return network_before(campaign, private_input)
    if action == 'network-after':
        return network_after(campaign)
    if action == 'identity-before':
        return identity_before()
    if action == 'identity-after':
        return identity_after(base64.b64decode(private_input, validate=True).decode('ascii'))
    raise ValueError('unknown P1 probe')


if __name__ == '__main__':
    # The controller appends a literal action call after loading this source.
    raise SystemExit('invoke only through the P1 controller')
