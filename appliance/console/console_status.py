"""Bounded, read-only appliance observations shared by console and future UI.

No Docker socket, journal, .env, OVF values or credentials are read. Markers
describe recorded provisioning progress, never proof that the application works.
"""
import concurrent.futures
import datetime
import ipaddress
import json
import re
from pathlib import Path
import subprocess

STATE = Path('/var/lib/culvert-appliance/state')
BUILD = Path('/var/lib/culvert-appliance/build-info.json')
STEPS = ('ovf', 'console', 'images', 'install', 'agent', 'complete')
LABELS = ('Network configuration', 'Console access', 'Application images',
          'Service installation', 'Maintenance agent', 'Provisioning complete')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C',
       'SYSTEMD_PAGER': '', 'SYSTEMD_COLORS': '0'}


def clean(value, limit=120):
    """Remove terminal control characters, bidi controls and multiline output."""
    return ''.join(c if ' ' <= c <= '~' else '?' for c in str(value))[:limit]


def command(args):
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding='utf-8',
                                errors='replace', timeout=4, env=ENV, check=False)
        return result.stdout[:65536] if result.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def object_json(raw):
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def summarize(markers, unit, health, setup, ready):
    """Conservative state derivation; unknown is never a success."""
    checks = ready.get('checks')
    checks = checks if isinstance(checks, dict) else {}
    required = ('policy_loaded', 'policy_posture', 'ca', 'setup_complete')
    checks_ok = all(isinstance(checks.get(k), dict) and
                    checks[k].get('status') == 'ok' for k in required)
    enrolled = setup.get('needsSetup') is False
    healthy = health == '200'
    active = unit.get('ActiveState', 'unknown')
    result = unit.get('Result', 'unknown')
    if active == 'failed' or result not in ('success', 'unknown', ''):
        phase, reason = 'failed', 'FIRSTBOOT_FAILED'
        message = 'Provisioning failed; open diagnostics.'
    elif 'complete' in markers:
        phase, reason = 'provisioned', 'PROVISIONING_RECORDED'
        message = 'Provisioning recorded; checking application.'
        if not healthy:
            reason, message = 'APPLICATION_UNAVAILABLE', 'Application is not responding.'
        elif setup.get('needsSetup') is True:
            reason, message = 'SETUP_REQUIRED', 'Open the management URL to create your administrator.'
        elif not enrolled:
            reason, message = 'SETUP_UNKNOWN', 'Administrator setup status is unavailable.'
        elif checks_ok and ready.get('_http') == '200':
            phase, reason = 'ready', 'HEALTH_CHECKS_PASSED'
            message = 'Health checks passed; verify traffic from a test client.'
        else:
            reason, message = 'READINESS_INCOMPLETE', 'Administrator enrolled; readiness checks are incomplete.'
    elif active in ('active', 'activating', 'reloading'):
        phase, reason, message = 'running', 'FIRSTBOOT_RUNNING', 'Preparing the appliance...'
    elif active == 'inactive':
        phase, reason = 'waiting', 'FIRSTBOOT_NOT_RUNNING'
        message = 'Provisioning is incomplete and is not running.'
    else:
        phase, reason, message = 'unknown', 'FIRSTBOOT_UNKNOWN', 'Provisioning status is unavailable.'
    return {'phase': phase, 'reason': reason, 'message': message,
            'application_responding': healthy, 'administrator_enrolled': enrolled,
            'traffic_verified': False}


def collect(state=STATE, build=BUILD, run=command, netdev=Path('/sys/class/net')):
    queries = {
        'unit': ['/usr/bin/systemctl', 'show', 'culvert-firstboot.service',
                 '--property=LoadState,ActiveState,SubState,Result,ExecMainStatus,NRestarts'],
        'network': ['/usr/sbin/ip', '-j', '-4', 'address', 'show', 'scope', 'global'],
        'health': ['/usr/bin/curl', '--noproxy', '*', '--silent', '--max-time', '2',
                   '--output', '/dev/null', '--write-out', '%{http_code}',
                   'http://127.0.0.1:8080/health'],
        # The self-signed exception is restricted to a fixed loopback read.
        'setup': ['/usr/bin/curl', '--noproxy', '*', '--silent', '--insecure',
                  '--max-time', '2', '--max-filesize', '65536',
                  'https://127.0.0.1:9090/api/setup/status'],
        'ready': ['/usr/bin/curl', '--noproxy', '*', '--silent', '--max-time', '2',
                  '--max-filesize', '65536', '--write-out', '\n%{http_code}',
                  'http://127.0.0.1:8080/ready'],
    }
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futures = {key: pool.submit(run, args) for key, args in queries.items()}
        raw = {key: future.result() for key, future in futures.items()}
    unit = {}
    for line in raw['unit'].splitlines():
        key, sep, value = line.partition('=')
        if sep and key in ('LoadState', 'ActiveState', 'SubState', 'Result', 'ExecMainStatus', 'NRestarts'):
            unit[key] = clean(value, 40)
    markers = []
    steps = []
    for key, label in zip(STEPS, LABELS):
        try:
            done = (state / (key + '.done')).is_file()
        except OSError:
            done = False
        if done:
            markers.append(key)
        steps.append({'id': key, 'label': label,
                      'state': 'recorded' if done else 'not_recorded'})
    addresses = []
    try:
        net = json.loads(raw['network'])
        if isinstance(net, list):
            for interface in net:
                if not isinstance(interface, dict):
                    continue
                name = interface.get('ifname', '')
                # The appliance supports one hardware-backed management NIC.
                # Docker bridges/veth addresses are not reachable setup URLs.
                if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name):
                    continue
                if not (netdev / name / 'device').exists():
                    continue
                info = interface.get('addr_info', [])
                if not isinstance(info, list):
                    continue
                for addr in info:
                    if not isinstance(addr, dict) or addr.get('family') != 'inet':
                        continue
                    ip = ipaddress.IPv4Address(addr.get('local', ''))
                    if not ip.is_loopback and not ip.is_link_local and not ip.is_unspecified:
                        addresses.append(str(ip))
    except (ValueError, TypeError):
        pass
    addresses = sorted(set(addresses))[:8]
    version, candidate = 'unknown', False
    try:
        with build.open(encoding='utf-8') as stream:
            data = object_json(stream.read(65536))
        appliance = data.get('appliance')
        if isinstance(appliance, dict):
            version = clean(appliance.get('version', 'unknown'), 70)
        metadata = data.get('candidate')
        candidate = isinstance(metadata, dict) and metadata.get('candidate') is True
    except (OSError, UnicodeError):
        pass
    ready_body, _, ready_code = raw['ready'].rpartition('\n')
    ready = object_json(ready_body)
    ready['_http'] = ready_code
    summary = summarize(markers, unit, raw['health'], object_json(raw['setup']), ready)
    return {'schema_version': 1,
            'observed_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'version': version, 'candidate': candidate, 'addresses': addresses,
            'management_urls': ['https://' + ip + ':9090' for ip in addresses],
            'network': 'address_assigned' if addresses else 'address_unavailable',
            'firstboot': unit, 'steps': steps, **summary}


def lines(snapshot):
    output = ['CULVERT APPLIANCE', 'Version: ' + clean(snapshot['version']), '']
    if snapshot['candidate']:
        output += ['CANDIDATE BUILD - not qualified for production', '']
    output += [clean(snapshot['message']), '']
    if snapshot['management_urls']:
        output += ['Management URL (available when application starts):']
        output += snapshot['management_urls']
    else:
        output += ['No IPv4 address. Check VM network/DHCP or sign in for recovery.']
    output += ['', 'Provisioning checkpoints (not application health):']
    output += [('  [x] ' if step['state'] == 'recorded' else '  [ ] ') + step['label']
               for step in snapshot['steps']]
    output += ['', 'Client traffic: not verified by this console']
    return output
