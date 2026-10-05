#!/usr/bin/env python3
"""Read-only post-run guest evidence; invoke through pinned SSH as root.

No raw command output, journal messages, environment or credentials leave the
guest. Missing/failed observations remain explicit; this script awards no PASS.
The caller must compare the boot ID and identities with pre-run evidence.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import urllib.error
import urllib.request


REQUIRED_READY = ('policy_loaded', 'policy_posture', 'ca', 'clamav')
STEPS = ('agent', 'complete', 'console', 'images', 'install', 'ovf')
UNIT_PROPERTIES = ('LoadState', 'ActiveState', 'SubState', 'Result',
                   'ExecMainStatus', 'ExecMainStartTimestampMonotonic',
                   'ExecMainExitTimestampMonotonic', 'ConditionResult')


def command(args, limit=1024 * 1024):
    try:
        result = subprocess.run(args, capture_output=True, timeout=25,
                                env={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                     'LC_ALL': 'C', 'SYSTEMD_COLORS': '0'})
        if len(result.stdout) > limit:
            return {'outcome': 'oversized', 'returncode': result.returncode}, None
        text = result.stdout.decode('utf-8', errors='strict')
        return {'outcome': 'completed', 'returncode': result.returncode}, text
    except subprocess.TimeoutExpired:
        return {'outcome': 'timeout', 'returncode': None}, None
    except (OSError, UnicodeError):
        return {'outcome': 'unavailable', 'returncode': None}, None


def successful(meta):
    return meta['outcome'] == 'completed' and meta['returncode'] == 0


def validated_command(args, pattern):
    meta, output = command(args)
    value = output.strip() if output is not None else ''
    valid = successful(meta) and re.fullmatch(pattern, value) is not None
    return dict(meta, valid=valid, value=value if valid else None)


def boot_id():
    try:
        value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return value if re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', value) else None
    except (OSError, UnicodeError):
        return None


def ready_observation():
    result = {'http_status': None, 'parsed': False,
              'rows': {name: {'present': False, 'ok': False} for name in REQUIRED_READY},
              'all_required_ok': False}
    # Disable ambient proxy settings; this is exclusively a guest loopback read.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        try:
            response = opener.open('http://127.0.0.1:8080/ready', timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            result['http_status'] = response.status
            raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            return result
        document = json.loads(raw)
        checks = document.get('checks') if isinstance(document, dict) else None
        if not isinstance(checks, dict):
            return result
        result['parsed'] = True
        for name in REQUIRED_READY:
            row = checks.get(name)
            result['rows'][name] = {'present': name in checks,
                                    'ok': isinstance(row, dict) and row.get('status') == 'ok'}
        result['all_required_ok'] = result['http_status'] == 200 and all(
            row['present'] and row['ok'] for row in result['rows'].values())
    except (OSError, ValueError, UnicodeError):
        pass
    return result


def unit_observation(name):
    args = ['systemctl', 'show', name]
    for prop in UNIT_PROPERTIES:
        args += ['-p', prop]
    meta, text = command(args)
    properties = {name: None for name in UNIT_PROPERTIES}
    if successful(meta):
        for line in text.splitlines():
            key, separator, value = line.partition('=')
            if separator and key in properties and re.fullmatch(r'[A-Za-z0-9_-]{0,80}', value):
                properties[key] = value
    return dict(meta, properties=properties)


def journal_observation():
    meta, text = command(['journalctl', '-b', '-u', 'culvert-firstboot.service',
                          '--no-pager', '-o', 'cat'], limit=8 * 1024 * 1024)
    result = dict(meta, full_current_boot=successful(meta), line_count=None,
                  step_done_count=None, step_done_counts={name: None for name in STEPS})
    if successful(meta):
        # Read the entire current-boot unit journal, never a tail. Export counts
        # only: first-boot messages may include the initial setup credential.
        done = re.findall(r'\bstep ([A-Za-z0-9_-]+): done\b', text)
        result.update(line_count=len(text.splitlines()), step_done_count=len(done),
                      step_done_counts={name: done.count(name) for name in STEPS})
    return result


def state_observation():
    try:
        paths = list(Path('/var/lib/culvert-appliance/state').iterdir())
        # Reject unexpected names instead of publishing arbitrary guest text.
        done = [path.name for path in paths if path.name.endswith('.done')]
        valid = all(re.fullmatch(r'[a-z][a-z0-9_-]{0,39}\.done', name) for name in done)
        regular = all(path.is_file() and not path.is_symlink()
                      for path in paths if path.name.endswith('.done'))
        return {'readable': True, 'valid': valid and regular,
                'done': sorted(done) if valid and regular else None}
    except OSError:
        return {'readable': False, 'valid': False, 'done': None}


def source_observation():
    try:
        raw = Path('/var/lib/culvert-appliance/build-info.json').read_bytes()
        document = json.loads(raw) if len(raw) <= 1024 * 1024 else {}
        source = document.get('source', {}).get('git_commit')
        valid = isinstance(source, str) and re.fullmatch(r'[0-9a-f]{40}', source) is not None
        return {'valid': valid, 'git_commit': source if valid else None}
    except (OSError, ValueError, AttributeError, UnicodeError):
        return {'valid': False, 'git_commit': None}


def main():
    result = {'schema': 1, 'root': os.geteuid() == 0}
    if not result['root']:
        result['error'] = 'root-required-for-complete-journal-observation'
        print(json.dumps(result, sort_keys=True))
        return 1
    result['boot_id_before_observation'] = boot_id()
    result['ready'] = ready_observation()
    result['kernel'] = validated_command(['uname', '-r'], r'[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9._+~-]*')
    result['firstboot_journal'] = journal_observation()
    result['units'] = {unit: unit_observation(unit) for unit in (
        'culvert-firstboot.service', 'culvert-stack-resume.service',
        'culvert-maint.service', 'docker.service', 'culvert-console-host.service')}
    result['state'] = state_observation()
    result['source'] = source_observation()
    result['image'] = validated_command(['docker', 'inspect', '-f', '{{.Image}}', 'culvert'], r'sha256:[0-9a-f]{64}')
    result['agent_version'] = validated_command(['culvert-maint', '--version'], r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?')
    result['boot_id_after_observation'] = boot_id()
    result['same_boot_during_observation'] = bool(result['boot_id_before_observation']) and (
        result['boot_id_before_observation'] == result['boot_id_after_observation'])
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
