#!/usr/bin/env python3
"""Collect/validate private post-reboot evidence; print only structured verdicts."""
import argparse
import datetime
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import uuid


HERE = Path(__file__).resolve().parent
REQUIRED = {'uid', 'boot_id', 'kernel', 'kernel_version', 'done_markers', 'build_info',
            'app_image_id', 'agent_version', 'agent_active', 'firstboot_unit', 'firstboot_journal',
            'resume_unit', 'resume_journal', 'resume_durable_log', 'resume_marker_present', 'proc_cmdline', 'docker_package_holds'}
KERNEL = re.compile(r'\d+\.\d+\.\d+-[A-Za-z0-9_.+-]+')
FINGERPRINT = re.compile(r'(?:[0-9A-F]{2}:){31}[0-9A-F]{2}')


def validate(observation, evidence, expected_source, expected_image, transport_exit=0):
    rows = []

    def record(name, passed):
        rows.append({'step': 'independent', 'check': name, 'result': 'pass' if passed else 'fail',
                     'detail': 'independent required evidence validated' if passed else 'required evidence missing, invalid or contradictory'})

    def read(name):
        path = evidence / name
        if path.stat().st_size > 1024 * 1024:
            raise ValueError('evidence too large')
        return path.read_text(encoding='utf-8').strip()

    integrity = (transport_exit == 0 and observation.get('schema_version') == 1
                 and observation.get('errors') == {} and REQUIRED <= observation.get('values', {}).keys()
                 and set(observation.get('required_fields', [])) == REQUIRED)
    record('postcheck-command-integrity', integrity)
    if not integrity:
        return rows
    v = observation['values']

    def check(name, predicate):
        try:
            record(name, predicate() is True)
        except Exception:
            record(name, False)

    def boot():
        before, after = read('esxi-boot-id-before.txt'), read('esxi-boot-id-after.txt')
        return all(str(uuid.UUID(value)) == value for value in (before, after, v['boot_id'])) and before != after == v['boot_id']

    def kernel():
        before, after = read('03-kernel-before.txt').splitlines(), read('07-kernel-after.txt').splitlines()
        return (len(before) == len(after) == 2 and all(KERNEL.fullmatch(x[0]) and x[1].startswith('#') for x in (before, after))
                and after == [v['kernel'], v['kernel_version']])

    def source():
        info = v['build_info']
        return (info['source']['git_commit'] == expected_source and info['source']['git_dirty'] is False
                and info['console']['source_git_commit'] == expected_source
                and info['console']['source_git_dirty'] is False
                and info['application']['index_digest'] == expected_image == v['app_image_id'] == read('08-image.txt')
                and info == json.loads(read('03-build-info.json')))

    def firstboot():
        unit = v['firstboot_unit']
        markers = set(v['done_markers'])
        return (unit['LoadState'] == 'loaded' and unit['ConditionResult'] in ('no', 'false')
                and unit['ExecMainStartTimestampMonotonic'] == '0'
                and markers == set(read('03-state-files.txt').splitlines())
                and markers == {'access.done', 'agent.done', 'complete.done', 'console.done', 'images.done', 'install.done', 'ovf.done'}
                and not re.search(r'step .*: done', v['firstboot_journal']))

    def resume():
        unit, journal = v['resume_unit'], v['resume_journal']
        durable = v['resume_durable_log']
        observed = datetime.datetime.fromisoformat(observation['captured_at']).timestamp()
        boot = durable['boot_start_epoch']
        if type(boot) is not int or not 0 < boot <= observed:
            return False
        current_lines = []
        for line in durable['lines']:
            timestamp = datetime.datetime.strptime(line.split()[0], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
            if boot <= timestamp <= observed and '[resume-stack]' in line:
                current_lines.append(line)
        current = journal + '\n' + '\n'.join(current_lines)
        return (unit['LoadState'] == 'loaded' and unit['Result'] == 'success' and unit['ExecMainStatus'] == '0'
                and int(unit['ExecMainStartTimestampMonotonic']) > 0 and v['resume_marker_present'] is False
                and 'stack started after the maintenance reboot' in current
                and re.search(r'holding .* and the maintenance agent lock', current) is not None)

    def policy():
        mutation = read('09-post-backup-mutation-name.txt')
        rules = json.loads(read('08-policy.json'))['rules']
        return (re.fullmatch(r'esxi-post-backup-block-\d+-\d+', mutation) is not None
                and not any(r.get('name') == mutation for r in rules)
                and any(r.get('name') == 'lab-allow-example' and r.get('enabled') is True for r in rules)
                and read('08-login.txt').splitlines()[-1] == '200'
                and read('08-enforce.txt').splitlines() == ['allowed 200', 'denied 403'])

    def ca():
        values = [read(name) for name in ('05-ca-fingerprint.txt', '09-ca-fingerprint.txt', '08-ca-fingerprint.txt')]
        return all(FINGERPRINT.fullmatch(value) for value in values) and len(set(values)) == 1

    def categories():
        values = [read(name) for name in ('05b-lookups-before.txt', '09-category-lookups.txt', '08-lookups-after.txt')]
        lines = values[0].splitlines()
        return (len(set(values)) == 1 and len(lines) >= 2
                and all(re.fullmatch(r'\S+ category=.* tier=(?:community|saas|none) matchedBy=.*', line) for line in lines)
                and any(re.fullmatch(r'\S+ category=\S+ tier=community matchedBy=\S+', line) for line in lines))

    check('root-observation', lambda: v['uid'] == 0)
    check('reboot-identity', boot)
    check('kernel-observation', kernel)
    check('source-image-identity', source)
    check('agent-version-active', lambda: v['agent_active'] == 'active' and v['agent_version'] == v['build_info']['application']['app_version_file'])
    check('firstboot-not-rerun', firstboot)
    check('locked-stack-resume', resume)
    check('docker-package-holds', lambda: {'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-compose-plugin'} <= set(v['docker_package_holds']))
    check('restored-policy-persistence', policy)
    check('ca-identity', ca)
    check('meaningful-category-persistence', categories)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--collect', action='store_true')
    mode.add_argument('--observation', type=Path)
    parser.add_argument('--bind')
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location('postcheck_bootstrap', HERE / 'bootstrap-checks.py')
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    lab = bootstrap.module.Lab(args.scope)
    bootstrap.private_directory(lab)
    output = lab.ev / 'independent-checks.jsonl'
    if output.exists():
        raise ValueError('independent checks already exist; preserve the prior run')
    destination = lab.sec / 'independent-postcheck.json'
    if args.collect:
        if not args.bind or destination.exists():
            raise ValueError('bind required; observation must not already exist')
        guest = (HERE / 'independent-postcheck-guest.py').read_bytes()
        script = b"python3 - <<'CULVERT_INDEPENDENT_POSTCHECK'\n" + guest + b'\nCULVERT_INDEPENDENT_POSTCHECK\n'
        try:
            result = subprocess.run([sys.executable, str(HERE / 'console-priv.py'), '--scope', str(args.scope),
                                     '--bind', args.bind, '--timeout', '480'], input=script,
                                    capture_output=True, timeout=600)
            raw, transport_exit = result.stdout, result.returncode
        except subprocess.TimeoutExpired:
            raw, transport_exit = b'', 90
        if len(raw) > 4 * 1024 * 1024:
            raise ValueError('postcheck output exceeded bound')
        try:
            observation = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            observation = {}
        envelope = {'transport_exit': transport_exit, 'observation': observation}
        with destination.open('x', encoding='utf-8') as out:
            json.dump(envelope, out)
    else:
        if not args.observation.resolve().is_relative_to(lab.sec.resolve()) or args.observation.stat().st_size > 4 * 1024 * 1024:
            raise ValueError('observation must be bounded private run evidence')
        envelope = json.loads(args.observation.read_text(encoding='utf-8'))
    rows = validate(envelope['observation'], lab.ev, lab.c['source_sha'], lab.c['image_id'], envelope['transport_exit'])
    with output.open('x', encoding='utf-8') as out:
        for row in rows:
            out.write(json.dumps(row) + '\n')
    for row in rows:
        print(row['result'].upper() + ': ' + row['check'])
    return 1 if any(row['result'] != 'pass' for row in rows) else 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Independent postcheck blocked; preserve private evidence; no guest mutation or retry.', file=sys.stderr)
        sys.exit(90)
