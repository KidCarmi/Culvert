#!/usr/bin/env python3
"""Read-only post-reboot observations. Full output is PRIVATE lab evidence."""
import datetime
import json
import os
from pathlib import Path
import subprocess
import threading


LIMIT = 1024 * 1024


def command(args):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timer = threading.Timer(25, process.kill)
    timer.start()
    try:
        raw = process.stdout.read(LIMIT + 1)
        if len(raw) > LIMIT:
            process.kill()
        code = process.wait(timeout=5)
        if code != 0 or len(raw) > LIMIT:
            raise ValueError('required command failed or exceeded its bound')
        return raw.decode('utf-8', errors='strict').rstrip('\n')
    finally:
        timer.cancel()
        process.stdout.close()


def read_file(path, limit=128 * 1024):
    with Path(path).open('rb') as source:
        raw = source.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('required file exceeded its bound')
    return raw.decode('utf-8').strip()


def unit(name):
    fields = ('LoadState', 'ActiveState', 'Result', 'ExecMainStatus', 'ConditionResult',
              'ExecMainStartTimestamp', 'ExecMainStartTimestampMonotonic')
    raw = command(['systemctl', 'show', name] + ['--property=' + field for field in fields])
    return dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)


def resume_log():
    boot = int(next(line.split()[1] for line in read_file('/proc/stat').splitlines() if line.startswith('btime ')))
    now = datetime.datetime.now(datetime.timezone.utc).timestamp()
    lines = []
    for line in read_file('/var/log/culvert-os-update.log', LIMIT).splitlines():
        if '[resume-stack]' not in line:
            continue
        timestamp = datetime.datetime.strptime(line.split()[0], '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=datetime.timezone.utc).timestamp()
        if boot <= timestamp <= now:
            lines.append(line)
    return {'boot_start_epoch': boot, 'lines': lines}


def collect():
    values, errors = {}, {}
    tasks = {
        'uid': os.geteuid,
        'boot_id': lambda: read_file('/proc/sys/kernel/random/boot_id'),
        'kernel': lambda: command(['uname', '-r']),
        'kernel_version': lambda: command(['uname', '-v']),
        'done_markers': lambda: sorted(p.name for p in Path('/var/lib/culvert-appliance/state').iterdir()
                                       if p.is_file() and p.name.endswith('.done')),
        'build_info': lambda: json.loads(read_file('/var/lib/culvert-appliance/build-info.json')),
        'app_image_id': lambda: command(['docker', 'inspect', '-f', '{{.Image}}', 'culvert']),
        'agent_version': lambda: command(['culvert-maint', '--version']),
        'agent_active': lambda: command(['systemctl', 'is-active', 'culvert-maint']),
        'firstboot_unit': lambda: unit('culvert-firstboot.service'),
        'firstboot_journal': lambda: command(['journalctl', '-b', '-u', 'culvert-firstboot.service',
                                            '--no-pager', '-o', 'short-monotonic']),
        'resume_unit': lambda: unit('culvert-stack-resume.service'),
        'resume_journal': lambda: command(['journalctl', '-b', '-u', 'culvert-stack-resume.service',
                                         '--no-pager', '-o', 'short-monotonic']),
        'resume_durable_log': resume_log,
        'resume_marker_present': lambda: os.path.lexists('/var/lib/culvert-appliance/state/stack-resume-on-boot'),
        'proc_cmdline': lambda: read_file('/proc/cmdline'),
        'docker_package_holds': lambda: command(['apt-mark', 'showhold']).splitlines(),
    }
    for name, task in tasks.items():
        try:
            values[name] = task()
        except Exception:
            errors[name] = 'required observation failed; no raw error exported'
    return {'schema_version': 1, 'captured_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'required_fields': list(tasks), 'values': values, 'errors': errors}


if __name__ == '__main__':
    observation = collect()
    encoded = json.dumps(observation, separators=(',', ':'))
    if len(encoded.encode('utf-8')) > 3 * 1024 * 1024:
        observation['values'] = {}
        observation['errors']['collection'] = 'aggregate observation exceeded its bound'
        encoded = json.dumps(observation, separators=(',', ':'))
    print(encoded)
    raise SystemExit(1 if observation['errors'] else 0)
