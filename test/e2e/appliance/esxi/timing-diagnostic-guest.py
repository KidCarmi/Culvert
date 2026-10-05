#!/usr/bin/env python3
"""Run only through already authenticated local recovery, never operator SSH.

Bounded read-only application diagnostics: timestamps, systemd state, I/O
pressure, direct-agent backup-list and the same one-shot Compose listing.
Listing starts temporary CLI containers, as the real endpoint does; it never
changes application data. Run outside the primary qualification request to
avoid competing with it. No response bodies, filenames, logs, headers, cookies,
environment values, or credentials are exported. No installation required.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time

LIMIT = 1024 * 1024
UNITS = ('docker.service', 'containerd.service', 'culvert-maint.service',
         'culvert-firstboot.service', 'culvert-stack-resume.service',
         'ssh.service', 'systemd-networkd-wait-online.service')
PROPERTIES = ('Id', 'ActiveState', 'SubState', 'ExecMainStatus',
              'ActiveEnterTimestampMonotonic', 'ExecMainStartTimestampMonotonic',
              'ExecMainExitTimestampMonotonic')


def stamp():
    return {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'monotonic_ns': time.monotonic_ns()}


def command(args, timeout, cwd=None):
    row = {'started': stamp()}
    started = time.monotonic()
    # Exclude inherited Docker/Compose settings and credential-bearing env.
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/root'}
    try:
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, cwd=cwd, env=env, start_new_session=True)
    except OSError:
        row.update(result='spawn_failed', ended=stamp(), elapsed_seconds=round(time.monotonic() - started, 6))
        return row, b''
    expired = threading.Event()

    def kill():
        expired.set()
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    timer = threading.Timer(timeout, kill)
    timer.start()
    try:
        raw = process.stdout.read(LIMIT + 1)
        oversized = len(raw) > LIMIT
        if oversized:
            kill()
        code = process.wait(timeout=3)
        result = 'oversize' if oversized else 'timeout' if expired.is_set() else 'ok' if code == 0 else 'command_failed'
        row.update(result=result, exit_code=code)
        return row, raw if result == 'ok' else b''
    finally:
        timer.cancel()
        if process.poll() is None:
            kill()
            process.wait(timeout=3)
        process.stdout.close()
        row.update(ended=stamp(), elapsed_seconds=round(time.monotonic() - started, 6))


def parse_units(raw):
    units = []
    for section in raw.decode('ascii').strip().split('\n\n'):
        fields = dict(line.split('=', 1) for line in section.splitlines() if '=' in line)
        if fields.get('Id') not in UNITS:
            continue
        item = {'unit': fields['Id']}
        for key in PROPERTIES[1:]:
            value = fields.get(key, '')
            if key.endswith('Monotonic') or key == 'ExecMainStatus':
                item[key] = int(value) if re.fullmatch(r'[0-9]{1,20}', value) else None
            else:
                item[key] = value if value in {'active', 'inactive', 'failed', 'activating',
                    'deactivating', 'reloading', 'maintenance', 'dead', 'running', 'exited',
                    'start', 'start-pre', 'start-post', 'stop', 'stop-sigterm', 'stop-sigkill',
                    'auto-restart', 'listening'} else 'unknown'
        units.append(item)
    return units


def pressure(path=Path('/proc/pressure/io')):
    with path.open('rb') as stream:
        raw = stream.read(2049)
    if len(raw) > 2048:
        raise ValueError('pressure bound')
    rows = {}
    for line in raw.decode('ascii').splitlines():
        kind, *values = line.split()
        if kind not in ('some', 'full'):
            continue
        row = {}
        for field in values:
            key, value = field.split('=', 1)
            if key in ('avg10', 'avg60', 'avg300', 'total') and re.fullmatch(r'[0-9]{1,20}(\.[0-9]{1,6})?', value):
                row[key] = float(value) if '.' in value else int(value)
        rows[kind] = row
    return rows


def probes(timeout):
    return (
        ('agent_backups', ['curl', '--silent', '--max-time', str(timeout - 1),
                           '--unix-socket', '/run/culvert-maint/culvert-maint.sock',
                           '--output', '/dev/null', '--write-out', '%{http_code}',
                           'http://localhost/v1/backups'], None),
        ('compose_backups', ['docker', 'compose', '-f', '/srv/culvert/docker-compose.yml',
                             '--profile', 'cli', 'run', '--rm', 'cli', '--list-backups',
                             '--backup-dir', '/backup'], '/srv/culvert'),
    )


def listing_result(kind, raw):
    if kind == 'agent_backups':
        code = raw.decode('ascii')
        if not re.fullmatch(r'[1-5][0-9]{2}', code):
            raise ValueError('invalid http status')
        return {'http_status': int(code), 'listing_succeeded': code == '200'}
    value = json.loads(raw)
    if value is not None and not isinstance(value, list):
        raise ValueError('invalid listing')
    return {'listing_succeeded': True, 'entry_count': len(value or [])}


def collect(samples, timeout):
    yield {'event': 'guest_timing_started', **stamp(), 'schema_version': 1,
           'note': 'Diagnostic listings run sequentially; not contemporaneous primary-request timings.'}
    identity = {'event': 'boot_identity', **stamp()}
    try:
        with Path('/proc/sys/kernel/random/boot_id').open('rb') as stream:
            boot = stream.read(65).strip()
        if not re.fullmatch(rb'[0-9a-f-]{36}', boot):
            raise ValueError('invalid boot identity')
        identity.update(result='ok', sha256=hashlib.sha256(boot).hexdigest())
    except (ValueError, OSError):
        identity['result'] = 'unavailable'
    yield identity
    row, raw = command(['systemctl', 'show', *UNITS, *('--property=' + p for p in PROPERTIES)], 15)
    row['event'] = 'unit_timestamps'
    if row['result'] == 'ok':
        try:
            row['units'] = parse_units(raw)
        except (ValueError, UnicodeError):
            row['result'] = 'invalid_response'
    yield row
    for sample in range(samples):
        for kind, args, cwd in probes(timeout):
            pre = {'event': 'io_pressure', 'sample': sample, 'probe': kind, **stamp()}
            try:
                pre['values'] = pressure()
                pre['result'] = 'ok'
            except (ValueError, OSError, UnicodeError):
                pre['result'] = 'unavailable'
            yield pre
            row, raw = command(args, timeout, cwd)
            row.update(event='backup_timing', probe=kind, sample=sample)
            if kind == 'agent_backups' and row.get('exit_code') == 28:
                row['result'] = 'timeout'
            if row['result'] == 'ok':
                try:
                    row.update(listing_result(kind, raw))
                except (ValueError, UnicodeError):
                    row['result'] = 'invalid_response'
            yield row
    yield {'event': 'guest_timing_finished', **stamp()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=2)
    parser.add_argument('--timeout', type=int, default=25)
    args = parser.parse_args(argv)
    if (sys.platform != 'linux' or os.geteuid() != 0 or not 1 <= args.samples <= 3
            or not 5 <= args.timeout <= 30):
        raise ValueError('authenticated Linux root and bounded samples required')
    for row in collect(args.samples, args.timeout):
        print(json.dumps(row, separators=(',', ':')), flush=True)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print(json.dumps({'event': 'diagnostic_failed', 'result': 'failed', **stamp()}), flush=True)
        sys.exit(90)
