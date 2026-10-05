#!/usr/bin/env python3
"""LAB guest evidence, read-only. Output is PRIVATE and must never enter chat.

Run via already authenticated recovery heredoc. No installation, daemon changes,
network probes, backup listings, environment dumps or unrestricted Docker inspect.
Correlation reads identities first and samples both clocks last. Full is bounded
and retains command errors; successful collection is not readiness qualification.
"""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import threading
import time

MIB = 1024 * 1024
OUTPUT_LIMIT = 7 * MIB
SAMPLER_LIMIT = 8 * MIB
SAMPLER = Path('/run/culvert-lab-boot-sampler/samples.jsonl')
UNITS = ('local-fs.target', 'sysinit.target', 'basic.target', 'network-online.target',
         'cloud-init-local.service', 'cloud-init.service', 'cloud-final.service',
         'apparmor.service', 'systemd-journal-flush.service', 'e2scrub_reap.service',
         'snapd.service', 'snapd.seeded.service', 'multipathd.service',
         'lvm2-monitor.service', 'systemd-udev-settle.service', 'dbus.service',
         'systemd-networkd.service', 'systemd-networkd-wait-online.service',
         'containerd.service', 'docker.service', 'culvert-maint.service',
         'culvert-firstboot.service', 'culvert-stack-resume.service', 'ssh.service',
         'culvert-lab-boot-sampler.service')
PROPERTIES = ('Id', 'LoadState', 'ActiveState', 'SubState', 'Result', 'ExecMainStatus',
              'After', 'Before', 'Requires', 'Wants', 'TriggeredBy', 'FragmentPath',
              'DropInPaths', 'ActiveEnterTimestampMonotonic',
              'InactiveExitTimestampMonotonic', 'ExecMainStartTimestampMonotonic',
              'ExecMainExitTimestampMonotonic', 'CPUUsageNSec', 'MemoryPeak',
              'TasksCurrent', 'IOReadBytes', 'IOReadOperations', 'IOWriteBytes', 'IOWriteOperations', 'ExecStartPre', 'CPUQuotaPerSecUSec',
              'CPUWeight', 'IOWeight', 'TimeoutStartUSec')
HASH_FILES = ('/var/lib/culvert-appliance/build-info.json', '/srv/culvert/docker-compose.yml',
              '/srv/culvert/docker-compose.maint-agent.yml', '/etc/docker/daemon.json',
              '/etc/containerd/config.toml', '/etc/culvert-maint/config.toml',
              '/etc/cloud/cloud.cfg.d/90-culvert-appliance.cfg')


def clock_sample():
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return {'monotonic_before_ns': before, 'realtime_ns': realtime,
            'monotonic_after_ns': after, 'bracket_ns': after - before}


def read_bounded(path, limit):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('regular file required')
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('file bound exceeded')
    return raw


def correlation(include_image=False, runner=None):
    boot = read_bounded(Path('/proc/sys/kernel/random/boot_id'), 64).decode().strip()
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot):
        raise ValueError('invalid boot identity')
    build = json.loads(read_bounded(Path('/var/lib/culvert-appliance/build-info.json'), 65536))
    source = build['source']['git_commit']
    if not re.fullmatch(r'[a-f0-9]{40}', source):
        raise ValueError('invalid source identity')
    value = {'boot_id': boot, 'source_revision': source,
             'source_dirty': build['source'].get('git_dirty')}
    if include_image:
        value['image_observation'] = (runner or command)(
            ['docker', 'inspect', '--format', '{{.Image}}', 'culvert'], 5, 4096)
    # No command or file read is placed inside this clock bracket.
    value['clock'] = clock_sample()
    return value


def command(argv, timeout, limit):
    row = {'argv': argv, 'timeout_seconds': timeout, 'capture_limit_bytes': limit,
           'started': clock_sample()}
    env = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C', 'HOME': '/root'}
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, env=env, start_new_session=True)
    except OSError:
        return dict(row, result='spawn_failed', ended=clock_sample())
    expired = threading.Event()

    def kill(timed_out=False):
        if timed_out:
            expired.set()
        try:
            if os.name == 'posix':
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
        except ProcessLookupError:
            pass

    timer = threading.Timer(timeout, lambda: kill(True))
    timer.start()
    try:
        raw = process.stdout.read(limit + 1)
        oversized = len(raw) > limit
        if oversized:
            kill()
        code = process.wait(timeout=3)
        row.update(result='output_limit' if oversized else 'timeout' if expired.is_set()
                   else 'ok' if code == 0 else 'command_failed', exit_code=code,
                   timed_out=expired.is_set(), truncated=oversized,
                   captured_bytes=min(len(raw), limit), output=raw[:limit].decode('utf-8', 'replace'))
    finally:
        timer.cancel()
        if process.poll() is None:
            kill()
            process.wait(timeout=3)
        process.stdout.close()
        row['ended'] = clock_sample()
    return row


def sampler_payload(raw, boot_id):
    if len(raw) > SAMPLER_LIMIT:
        raise ValueError('sampler exceeds bound')
    rows = [json.loads(line) for line in raw.splitlines()]
    if any(not isinstance(x, dict) for x in rows):
        raise ValueError('invalid sampler row')
    if (not rows or rows[0].get('kind') != 'header' or rows[0].get('schema') != 1
            or rows[0].get('boot_id') != boot_id):
        raise ValueError('sampler identity mismatch')
    if any(x.get('kind') == 'sample' and x.get('boot_id') != boot_id for x in rows):
        raise ValueError('sampler changed boot')
    if any(x.get('kind') != 'sample' for x in rows[1:-1]):
        raise ValueError('invalid sampler sequence')
    complete = rows[-1].get('kind') == 'end'
    if len(rows) > 1 and rows[-1].get('kind') not in ('sample', 'end'):
        raise ValueError('invalid final sampler row')
    if complete and rows[-1].get('reason') not in ('deadline', 'byte_limit'):
        raise ValueError('invalid sampler end reason')
    status = 'byte_limit' if complete and rows[-1]['reason'] == 'byte_limit' else 'ok' if complete else 'active_snapshot'
    return {'result': status, 'recording_complete': complete,
            'recording_end_reason': rows[-1].get('reason') if complete else None,
            'encoding': 'gzip+base64', 'uncompressed_bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest(), 'row_count': len(rows),
            'data': base64.b64encode(gzip.compress(raw, mtime=0)).decode('ascii')}


def command_plan(boot_epoch):
    since = str(boot_epoch)  # Docker accepts Unix seconds, not journalctl's @seconds syntax.
    inspect_format = ('{"id":{{json .Id}},"image_id":{{json .Image}},'
                      '"started_at":{{json .State.StartedAt}},"status":{{json .State.Status}},'
                      '"health":{{json .State.Health}},"restart_count":{{json .RestartCount}},'
                      '"networks":{{json .NetworkSettings.Networks}}}')
    plan = [
        ('unit_properties', ['systemctl', 'show', *UNITS, *('--property=' + x for x in PROPERTIES)], 15, 300000),
        ('critical_chain', ['systemd-analyze', 'critical-chain', 'docker.service', 'culvert-stack-resume.service'], 10, 65536),
        ('boot_time', ['systemd-analyze', 'time'], 10, 8192),
        ('unit_logs', ['journalctl', '-b', '--no-pager', '-o', 'short-monotonic', '-n', '3000',
                       *[arg for unit in UNITS if unit.endswith('.service') for arg in ('-u', unit)]], 20, MIB),
        ('kernel_logs', ['journalctl', '-b', '-k', '--no-pager', '-o', 'short-monotonic', '-n', '1500'], 15, 400000),
        ('cloud_init_timing', ['cloud-init', 'analyze', 'show'], 10, 150000),
        ('package_versions', ['dpkg-query', '-W', '-f=${binary:Package}=${Version}\n',
                              'docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-compose-plugin',
                              'cloud-init', 'snapd', 'apparmor', 'e2fsprogs', 'open-vm-tools'], 10, 16384),
        ('kernel_version', ['uname', '-r'], 5, 4096),
        ('compose_version', ['docker', 'compose', 'version', '--short'], 10, 8192),
        ('clamav_signature_version', ['docker', 'exec', 'culvert-clamav', 'clamdscan', '--version'], 10, 8192),
        ('clamav_signature_files', ['docker', 'exec', 'culvert-clamav', 'sh', '-c',
                                   "stat -c '%n %s %Y' /var/lib/clamav/*.cvd /var/lib/clamav/*.cld"], 10, 16384)]
    for name in ('culvert', 'culvert-clamav'):
        plan.extend([
            (name + '_state', ['docker', 'inspect', '--format', inspect_format, name], 10, 80000),
            (name + '_logs', ['docker', 'logs', '--timestamps', '--since', since, '--tail', '1500', name], 15, 600000)])
    plan.append(('docker_events', ['docker', 'events', '--since', since, '--until', str(int(time.time())),
                                  '--filter', 'type=container', '--format',
                                  '{"timeNano":{{.TimeNano}},"action":{{json .Action}},"id":{{json .ID}}}'], 10, 180000))
    return plan


def full_report(identity, runner=command, duration=150):
    deadline = time.monotonic() + duration
    result = {'identity': identity, 'commands': [], 'file_hashes': [],
              'query_limits': 'Journals/logs retain bounded tails; absence outside retained ranges is unproven.'}
    result['clamav_probe_configuration'] = {'result': 'unavailable_or_invalid'}
    result['sampler_installation_receipt'] = {'result': 'unavailable_or_invalid'}
    try:
        config_path = Path('/usr/local/libexec/culvert-lab-boot-sampler.clamav.json')
        info = config_path.lstat()
        if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or not stat.S_ISREG(info.st_mode):
            raise ValueError('private sampler configuration required')
        config_raw = read_bounded(config_path, 4096)
        result['clamav_probe_configuration'] = {'result': 'ok', 'sha256': hashlib.sha256(config_raw).hexdigest(),
                                               'configuration': json.loads(config_raw)}
    except (OSError, ValueError, UnicodeError):
        pass
    try:
        receipt_path = Path('/usr/local/libexec/culvert-lab-boot-sampler.receipt.json')
        info = receipt_path.lstat()
        if stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or not stat.S_ISREG(info.st_mode):
            raise ValueError('private sampler receipt required')
        receipt_raw = read_bounded(receipt_path, 8192)
        result['sampler_installation_receipt'] = {'result': 'ok', 'sha256': hashlib.sha256(receipt_raw).hexdigest(),
                                                 'receipt': json.loads(receipt_raw)}
    except (OSError, ValueError, UnicodeError):
        pass
    for path in HASH_FILES:
        row = {'path': path}
        try:
            raw = read_bounded(Path(path), MIB)
            row.update(result='ok', bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        except (OSError, ValueError):
            row['result'] = 'unavailable_or_over_bound'
        result['file_hashes'].append(row)
    try:
        info, parent = SAMPLER.lstat(), SAMPLER.parent.lstat()
        if (stat.S_IMODE(info.st_mode) != 0o600 or info.st_uid != 0 or info.st_nlink != 1
                or not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                or stat.S_IMODE(parent.st_mode) != 0o700):
            raise ValueError('sampler ownership/mode')
        result['sampler'] = sampler_payload(read_bounded(SAMPLER, SAMPLER_LIMIT), identity['boot_id'])
    except (OSError, ValueError, KeyError, UnicodeError):
        result['sampler'] = {'result': 'unavailable_or_invalid', 'recording_complete': False}
    raw_stat = read_bounded(Path('/proc/stat'), 128 * 1024).decode('ascii')
    match = re.search(r'^btime ([0-9]{1,12})$', raw_stat, re.MULTILINE)
    if not match:
        raise ValueError('boot time unavailable')
    result['boot_epoch_seconds'] = int(match[1])
    for name, argv, timeout, limit in command_plan(int(match[1])):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            row = {'result': 'collection_deadline', 'argv': argv}
        else:
            row = runner(argv, min(timeout, remaining), limit)
        result['commands'].append(dict(row, name=name))
    result['finished_clock'] = clock_sample()
    return result


def encode_report(report, limit=OUTPUT_LIMIT):
    """Bound encoded bytes before writing. Omitted payloads remain explicit errors."""
    encode = lambda: (json.dumps(report, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
    report['output_truncated'] = False
    raw = encode()
    payloads = [(row, 'output') for row in report.get('full', {}).get('commands', []) if 'output' in row]
    sampler = report.get('full', {}).get('sampler', {})
    if 'data' in sampler:
        payloads.append((sampler, 'data'))
    for row, key in sorted(payloads, key=lambda pair: len(pair[0][pair[1]]), reverse=True):
        if len(raw) <= limit:
            break
        value = row.pop(key)
        row.update(payload_omitted=True, omitted_characters=len(value),
                   result_before_omission=row.get('result'), result='total_output_limit')
        report['output_truncated'] = True
        raw = encode()
    if len(raw) > limit:
        raise ValueError('metadata exceeds output bound')
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('correlation', 'full'), default='correlation')
    parser.add_argument('--include-image', action='store_true')
    args = parser.parse_args(argv)
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise ValueError('authenticated Linux root required')
    identity = correlation(args.include_image)
    report = {'schema_version': 1, 'mode': args.mode, 'private_output': True, 'identity': identity,
              'note': 'Read-only diagnostic capture; no readiness or lock-ownership success inferred.'}
    if args.mode == 'full':
        report['full'] = full_report(identity)
    raw = encode_report(report)
    written = sys.stdout.buffer.write(raw)
    if written != len(raw):
        raise OSError('short output write')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('BLOCKED: bounded private guest collection failed', file=sys.stderr)
        sys.exit(1)
