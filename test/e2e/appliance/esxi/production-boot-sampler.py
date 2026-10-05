#!/usr/bin/env python3
"""Disposable LAB boot observer. Never package in the deliverable appliance."""
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import time

INTERVAL = 2
DURATION = 900
MAX_BYTES = 8 * 1024 * 1024
MAX_PIDS = 2048
MAX_PROCESSES = 128
OUTPUT = Path('/run/culvert-lab-boot-sampler')
CLAMAV_CONFIG = Path('/usr/local/libexec/culvert-lab-boot-sampler.clamav.json')
IO_FIELDS = {'rchar', 'wchar', 'syscr', 'syscw', 'read_bytes', 'write_bytes', 'cancelled_write_bytes'}
PROCESS_NAMES = {'containerd', 'dockerd', 'docker', 'docker-compose', 'compose', 'clamd', 'freshclam'}
PROCESS_UNITS = {'culvert-stack-resume.service', 'cloud-init-local.service', 'cloud-init.service',
                 'cloud-config.service', 'cloud-final.service', 'e2scrub_reap.service',
                 'e2scrub_all.service', 'systemd-journal-flush.service', 'snapd.service', 'apparmor.service'}
LOCK_PATHS = {'os_update': Path('/run/culvert-os-update.lock'),
              'maintenance_agent': Path('/var/lib/culvert-maint/host-maintenance.lock')}


def bounded(path, limit):
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('observation bound exceeded')
    return raw.decode('ascii').strip()


def counters(raw):
    result = {}
    for line in raw.splitlines():
        name, value = line.split(':', 1)
        if name in IO_FIELDS and re.fullmatch(r'[0-9]{1,20}', value.strip()):
            result[name] = int(value)
    if set(result) != IO_FIELDS:
        raise ValueError('incomplete process IO counters')
    return result


def process_stat(raw, pid):
    # comm can contain spaces/parentheses. Only numeric stat fields are emitted.
    left, right = raw.find('('), raw.rfind(')')
    if left < 1 or right <= left or int(raw[:left].strip()) != pid:
        raise ValueError('invalid process stat')
    fields = raw[right + 1:].split()
    if len(fields) < 20 or fields[0] not in 'RSDZTWtXxKPI':
        raise ValueError('incomplete process stat')
    names = {'minor_faults': 7, 'child_minor_faults': 8, 'major_faults': 9,
             'child_major_faults': 10, 'user_ticks': 11, 'system_ticks': 12,
             'child_user_ticks': 13, 'child_system_ticks': 14, 'start_ticks': 19}
    result = {name: int(fields[index]) for name, index in names.items()}
    if any(value < 0 for value in result.values()):
        raise ValueError('negative process counter')
    result['state'] = fields[0]
    return result


def pressure(raw):
    result = {}
    for line in raw.splitlines():
        fields = line.split()
        if not fields or fields[0] not in ('some', 'full'):
            raise ValueError('invalid pressure row')
        values = dict(item.split('=', 1) for item in fields[1:])
        if (set(values) != {'avg10', 'avg60', 'avg300', 'total'}
                or not re.fullmatch(r'[0-9]{1,20}', values['total'])
                or not all(re.fullmatch(r'[0-9]{1,3}\.[0-9]{2}', values[key])
                           for key in ('avg10', 'avg60', 'avg300'))):
            raise ValueError('invalid pressure values')
        result[fields[0]] = {key: int(value) if key == 'total' else float(value)
                             for key, value in values.items()}
    if 'some' not in result:
        raise ValueError('empty pressure observation')
    return result


def disks(raw):
    result = []
    for line in raw.splitlines():
        fields = line.split()
        if (len(result) >= 512 or len(fields) < 14 or len(fields) > 20
                or not re.fullmatch(r'[A-Za-z0-9_.!-]{1,64}', fields[2])
                or not all(re.fullmatch(r'[0-9]{1,20}', value) for value in fields[:2] + fields[3:])):
            raise ValueError('invalid or oversized diskstats')
        result.append({'major': int(fields[0]), 'minor': int(fields[1]),
                       'device': fields[2], 'counters': [int(x) for x in fields[3:]]})
    return result


def parse_clamav_config(data):
    if (not isinstance(data, dict) or set(data) != {'schema', 'address', 'port', 'container_id'}
            or type(data['schema']) is not int or data['schema'] != 1
            or type(data['port']) is not int or data['port'] != 3310
            or not isinstance(data['container_id'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', data['container_id'])):
        raise ValueError('invalid ClamAV endpoint identity')
    address = ipaddress.IPv4Address(data['address'])
    if (not address.is_private or address.is_loopback or address.is_link_local
            or address.is_unspecified or address.is_multicast or address.is_reserved
            or str(address) != data['address']):
        raise ValueError('ClamAV endpoint must be an explicit private bridge IPv4')
    return data


def load_clamav_config(path=CLAMAV_CONFIG):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError('root-owned private ClamAV endpoint required')
    return parse_clamav_config(json.loads(bounded(path, 4096)))


def clamav_ping(config):
    started = time.monotonic_ns()
    result = {'pong': False, 'error': None, 'started_monotonic_ns': started}
    deadline = time.monotonic() + 0.25
    try:
        with socket.create_connection((config['address'], config['port']), timeout=0.25) as connection:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError()
            connection.settimeout(remaining)
            connection.sendall(b'nPING\n')
            reply = b''
            while len(reply) < 32:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError()
                connection.settimeout(remaining)
                chunk = connection.recv(32 - len(reply))
                if not chunk:
                    break
                reply += chunk
                if b'\n' in reply or b'\0' in reply:
                    break
            result['pong'] = reply in (b'PONG\n', b'PONG\0')
            if not result['pong']:
                result['error'] = 'unexpected_reply'
    except TimeoutError:
        result['error'] = 'timeout'
    except OSError:
        result['error'] = 'connection_failed'
    result['ended_monotonic_ns'] = time.monotonic_ns()
    result['elapsed_ns'] = result['ended_monotonic_ns'] - started
    return result


class Collector:
    def __init__(self, proc=Path('/proc'), clock=time.monotonic, boot_id=None, clamav_config=None):
        self.proc, self.clock = proc, clock
        self.boot_id = boot_id or bounded(proc / 'sys/kernel/random/boot_id', 64)
        self.clamav_config = clamav_config

    def locks(self):
        result = {name: {'available': False, 'held': None, 'holder_pids': []} for name in LOCK_PATHS}
        try:
            rows = bounded(self.proc / 'locks', 64 * 1024).splitlines()
            if len(rows) > 1024:
                return result
        except (OSError, ValueError, UnicodeError):
            return result
        for name, path in LOCK_PATHS.items():
            try:
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode):
                    continue
                identity = (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
                holders = []
                for line in rows:
                    fields = line.split()
                    if len(fields) < 8 or fields[1] == '->':
                        continue  # A queued waiter does not own the lock.
                    major, minor, inode = fields[5].split(':')
                    if (int(major, 16), int(minor, 16), int(inode)) == identity:
                        if fields[1] not in ('FLOCK', 'POSIX', 'OFDLCK') or not re.fullmatch(r'-?[0-9]{1,10}', fields[4]):
                            raise ValueError('invalid matching lock owner')
                        holders.append(int(fields[4]))
                result[name] = {'available': True, 'held': bool(holders),
                                'holder_pids': sorted(set(pid for pid in holders if pid > 0))}
            except (OSError, ValueError, IndexError):
                continue
        return result

    def processes(self):
        result, scanned, truncated, unavailable = [], 0, False, 0
        deadline = self.clock() + 0.25
        with os.scandir(self.proc) as entries:
            for count, entry in enumerate(entries):
                if count >= 4096 or scanned >= MAX_PIDS or len(result) >= MAX_PROCESSES or self.clock() >= deadline:
                    truncated = True
                    break
                if not entry.name.isascii() or not entry.name.isdecimal():
                    continue
                scanned += 1
                base = self.proc / entry.name
                try:
                    comm = bounded(base / 'comm', 64)
                    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', comm):
                        continue
                    selected = comm in PROCESS_NAMES
                    selected_unit = None
                    if not selected:
                        group = bounded(base / 'cgroup', 4096)
                        units = set(part for line in group.splitlines()
                                    for part in line.split(':', 2)[-1].split('/')) & PROCESS_UNITS
                        selected_unit = sorted(units)[0] if units else None
                        selected = selected_unit is not None
                    if not selected:
                        continue
                    pid = int(entry.name)
                    state = process_stat(bounded(base / 'stat', 4096), pid)
                    io = counters(bounded(base / 'io', 4096))
                    wchan = bounded(base / 'wchan', 256)
                    if not re.fullmatch(r'[A-Za-z0-9_.]{1,128}', wchan):
                        raise ValueError('invalid wait channel')
                    # Reject PID reuse across the multiple proc reads.
                    if process_stat(bounded(base / 'stat', 4096), pid)['start_ticks'] != state['start_ticks']:
                        raise ValueError('process identity changed')
                    result.append({'comm': comm, 'pid': pid, 'unit': selected_unit,
                                   'stat': state, 'io': io, 'wchan': wchan})
                except (OSError, ValueError, UnicodeError):
                    unavailable += 1
        return {'processes': sorted(result, key=lambda item: item['pid']), 'scanned': scanned,
                'scan_truncated': truncated, 'unavailable': unavailable}

    def sample(self):
        row = {'kind': 'sample', 'boot_id': self.boot_id, 'monotonic_ns': time.monotonic_ns(),
               'realtime_ns': time.time_ns(),
               'realtime': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'errors': []}
        tasks = {'pressure_' + name: lambda name=name: pressure(bounded(self.proc / 'pressure' / name, 2048))
                 for name in ('cpu', 'io', 'memory')}
        tasks.update(diskstats=lambda: disks(bounded(self.proc / 'diskstats', 128 * 1024)),
                     process_observation=self.processes, maintenance_locks=self.locks)
        try:
            with (self.proc / 'stat').open('rb') as source:
                first = source.readline(4096).decode('ascii').split()
            if first[0] != 'cpu' or not 9 <= len(first) <= 11 or not all(x.isdecimal() for x in first[1:]):
                raise ValueError('invalid aggregate CPU counters')
            row['cpu_ticks'] = [int(value) for value in first[1:]]
            row['iowait_ticks'] = row['cpu_ticks'][4]
        except (OSError, ValueError, UnicodeError, IndexError):
            row['errors'].append('cpu')
        for name, task in tasks.items():
            try:
                row[name] = task()
            except (OSError, ValueError, UnicodeError):
                row['errors'].append(name)
        row['clamav_ping'] = (clamav_ping(self.clamav_config) if self.clamav_config else
                              {'pong': None, 'error': 'not_configured'})
        row['sample_elapsed_ns'] = time.monotonic_ns() - row['monotonic_ns']
        return row


def write_row(stream, row, used, limit=MAX_BYTES):
    encoded = (json.dumps(row, separators=(',', ':'), ensure_ascii=True) + '\n').encode('ascii')
    if used + len(encoded) > limit:
        return None
    stream.write(encoded)
    stream.flush()
    return used + len(encoded)


def runtime_tmpfs(mounts, output=OUTPUT):
    output_path = output.as_posix()
    candidates = []
    for line in mounts.splitlines():
        columns, filesystem = line.split(' - ', 1)
        mountpoint = columns.split()[4]
        if output_path == mountpoint or output_path.startswith(mountpoint.rstrip('/') + '/'):
            candidates.append((len(mountpoint), filesystem.split()[0]))
    return bool(candidates) and max(candidates)[1] == 'tmpfs'


def record(stream, collector, header, clock=time.monotonic, sleep=time.sleep, duration=DURATION, limit=MAX_BYTES):
    if not 0 < duration <= DURATION or not 1024 <= limit <= MAX_BYTES:
        raise ValueError('invalid recorder limits')
    start = clock()
    used = write_row(stream, header, 0, limit - 512)
    if used is None:
        raise ValueError('header exceeds recorder bound')
    reason, samples = 'deadline', 0
    while clock() < start + duration:
        updated = write_row(stream, collector.sample(), used, limit - 512)
        if updated is None:
            reason = 'byte_limit'
            break
        used, samples = updated, samples + 1
        # Skip missed slots rather than burst/catch up during contention.
        next_sample = start + (int((clock() - start) / INTERVAL) + 1) * INTERVAL
        wait = min(next_sample, start + duration) - clock()
        if wait > 0:
            sleep(wait)
    write_row(stream, {'kind': 'end', 'reason': reason, 'samples': samples,
                       'monotonic_ns': time.monotonic_ns()}, used, limit)


def main():
    if os.geteuid() != 0:
        raise ValueError('root-only diagnostic')
    info = OUTPUT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('private runtime directory required')
    mounts = bounded(Path('/proc/self/mountinfo'), 256 * 1024)
    if not runtime_tmpfs(mounts):
        raise ValueError('runtime output must be tmpfs')
    source_sha = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    clamav_config = load_clamav_config()
    boot_id = bounded(Path('/proc/sys/kernel/random/boot_id'), 64)
    if not re.fullmatch(r'[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', boot_id):
        raise ValueError('invalid boot identity')
    descriptor = os.open(OUTPUT / 'samples.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'wb') as output:
        record(output, Collector(boot_id=boot_id, clamav_config=clamav_config), {'kind': 'header', 'schema': 1, 'boot_id': boot_id,
                                     'sampler_sha256': source_sha, 'interval_seconds': INTERVAL,
                                     'duration_seconds': DURATION, 'max_bytes': MAX_BYTES,
                                     'clock_ticks_per_second': os.sysconf('SC_CLK_TCK')})


if __name__ == '__main__':
    main()
