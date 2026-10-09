#!/usr/bin/env python3
"""LAB only: supervised bounded root-filesystem pressure; never run on import.

The supervisor owns exactly one filler subprocess. It kills/reaps that process
BEFORE cleanup, so a late allocation cannot race space release. Private control
and evidence live in tmpfs. A pinned controller lease and 150-second ceiling
both fail closed. Kernel/host failure can prevent cleanup; that is never PASS.
"""
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import sys
import time

GIB = 1024 ** 3
MAX_INODES = 100000
MAX_SECONDS = 150
MAX_ROOT = 41 * GIB  # 40-GiB virtual disk, tolerance only for statvfs accounting


def require(value, reason):
    if not value:
        raise ValueError(reason)


def paths(operation, mode):
    require(re.fullmatch('[0-9a-f]{32}', operation) is not None, 'operation')
    require(mode in ('blocks', 'inodes'), 'mode')
    return (Path('/var/lib') / ('culvert-lab-pressure-' + operation + '-' + mode),
            Path('/run') / ('culvert-lab-pressure-' + operation + '-' + mode))


def safe_directory(path):
    require(path.is_absolute(), 'absolute directory')
    for current in [path, *path.parents]:
        st = current.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == 0 and st.st_mode & 0o022 == 0,
                'unsafe directory')
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def root_guard(path):
    st = os.statvfs(path)
    require(os.stat(path).st_dev == os.stat('/').st_dev, 'not root filesystem')
    require(2 * GIB <= st.f_blocks * st.f_frsize <= MAX_ROOT, 'root size differs')
    return {'bytes_free': st.f_bfree * st.f_frsize,
            'bytes_available': st.f_bavail * st.f_frsize,
            'f_bfree': st.f_bfree, 'f_bavail': st.f_bavail, 'block_bytes': st.f_frsize,
            'unavailable_free_bytes': (st.f_bfree - st.f_bavail) * st.f_frsize,
            'accounting_note': 'free-minus-available; may include filesystem internal reserve; not changed',
            'inodes_free': st.f_ffree}


def identity(st):
    return {'device': st.st_dev, 'inode': st.st_ino}


def regular(st):
    require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1
            and st.st_mode & 0o077 == 0, 'unsafe pressure file')


def pressure_probe(root, armed, filled, mode):
    """A fresh single-block allocation test, never a free-byte threshold.

    Only our pre-created empty file may be touched. Re-check directory, probe
    and retained filler identity on both sides; freed/truncated filler is not
    evidence of sustained exhaustion. A successful probe is freed immediately.
    """
    require(filled['result'] == 'exhausted' and filled['binding'] == armed['binding'], 'fill binding')
    directory = safe_directory(root)
    data = None
    try:
        def bound():
            require(identity(os.fstat(directory)) == armed['binding']['root']
                    == identity(root.lstat()), 'pressure directory changed')
            root_guard(root)
            st = os.stat('probe', dir_fd=directory, follow_symlinks=False)
            regular(st)
            require(identity(st) == armed['binding']['probe'], 'pressure probe changed')
            if data is not None:
                require(identity(os.fstat(data)) == identity(st), 'probe descriptor changed')
            if mode == 'blocks':
                blocks = os.stat('blocks', dir_fd=directory, follow_symlinks=False)
                regular(blocks)
                require(identity(blocks) == filled['blocks_identity']
                        and blocks.st_size >= filled['allocated_bytes']
                        and blocks.st_blocks * 512 >= filled['allocated_bytes'], 'filler removed or truncated')
        bound()
        data = os.open('probe', os.O_RDWR | os.O_NOFOLLOW, dir_fd=directory)
        regular(os.fstat(data))
        bound()
        require(os.fstat(data).st_size == 0 and os.fstat(data).st_blocks == 0, 'probe is not empty')
        before = root_guard(root)
        require(before['block_bytes'] == 4096, 'unsupported allocation unit')
        result = {'started_ns': time.monotonic_ns(), 'allocation_bytes': 4096,
                  'filesystem_before': before, 'binding': armed['binding']}
        try:
            os.posix_fallocate(data, 0, 4096)
            result['errno'] = None
            result['exhausted'] = False
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
            result['errno'] = 'ENOSPC'
            result['exhausted'] = mode == 'blocks'
        finally:
            os.ftruncate(data, 0)
        bound()
        result['filesystem_after'] = root_guard(root)
        # Inode exhaustion is independently proven by f_ffree==0. An existing
        # file cannot test inode creation; never label block ENOSPC as inodes.
        if mode == 'inodes':
            result['exhausted'] = (before['inodes_free'] == 0
                                   and result['filesystem_after']['inodes_free'] == 0)
            result['inode_evidence'] = 'filled_create_ENOSPC_and_zero_free_inodes'
        result['ended_ns'] = time.monotonic_ns()
        return result
    finally:
        if data is not None:
            os.close(data)
        os.close(directory)


def tmpfs_guard(path):
    # Fixed /run mount only. Never accept a guessed directory on the full disk.
    entries = Path('/proc/mounts').read_text().splitlines()
    require(any(len(x.split()) >= 3 and x.split()[1:3] == ['/run', 'tmpfs'] for x in entries),
            'run is not tmpfs')
    require(os.stat(path).st_dev == os.stat('/run').st_dev, 'control not tmpfs')


def lease(config):
    c = http.client.HTTPSConnection(config['host'], config['port'], timeout=2,
                                    context=ssl._create_unverified_context())
    try:
        c.connect()
        require(hashlib.sha256(c.sock.getpeercert(binary_form=True)).hexdigest() == config['certificate_sha256'],
                'lease pin')
        c.request('GET', '/' + config['token'], headers={'Connection': 'close'})
        response = c.getresponse()
        raw = response.read(1025)
        return response.status == 200 and len(raw) <= 1024 and json.loads(raw) == {'permit': True}
    except (OSError, ValueError, KeyError, http.client.HTTPException):
        return False
    finally:
        c.close()


def atomic_json(path, value):
    raw = json.dumps(value, sort_keys=True).encode()
    require(len(raw) < 8192, 'record limit')
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(raw)
    os.replace(temporary, path)


def fill_blocks(fd, allocate=os.posix_fallocate if hasattr(os, 'posix_fallocate') else None,
                clock=time.monotonic):
    require(allocate is not None, 'fallocate unavailable')
    total, chunk, end = 0, 64 * 1024 ** 2, clock() + 100
    while clock() < end and total + 4096 <= 40 * GIB:
        try:
            allocate(fd, total, min(chunk, 40 * GIB - total))
            total += min(chunk, 40 * GIB - total)
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
            if chunk == 4096:
                return {'result': 'exhausted', 'errno': 'ENOSPC', 'allocated_bytes': total}
            chunk = max(4096, chunk // 16)
    return {'result': 'bounded_not_exhausted', 'allocated_bytes': total}


def fill_inodes(directory_fd, free, clock=time.monotonic):
    if free > MAX_INODES:
        return {'result': 'bounded_not_exhausted', 'reason': 'inode_safety_cap', 'created': 0}
    created, end = 0, clock() + 100
    while created < MAX_INODES and clock() < end:
        try:
            fd = os.open('i%06d' % created, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
            os.close(fd)
            created += 1
        except OSError as error:
            if error.errno not in (errno.ENOSPC, errno.EDQUOT):
                raise
            return {'result': 'exhausted' if error.errno == errno.ENOSPC else 'quota_not_exhaustion',
                    'errno': errno.errorcode[error.errno], 'created': created}
    return {'result': 'bounded_not_exhausted', 'created': created}


def validate_entries(directory_fd):
    names = os.listdir(directory_fd)
    require(len(names) <= MAX_INODES + 3, 'cleanup entry limit')
    for name in names:
        require(name in ('blocks', 'reserve', 'probe') or re.fullmatch('i[0-9]{6}', name), 'unexpected entry')
        st = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == 0 and st.st_nlink == 1, 'unsafe cleanup entry')
    return names


def release(directory_fd):
    # Validate ALL names before changing any; no recursion, glob or shell.
    names = validate_entries(directory_fd)
    for name in sorted(names, key=lambda x: x != 'reserve'):
        os.unlink(name, dir_fd=directory_fd)
    require(not os.listdir(directory_fd), 'cleanup incomplete')


def fill(operation, mode):
    root, control = paths(operation, mode)
    fd = safe_directory(root)
    try:
        initial = root_guard(root)
        if mode == 'blocks':
            data = os.open('blocks', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                           0o600, dir_fd=fd)
            try:
                result = fill_blocks(data)
                result['blocks_identity'] = identity(os.fstat(data))
            finally:
                os.close(data)
        else:
            result = fill_inodes(fd, initial['inodes_free'])
        result['binding'] = json.loads((control / 'binding.json').read_bytes())
        result['after'] = root_guard(root)
        if mode == 'inodes' and result['result'] == 'exhausted' and result['after']['inodes_free'] != 0:
            result['result'] = 'blocks_exhausted_not_inodes'
        atomic_json(control / 'filled.json', result)
    finally:
        os.close(fd)


def supervise(config):
    require(os.geteuid() == 0, 'root required')
    root, control = paths(config['operation'], config['mode'])
    control_fd = safe_directory(control)
    os.close(control_fd)
    tmpfs_guard(control)
    parent = safe_directory(root.parent)
    os.close(parent)
    require(lease(config['lease']), 'no controller lease')
    root.mkdir(mode=0o700)  # One-shot, never reuse a preexisting pressure directory.
    fd = safe_directory(root)
    worker = None
    report = {'schema': 1, 'released': False, 'reason': 'supervisor_error'}
    try:
        def interrupted(*unused):
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            raise RuntimeError('supervisor_interrupted')
        signal.signal(signal.SIGTERM, interrupted)
        report['before'] = root_guard(root)
        reserve = os.open('reserve', os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
                          0o600, dir_fd=fd)
        try:
            os.posix_fallocate(reserve, 0, 32 * 1024 ** 2)
        finally:
            os.close(reserve)
        probe = os.open('probe', os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW,
                        0o600, dir_fd=fd)
        try:
            binding = {'root': identity(os.fstat(fd)), 'probe': identity(os.fstat(probe))}
        finally:
            os.close(probe)
        atomic_json(control / 'binding.json', binding)
        worker = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), '--fill',
                                   config['operation'], config['mode']], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                  close_fds=True, start_new_session=True)
        atomic_json(control / 'armed.json', {'worker_pid': worker.pid, 'max_seconds': MAX_SECONDS, 'binding': binding})
        end = time.monotonic() + MAX_SECONDS
        while time.monotonic() < end:
            if (control / 'release').exists():
                report['reason'] = 'requested'
                break
            if not lease(config['lease']):
                report['reason'] = 'lease_lost'
                break
            rc = worker.poll()
            if rc not in (None, 0):
                report['reason'] = 'worker_failed'
                break
            time.sleep(1)
        else:
            report['reason'] = 'deadline'
    finally:
        # Only kill the child represented by our Popen handle; no PID file trust.
        if worker is not None and worker.poll() is None:
            worker.kill()
        if worker is not None:
            worker.wait(timeout=10)
        release(fd)
        report['released'] = True
        report['after'] = root_guard(root)
        os.close(fd)
        root.rmdir()
        atomic_json(control / 'released.json', report)


if __name__ == '__main__':
    try:
        if len(sys.argv) == 4 and sys.argv[1] == '--fill':
            fill(sys.argv[2], sys.argv[3])
        elif len(sys.argv) == 2 and sys.argv[1] == '--supervise':
            raw = sys.stdin.buffer.read(8193)
            require(len(raw) <= 8192, 'config limit')
            supervise(json.loads(raw))
        else:
            raise ValueError('explicit supervised invocation required')
    except Exception:
        # No private lease endpoint or arbitrary exception contents on console.
        sys.exit(90)
