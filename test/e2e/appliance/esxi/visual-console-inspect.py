#!/usr/bin/env python3
"""Read-only guest console diagnostics, run only through authenticated gpriv.

The optional bounded empty /dev/console open writes no content and records its
outcome; it never changes getty, GRUB, tty mode, services or access configuration.
All output remains private. No credentials, environment or process args are read.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import time

SOURCE = 'cd8e44505bd329e5de675592ad4c23f92a534d55'


def command(argv, timeout=8):
    try:
        result = subprocess.run(argv, capture_output=True, timeout=timeout)
        if len(result.stdout) > 256 * 1024 or len(result.stderr) > 16384:
            return {'status': 'blocked', 'reason': 'output_bound'}
        return {'status': 'observed', 'exit': result.returncode,
                'stdout': result.stdout.decode('utf-8', errors='replace'),
                'stderr_bytes': len(result.stderr)}
    except subprocess.TimeoutExpired:
        return {'status': 'blocked', 'reason': 'timeout'}


def console_open():
    start = time.monotonic_ns()
    value = command(['timeout', '--signal=TERM', '--kill-after=1s', '3s',
                     'sh', '-c', ': > /dev/console'], timeout=6)
    value['elapsed_ns'] = time.monotonic_ns() - start
    return value


def vt_mode():
    fd = None
    try:
        fd = os.open('/dev/tty1', os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
        result = fcntl.ioctl(fd, 0x4B3B, bytes(4))  # KDGETMODE only; never KDSETMODE.
        return {'status': 'observed', 'mode': struct.unpack('i', result)[0]}
    except OSError:
        return {'status': 'blocked', 'reason': 'unavailable'}
    finally:
        if fd is not None: os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test-console-open', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0: raise ValueError('authenticated root required')
    build = json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_bytes())
    if build['source']['git_commit'] != SOURCE or build['source']['git_dirty'] is not False:
        raise ValueError('exact candidate source required')
    value = {'schema': 1, 'source': SOURCE, 'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
             'monotonic_ns': time.monotonic_ns(), 'realtime_ns': time.time_ns(), 'tty1_mode': vt_mode(),
             'active_vt': Path('/sys/class/tty/tty0/active').read_text().strip(),
             'getty': command(['systemctl', 'show', 'getty@tty1.service', '-p', 'TTYReset', '-p', 'TTYVHangup',
                               '-p', 'TTYVTDisallocate', '-p', 'Result', '-p', 'ExecMainStatus', '-p', 'ActiveState']),
             'console_size': command(['timeout', '3s', 'stty', '-F', '/dev/tty1', 'size']),
             'splash_units': command(['systemctl', 'show', 'plymouth-start.service', 'plymouth-quit.service',
                                      'culvert-kernel-log-vt.service', '-p', 'Id', '-p', 'Result', '-p', 'ActiveState',
                                      '-p', 'ConditionResult', '-p', 'ExecMainStatus']),
             'kernel_log_tail': command(['journalctl', '-b', '-k', '-n', '300', '--no-pager', '-o', 'short-monotonic'])}
    cfg = Path('/etc/default/grub.d/99-culvert-splash.cfg')
    value['splash_cfg_sha256'] = hashlib.sha256(cfg.read_bytes()).hexdigest()
    value['efi_ubuntu_directory_exists'] = Path('/boot/efi/EFI/ubuntu').is_dir()
    value['console_open'] = console_open() if args.test_console_open else {'status': 'not-run'}
    print(json.dumps(value, sort_keys=True))


if __name__ == '__main__': main()
