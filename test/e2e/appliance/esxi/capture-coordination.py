"""Bounded read-only screenshot acquisition; never retries keyboard input."""
import contextlib
import json
import os
from pathlib import Path
import time
import uuid


class ReadFailure(OSError):
    retryable_snapshot_read = True


def receipt(lab, stage, error):
    directory = Path(getattr(lab, 'private_diagnostics', lab.run / 'secrets')) / 'capture-errors'
    directory.mkdir(exist_ok=True)
    with (directory / (uuid.uuid4().hex + '.json')).open('x', encoding='utf-8') as output:
        json.dump({'stage': stage, 'error_type': type(error).__name__,
                   'time_ns': time.time_ns(), 'readonly': True}, output)


@contextlib.contextmanager
def lock(run, deadline, clock=time.monotonic, pause=time.sleep):
    path = run / 'console-capture.lock'
    while True:
        if clock() >= deadline: raise TimeoutError('capture lock deadline exceeded')
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            break
        except FileExistsError:
            pause(min(0.1, max(0, deadline-clock())))
    try:
        os.write(fd, str(os.getpid()).encode()); os.close(fd); fd = None
        yield
    finally:
        if fd is not None: os.close(fd)
        path.unlink()


def snapshot(lab, path, deadline, clock=time.monotonic, pause=time.sleep):
    def budget():
        remaining = deadline-clock()
        if remaining < 1: raise TimeoutError('snapshot observation deadline exceeded')
        return min(10, remaining)
    for attempt in range(3):
        target = path if attempt == 0 else path.with_name(path.stem + '.attempt-' + str(attempt+1) + path.suffix)
        if target.exists() or target.is_symlink(): raise ValueError('capture evidence already exists')
        stage = 'ownership-before'
        try:
            with lock(lab.run, deadline, clock, pause):
                lab.vm(timeout=budget())  # Ownership failures are terminal.
                stage = 'screenshot'
                lab.gov('vm.console', '-capture=' + str(target), lab.state['path'],
                        timeout=budget(), json_output=False)
                if not target.is_file() or target.is_symlink(): raise ValueError('capture missing or linked')
                if target.stat().st_size == 0: raise ReadFailure('empty screenshot')
                stage = 'ownership-after'
                lab.vm(timeout=budget())
                return target
        except Exception as error:
            receipt(lab, stage, error)
            # Only the adapter's classified read-transport failure or a zero-byte
            # successful download is retryable. No ownership/decoder/input retry.
            if not (isinstance(error, OSError) and getattr(error, 'retryable_snapshot_read', False)) or attempt == 2:
                raise
            pause(min(0.5, max(0, deadline-clock())))
    raise RuntimeError('unreachable')
