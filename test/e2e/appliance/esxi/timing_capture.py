"""Shared private-output plumbing for timing capture runners (no VM actions)."""
import datetime
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import threading

HERE = Path(__file__).resolve().parent
LIMIT = 2 * 1024 * 1024


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def load_lab(scope):
    spec = importlib.util.spec_from_file_location('timing_capture_bootstrap', HERE / 'bootstrap-checks.py')
    bootstrap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bootstrap)
    lab = bootstrap.module.Lab(scope)
    bootstrap.module.validate_scope(lab.c)
    bootstrap.private_directory(lab)
    return lab


def destinations(lab, label, prefix):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}', label):
        raise ValueError('invalid capture label')
    if lab.sec.resolve() != lab.run.resolve() / 'secrets':
        raise ValueError('invalid private location')
    paths = (lab.sec / f'{prefix}-{label}.raw', lab.sec / f'{prefix}-{label}.stderr',
             lab.ev / f'{prefix}-{label}.json')
    if any(path.exists() or path.is_symlink() for path in paths):
        raise ValueError('capture exists; preserve it')
    return paths


def capture(args, payload, raw_path, error_path, timeout):
    """Drain capped pipes directly into private exclusive files; no raw printing."""
    over = threading.Event()
    failures = threading.Event()
    with raw_path.open('xb') as out, error_path.open('xb') as err:
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)

        def drain(source, target):
            remaining = LIMIT
            try:
                while True:
                    chunk = source.read(min(65536, remaining + 1))
                    if not chunk:
                        break
                    target.write(chunk[:remaining])
                    remaining -= len(chunk)
                    if remaining < 0:
                        over.set()
                        process.kill()
                        break
            except OSError:
                failures.set()
                process.kill()
            finally:
                source.close()

        def feed():
            try:
                process.stdin.write(payload)
                process.stdin.close()
            except (BrokenPipeError, OSError):
                failures.set()

        threads = [threading.Thread(target=drain, args=pair, daemon=True)
                   for pair in ((process.stdout, out), (process.stderr, err))]
        threads.append(threading.Thread(target=feed, daemon=True))
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            code = process.wait(timeout=5)
        finally:
            for thread in threads:
                thread.join(timeout=5)
        if any(thread.is_alive() for thread in threads):
            raise ValueError('capture pipe did not close')
    return {'exit_code': code, 'timeout': timed_out, 'oversize': over.is_set(),
            'capture_error': failures.is_set()}


def write_summary(path, value):
    encoded = json.dumps(value, indent=2)
    if len(encoded.encode('utf-8')) > 256 * 1024:
        raise ValueError('summary bound')
    with path.open('x', encoding='utf-8') as stream:
        stream.write(encoded + '\n')
