#!/usr/bin/env python3
"""Private read-only continuation: retry only exact same-host screenshot HTTP409.

No keyboard, authentication UI, power operation or guest command is available.
Original controller and preflight remain immutable; every gap stays recorded.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from urllib.parse import urlsplit

ORIGINAL = '91fd17fba173c555d5ab275f0143d8a582993689'
MAX_CONSECUTIVE = 5
MAX_TOTAL = 10


def need(ok, message):
    if not ok: raise ValueError(message)


def screenshot_conflict(result, govc, endpoint):
    """Exact observed download error, never an arbitrary409 or stale error file."""
    if not 0 < result.returncode <= 255 or result.stdout != b'' or len(result.stderr) > 65536: return False
    try:
        text = result.stderr.decode('utf-8').strip()
        match = re.fullmatch(r'([^\r\n]+): download\((https://[^\s()]+)\): 409 Conflict', text)
        if not match or match[1].replace('\\', '/').casefold() != str(govc).replace('\\', '/').casefold(): return False
        url, target = urlsplit(match[2]), urlsplit(endpoint)
        return (url.username is None and url.password is None and target.scheme == 'https'
                and url.hostname == target.hostname and (url.port or 443) == (target.port or 443)
                and url.path == '/screen' and re.fullmatch(r'id=[0-9]+', url.query) is not None
                and not url.fragment)
    except (ValueError, UnicodeError):
        return False


def capture_once(lab, path, timeout):
    need(lab._credential_env is not None, 'owned API check must precede capture')
    env = dict(lab._credential_env)
    env.update(GOVC_URL=lab.c['endpoint'], GOVC_PERSIST_SESSION='false',
               GOVC_INSECURE='true' if lab.c.get('tls_insecure') else 'false')
    return subprocess.run([lab.govc, 'vm.console', '-capture=' + str(path), lab.state['path']],
                          env=env, capture_output=True, timeout=timeout)


def conflict_artifact(path):
    if not os.path.lexists(path): return
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size == 0
         and not getattr(info, 'st_file_attributes', 0) & 0x400,
         'partial or linked conflict capture refused; no retry')


def evidence(directory, sequence, result, started, ended, status):
    row = {'event': 'capture_attempt', 'attempt': sequence, 'status': status,
           'started_monotonic_ns': started, 'finished_monotonic_ns': ended,
           'finished_realtime_ns': time.time_ns(), 'exit_code': result.returncode}
    for name in ('stdout', 'stderr'):
        raw = getattr(result, name) or b''
        need(isinstance(raw, bytes), 'capture diagnostics must be bytes')
        path = directory / ('attempt-%04d.%s' % (sequence, name))
        with path.open('xb') as output: output.write(raw[:65536])
        row[name + '_sha256'] = hashlib.sha256(raw).hexdigest()
        row[name + '_bytes'] = len(raw)
        row[name + '_retained_bytes'] = min(len(raw), 65536)
    with (directory / ('attempt-%04d.json' % sequence)).open('x', encoding='utf-8') as output:
        json.dump(row, output, sort_keys=True)
    return row


def observe(lab, args, visual, clock=time.monotonic, pause=time.sleep, capture=capture_once):
    need(re.fullmatch(r'[a-z][a-z0-9-]{0,47}', args.label), 'invalid private label')
    need(1 <= args.seconds <= 900 and 0.5 <= args.interval <= 10, 'capture bounds refused')
    pinned = visual.identity(visual.read_json(lab.state_file))
    visual.no_identity_reset(lab)
    visual.preflight(lab)
    scope_hash = hashlib.sha256(lab.scope_path.read_bytes()).hexdigest()
    directory = lab.sec / ('visual-continuation-' + args.label)
    directory.mkdir(mode=0o700)
    deadline = clock() + args.seconds
    sequence = frames = total_bytes = consecutive = conflicts = 0
    header = {'event': 'begin', 'original_controller': ORIGINAL,
              'helper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'scope_sha256': scope_hash, 'identity': pinned,
              'coverage': 'sampled with explicit gaps; never continuous',
              'max_consecutive_conflicts': MAX_CONSECUTIVE, 'max_total_conflicts': MAX_TOTAL}
    with (directory / 'events.jsonl').open('x', encoding='utf-8', newline='\n') as output:
        def emit(row):
            output.write(json.dumps(row, sort_keys=True) + '\n'); output.flush()
        emit(header)
        try:
            while clock() < deadline:
                need(hashlib.sha256(lab.scope_path.read_bytes()).hexdigest() == scope_hash, 'scope changed')
                state = visual.read_json(lab.state_file)
                need(visual.identity(state) == pinned, 'owned identity changed')
                visual.no_identity_reset(lab)
                lab.state = state
                vm = lab.vm(timeout=10)
                power = vm['runtime']['powerState']
                if power == 'poweredOff':
                    emit({'event': 'gap', 'reason': 'owned_powered_off', 'monotonic_ns': time.monotonic_ns()})
                    pause(min(args.interval, max(0, deadline - clock()))); continue
                need(power == 'poweredOn', 'unexpected owned power state')
                need(sequence < 900 and total_bytes < visual.MAX_TOTAL, 'count/byte budget exhausted')
                path = directory / ('frame-%04d.png' % sequence)
                started = time.monotonic_ns()
                try:
                    result = capture(lab, path, 10)
                except subprocess.TimeoutExpired as error:
                    result = subprocess.CompletedProcess([], -1, error.stdout or b'', error.stderr or b'')
                    emit(evidence(directory, sequence, result, started, time.monotonic_ns(), 'timeout_no_retry'))
                    raise ValueError('capture timeout; no retry') from None
                conflict = screenshot_conflict(result, lab.govc, lab.c['endpoint'])
                row = evidence(directory, sequence, result, started, time.monotonic_ns(),
                               'http409_gap' if conflict else 'download_succeeded_unvalidated' if result.returncode == 0 else 'failure_no_retry')
                emit(row); sequence += 1
                need(row['stdout_bytes'] <= 65536 and row['stderr_bytes'] <= 65536,
                     'capture diagnostics exceeded bound; no retry')
                if result.returncode:
                    need(conflict, 'non-screenshot-conflict failure; no retry')
                    consecutive += 1; conflicts += 1
                    conflict_artifact(path)
                    need(consecutive < MAX_CONSECUTIVE and conflicts < MAX_TOTAL, 'screenshot conflict budget exhausted')
                    pause(min(args.interval, max(0, deadline - clock())))
                    continue
                consecutive = 0
                # A success cannot bypass the ownership check after the download.
                lab.vm(timeout=10)
                metadata = visual.image_metadata(path, visual.MAX_TOTAL - total_bytes)
                total_bytes += metadata['bytes']; frames += 1
                emit({'event': 'frame', 'attempt': sequence - 1, 'filename': path.name, **metadata,
                      'monotonic_ns': time.monotonic_ns(), 'realtime_ns': time.time_ns()})
                pause(min(args.interval, max(0, deadline - clock())))
            need(frames > 0, 'no validated frame collected')
            emit({'event': 'complete', 'frames': frames, 'http409_gaps': conflicts,
                  'bytes': total_bytes, 'continuous_coverage': False})
        except Exception:
            emit({'event': 'blocked', 'frames': frames, 'http409_gaps': conflicts,
                  'monotonic_ns': time.monotonic_ns(), 'no_automatic_reentry': True})
            raise
    return frames, conflicts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-root', type=Path, required=True)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--seconds', type=float, default=300)
    parser.add_argument('--interval', type=float, default=1)
    args = parser.parse_args()
    try:
        root = args.original_root.resolve()
        scope = json.loads(args.scope.read_bytes())
        manifest = Path(scope['controller_manifest'])
        data = json.loads(manifest.read_bytes())
        need(data.get('revision') == ORIGINAL, 'original controller revision required')
        path = root / 'test/e2e/appliance/esxi/controller-freeze.py'
        need(hashlib.sha256(path.read_bytes()).hexdigest() == data['files']['test/e2e/appliance/esxi/controller-freeze.py'], 'verifier identity differs')
        spec = importlib.util.spec_from_file_location('original_freeze', path)
        freeze = importlib.util.module_from_spec(spec); spec.loader.exec_module(freeze)
        freeze.verify(manifest, root)
        spec = importlib.util.spec_from_file_location('original_visual', root / 'test/e2e/appliance/esxi/visual-capture.py')
        visual = importlib.util.module_from_spec(spec); spec.loader.exec_module(visual)
        boot = visual.load(); lab = boot.module.Lab(args.scope)
        boot.module.validate_scope(lab.c); boot.private_directory(lab)
        with visual.passive_lock(lab.run):
            frames, conflicts = observe(lab, args, visual)
        print('Private capture complete: %d frames, %d recorded409 gaps; review required.' % (frames, conflicts))
        return 0
    except Exception:
        print('BLOCKED: private capture stopped; preserve all attempt receipts; no automatic reentry.', file=sys.stderr)
        return 90


if __name__ == '__main__': sys.exit(main())
