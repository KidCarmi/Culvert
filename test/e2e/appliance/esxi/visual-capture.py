#!/usr/bin/env python3
"""Private passive ESXi screenshots, only after an exact owned UUID exists.

Start before `up`; this helper never imports, powers, types or uses guest SSH.
The passive lock is separate from operation.lock so import can finish. Every
frame is private and may contain bootstrap or recovery credentials.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
import time
import uuid

HERE = Path(__file__).resolve().parent
SOURCE = 'cd8e44505bd329e5de675592ad4c23f92a534d55'
MAX_IMAGE = 16 * 1024 * 1024
MAX_TOTAL = 128 * 1024 * 1024
PHASES = ('imported', 'powered-on', 'baseline-verified', 'qualification-started',
          'restore-qualification-started', 'baseline-completed')


def need(ok, reason):
    if not ok: raise ValueError(reason)


def load():
    spec = importlib.util.spec_from_file_location('visual_bootstrap', HERE / 'bootstrap-checks.py')
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def read_json(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024, 'bounded regular evidence required')
    return json.loads(path.read_bytes())


def identity(state):
    need(not state.get('deleted') and state.get('phase') in PHASES, 'owned VM not ready')
    need(str(uuid.UUID(state['uuid'])) == state['uuid'], 'canonical owned UUID required')
    need(state['ref'].get('type') == 'VirtualMachine', 'owned VM reference required')
    return {k: state[k] for k in ('uuid', 'ref', 'owner', 'name', 'path', 'endpoint', 'host_ref', 'ds_ref', 'network_ref')}


def no_identity_reset(lab):
    # The access-aware flow retains powered-on in the ledger, including across
    # maintenance. Reset has its own durable attempt marker, checked separately.
    for name in ('p1-regressions', 'p1-regressions-confirmation'):
        path = lab.sec / name / 'identity-reset.attempt.json'
        need(not path.exists() and not path.is_symlink(), 'identity reset campaign refused')


def preflight(lab):
    value = read_json(lab.ev / 'preflight.json')
    freeze = read_json(Path(lab.c['controller_manifest']))
    need(value['expected_source'] == lab.c['source_sha'] == SOURCE
         and value['expected_image'] == lab.c['image_id']
         and value['artifact']['ova_sha256'] == lab.c['ova_sha256']
         and value['harness_sha'] == freeze['revision'] and value['harness_dirty'] is False
         and value['controller_freeze'] == freeze, 'preflight/freeze/candidate mismatch')


def image_metadata(path, remaining):
    need(path.is_file() and not path.is_symlink(), 'capture missing or linked')
    size = path.stat().st_size
    need(24 <= size <= min(MAX_IMAGE, remaining), 'private capture byte budget exceeded')
    with path.open('rb') as stream:
        header = stream.read(24)
        need(header[:8] == b'\x89PNG\r\n\x1a\n' and header[12:16] == b'IHDR', 'capture is not PNG')
        width, height = struct.unpack('>II', header[16:24])
        need(1 <= width <= 4096 and 1 <= height <= 2160, 'capture dimensions outside budget')
        stream.seek(0); digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'bytes': size, 'sha256': digest, 'width': width, 'height': height}


@contextlib.contextmanager
def passive_lock(run):
    path = run / 'visual-capture.lock'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode()); os.close(fd); fd = None
        yield
    finally:
        if fd is not None: os.close(fd)
        path.unlink()


def capture(lab, args, private_directory, clock=time.monotonic, pause=time.sleep):
    need(re.fullmatch('[a-z][a-z0-9-]{0,47}', args.label), 'invalid capture label')
    need(1 <= args.seconds <= 900 and 0.5 <= args.interval <= 10
         and 1 <= args.wait_owned_seconds <= 1800, 'capture bounds refused')
    deadline = clock() + args.wait_owned_seconds
    # `up` creates the ledger before import but adds UUID/ref only after exact
    # placement and annotation checks. Never resolve names or broad inventory.
    while True:
        if lab.state_file.exists():
            state = read_json(lab.state_file)
            if state.get('deleted'): raise ValueError('owned ledger retired')
            if state.get('uuid') and state.get('ref'): break
        need(clock() < deadline, 'owned UUID wait expired')
        pause(min(0.5, max(0, deadline - clock())))
    pinned = identity(state)
    no_identity_reset(lab)
    preflight(lab)
    private_directory(lab)  # `up` has now established the restricted ACL.
    directory = lab.sec / ('visual-' + args.label)
    directory.mkdir(mode=0o700)  # Exclusive; never replace an earlier sequence.
    scope_hash = hashlib.sha256(lab.scope_path.read_bytes()).hexdigest()
    frames, total, started, powered_off_seen = 0, 0, None, False
    with (directory / 'frames.jsonl').open('x', encoding='utf-8', newline='\n') as output:
        def emit(value):
            output.write(json.dumps(value, sort_keys=True) + '\n'); output.flush()
        emit({'event': 'owned', 'identity': pinned, 'scope_sha256': scope_hash,
              'source': lab.c['source_sha'], 'ova_sha256': lab.c['ova_sha256'], 'image_id': lab.c['image_id']})
        while True:
            if started is not None and clock() - started >= args.seconds: break
            need(hashlib.sha256(lab.scope_path.read_bytes()).hexdigest() == scope_hash, 'scope changed')
            state = read_json(lab.state_file)
            need(identity(state) == pinned, 'owned identity changed')
            no_identity_reset(lab)
            lab.state = state
            vm = lab.vm(timeout=10)  # Annotation, UUID, host, datastore and network.
            power = vm['runtime']['powerState']
            if power != 'poweredOn':
                need(power == 'poweredOff' and (started is not None or clock() < deadline), 'unexpected power transition')
                if lab.c.get('visual_capture_label') == args.label and state.get('visual_capture_nonce'):
                    armed = {k: state[k] for k in ('uuid', 'ref', 'owner', 'visual_capture_nonce')}
                    armed.update(scope_sha256=scope_hash, power_state='poweredOff', monotonic_ns=time.monotonic_ns())
                    temporary = directory / 'armed.tmp'
                    temporary.write_text(json.dumps(armed), encoding='utf-8')
                    os.replace(temporary, directory / 'armed.json')
                emit({'event': 'powered_off', 'monotonic_ns': time.monotonic_ns()})
                powered_off_seen = True; pause(0.5); continue
            if started is None: started = clock()
            if clock() - started >= args.seconds: break
            need(frames < 900 and total < MAX_TOTAL, 'capture count/byte budget exhausted')
            begin = time.monotonic_ns()
            path = directory / ('frame-%04d.png' % frames)
            lab.gov('vm.console', '-capture=' + str(path), pinned['path'], timeout=10, json_output=False)
            # A screenshot cannot be assigned to a replaced/reconfigured VM.
            lab.vm(timeout=10)
            metadata = image_metadata(path, MAX_TOTAL - total)
            total += metadata['bytes']; frames += 1
            emit({'event': 'frame', 'filename': path.name, **metadata, 'uuid': pinned['uuid'],
                  'started_monotonic_ns': begin, 'finished_monotonic_ns': time.monotonic_ns(),
                  'finished_realtime_ns': time.time_ns(), 'elapsed_seconds': round(clock() - started, 3),
                  'observed_powered_off_before_capture': powered_off_seen})
            pause(min(args.interval, max(0, args.seconds - (clock() - started))))
        need(frames > 0, 'no private visual observations collected')
        result = {'event': 'complete', 'frames': frames, 'bytes': total,
                  'observed_powered_off_before_capture': powered_off_seen,
                  'coverage': 'sampled only; firmware/early splash may precede first frame',
                  'privacy': 'raw screenshots and metadata private; no automatic publication'}
        emit(result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--seconds', type=float, default=300)
    parser.add_argument('--interval', type=float, default=2)
    parser.add_argument('--wait-owned-seconds', type=float, default=1800)
    args = parser.parse_args()
    try:
        boot = load(); lab = boot.module.Lab(args.scope)
        boot.module.validate_scope(lab.c)
        need(lab.c['source_sha'] == SOURCE and lab.c.get('controller_manifest'), 'exact frozen visual candidate required')
        with passive_lock(lab.run):
            result = capture(lab, args, boot.private_directory)
        print('Captured %d private frames; visual acceptance requires review.' % result['frames'])
        return 0
    except Exception:
        print('BLOCKED: private visual capture stopped; preserve evidence and reconcile ownership.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
