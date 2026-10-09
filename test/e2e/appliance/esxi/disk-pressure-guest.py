#!/usr/bin/env python3
"""Private authenticated guest orchestration; imported by the frozen controller.

This deliberately does NOT qualify backups or updates under pressure. Both
maintenance locks exclude them. No product process is restarted by this code.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bind_response_evidence(backend):
    original = backend.request
    allowed = {'content-type', 'content-length', 'cache-control', 'date', 'server', 'via'}
    def observed(port, path, method='GET', payload=None, tls=False):
        code, raw, headers = original(port, path, method, payload, tls)
        if port == 8080 and path.startswith('http://'):
            selected, used, truncated = [], 0, False
            for name, value in headers:
                if name.lower() not in allowed and not name.lower().startswith('x-culvert-'):
                    continue
                item = [name[:64], value[:256]]
                size = len(json.dumps(item).encode())
                if used + size > 1024:
                    truncated = True
                    continue
                used += size
                selected.append(item)
                truncated = truncated or len(name) > 64 or len(value) > 256
            backend.last_response_evidence = {'allowlisted_headers': selected, 'headers_truncated': truncated}
        return code, raw, headers
    backend.request = observed


def classify(kind, code, raw, expected, fetched):
    if kind == 'eicar' and 200 <= code < 300:
        return 'eicar_delivered'
    if code == 403 and b'antivirus scanning is currently unavailable' in raw.lower():
        return 'av_unavailable'
    if not fetched:
        return 'unproven_origin'
    if kind == 'clean' and code == 200 and raw == expected:
        return 'clean_delivered'
    if kind == 'eicar' and code == 403 and b'Blocked by CLAMAV scan' in raw:
        return 'eicar_blocked'
    return 'unexpected_response'


def probe(backend, kind, fresh, seen):
    body = fresh(kind)
    digest = sha(body)
    need(digest not in seen, 'fixture_reused')
    seen.add(digest)
    # Remove previous finished fixture paths; every request still has new body
    # and URL, and the origin acknowledges this particular fetch.
    backend.payloads.clear()
    backend.fetched.clear()
    started = time.monotonic_ns()
    code, raw, fetched = backend.probe(kind, body)
    verdict = classify(kind, code, raw, body, fetched)
    paths = list(backend.payloads)
    path = paths[0] if len(paths) == 1 else None
    url = ('http://' + backend.address + ':' + str(backend.server.server_port) + path) if path else None
    # Preserve the full bounded body on the critical delivered-EICAR path.
    # Routine block pages have an explicit smaller evidence cap.
    limit = 1024 ** 2 if verdict == 'eicar_delivered' else 2048
    response_evidence = getattr(backend, 'last_response_evidence', {})
    if not isinstance(response_evidence, dict):
        response_evidence = {}
    return {'kind': kind, 'started_ns': started, 'ended_ns': time.monotonic_ns(),
            'http_status': code, 'body_sha256': digest, 'response_sha256': sha(raw),
            'origin_fetched': fetched, 'verdict': verdict, 'private_origin_url': url,
            'private_expected_body_base64': base64.b64encode(body).decode(),
            'private_response_body_base64': base64.b64encode(raw[:limit]).decode(),
            'response_metadata': response_evidence,
            'response_bytes': len(raw), 'response_truncated': len(raw) > limit}


def negative_control(backend):
    # Reserved .invalid name: no dependency on an external test service.
    url = 'http://culvert-pressure-denied.invalid/' + secrets.token_hex(24)
    code, raw, _ = backend.request(8080, url)
    return {'http_status': code, 'response_sha256': sha(raw), 'private_url': url,
            'pass': code == 403 and b'Default Deny' in raw and b'No matching policy rule' in raw}


def ready(backend):
    started = time.monotonic_ns()
    code, raw, _ = backend.request(8080, '/ready')
    value = json.loads(raw)
    return {'http_status': code, 'status': value.get('status'),
            'clamav_status': value.get('checks', {}).get('clamav', {}).get('status'),
            'started_ns': started, 'ended_ns': time.monotonic_ns()}


def sample(backend, fresh, seen, strict):
    result = {'started_ns': time.monotonic_ns(), 'probes': []}
    # EICAR first: stop taking optional probes as soon as actual delivery occurs.
    for kind in ('eicar', 'clean'):
        row = probe(backend, kind, fresh, seen)
        result['probes'].append(row)
        if row['verdict'] == 'eicar_delivered':
            result['pass'] = False
            return result
    result['ready'] = ready(backend)
    result['probes'].append(probe(backend, 'clean', fresh, seen))
    result['default_deny_control'] = negative_control(backend)
    verdicts = [x['verdict'] for x in result['probes']]
    ready_ok = result['ready']['http_status'] == 200 and result['ready']['status'] == 'ready'
    persistent_refusal = verdicts[1:] == ['av_unavailable', 'av_unavailable']
    av_not_ready = (result['ready']['http_status'] == 503 and result['ready']['status'] == 'not_ready'
                    and result['ready']['clamav_status'] == 'fail')
    result['readiness_truthful'] = not persistent_refusal or av_not_ready
    if strict:
        result['pass'] = (verdicts == ['eicar_blocked', 'clean_delivered', 'clean_delivered']
                          and ready_ok and result['ready']['clamav_status'] == 'ok')
    else:
        result['pass'] = (verdicts[0] in ('eicar_blocked', 'av_unavailable')
                          and all(x in ('clean_delivered', 'av_unavailable') for x in verdicts[1:])
                          and result['readiness_truthful'])
    result['pass'] = result['pass'] and result['default_deny_control']['pass']
    return result


def container_state(command):
    # Explicit metadata only; full docker inspect may include credentials.
    fmt = '{{json .Id}} {{json .Image}} {{json .State.Running}} {{json .State.StartedAt}} {{json .RestartCount}}'
    return {name: command(['docker', 'inspect', '--format', fmt, name])
            for name in ('culvert', 'culvert-clamav')}


def network_pair(command):
    objects = [json.loads(command(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', name]))
               for name in ('culvert', 'culvert-clamav')]
    common = set(objects[0]) & set(objects[1])
    need(len(common) == 1, 'capture_network_ambiguous')
    name = common.pop()
    return objects[1][name]['IPAddress'], objects[0][name]['IPAddress']


def read_json(path):
    raw = path.read_bytes()
    need(len(raw) < 8192, 'private_record_limit')
    return json.loads(raw)


def capture_healthy(value):
    return (value.get('available') is True
            and not any(value.get(k) for k in ('error', 'output_limit', 'packet_limit')))


def correlate_control(capture, row):
    expected = b' FOUND' if row['kind'] == 'eicar' else b': OK'
    unique = {}
    for fragment in capture.observations(row['started_ns'], row['ended_ns']):
        raw = bytes.fromhex(fragment['response_fragment_hex'])
        if fragment.get('fragment_truncated') or not any(expected + terminator in raw for terminator in (b'\0', b'\n')):
            continue
        key = (fragment['destination_port'], fragment['sequence'], fragment['payload_sha256'])
        unique[key] = {k: fragment[k] for k in ('destination_port', 'sequence', 'payload_sha256', 'monotonic_ns')}
    ports = {key[0] for key in unique}
    return {'pass': bool(unique) and len(ports) == 1, 'fragments': list(unique.values()),
            'request_body_sha256': row['body_sha256'], 'private_origin_url': row['private_origin_url'],
            'started_ns': row['started_ns'], 'ended_ns': row['ended_ns'],
            'semantics': 'deduplicated response fragments inside fresh request window; not complete TCP transactions'}


def prefill_control(capture, backend, fresh, seen):
    before = capture.snapshot()
    result = {'before': before, 'sample': sample(backend, fresh, seen, strict=True)}
    after = capture.snapshot()
    result['after'] = after
    rows = result['sample'].get('probes', [])
    result['correlations'] = [correlate_control(capture, row) for row in rows]
    ports = {fragment['destination_port'] for row in result['correlations'] for fragment in row['fragments']}
    result['pass'] = (result['sample']['pass'] and capture_healthy(before) and capture_healthy(after)
                      and len(result['correlations']) == 3 and len(ports) == 3
                      and all(row['pass'] for row in result['correlations']))
    return result


def phase(config, mode, backend, source, worker, capture_type, fresh, seen):
    root, control = worker.paths(config['operation'], mode)
    control.mkdir(mode=0o700)
    worker.tmpfs_guard(control)
    os.close(worker.safe_directory(control))
    script = control / 'worker.py'
    script.write_bytes(source)
    script.chmod(0o600)
    result = {'mode': mode, 'result': 'fail', 'samples': [], 'released': False,
              'backup_under_pressure': 'NOT_RUN_both_locks_held',
              'update_under_pressure': 'NOT_RUN_both_locks_held'}
    supervisor, capture = None, None
    try:
        sidecar, proxy = network_pair(backend.command)
        capture = capture_type(sidecar, proxy, control / 'clamd-response-fragments.jsonl')
        capture.start()
        result['capture_positive_control'] = prefill_control(capture, backend, fresh, seen)
        need(result['capture_positive_control']['pass'], 'prefill_capture_control_failed')
        result['pressure_capture_start'] = capture.snapshot()
        result['pressure_started_ns'] = time.monotonic_ns()
        supervisor = subprocess.Popen([sys.executable, str(script), '--supervise'], stdin=subprocess.PIPE,
                                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                      close_fds=True, start_new_session=True)
        supervisor.stdin.write(json.dumps({'operation': config['operation'], 'mode': mode,
                                          'lease': config['lease']}).encode())
        supervisor.stdin.close()
        end, exhausted_samples = time.monotonic() + 130, 0
        while time.monotonic() < end:
            backend.check_locks()
            if (control / 'released.json').exists():
                break
            need(supervisor.poll() is None, 'supervisor_exited')
            if not (control / 'armed.json').exists():
                time.sleep(.25)
                continue
            filled = read_json(control / 'filled.json') if (control / 'filled.json').exists() else None
            if filled is not None:
                result['fill'] = filled
                if filled['result'] != 'exhausted':
                    result['result'] = 'blocked'
                    break
            armed = read_json(control / 'armed.json')
            filesystem_before = worker.root_guard(root)
            allocation_before = worker.pressure_probe(root, armed, filled, mode) if filled else None
            row = sample(backend, fresh, seen, strict=False)
            result['samples'].append(row)  # Preserve a delivered body even if watchdog just removed root.
            row['fill_complete_at_start'] = filled is not None
            row['filesystem_before'] = filesystem_before
            row['allocation_before'] = allocation_before
            if not row['pass']:
                raise ValueError('enforcement_or_readiness_failed')
            row['filesystem'] = worker.root_guard(root)
            row['allocation_after'] = worker.pressure_probe(root, armed, filled, mode) if filled else None
            row['pressure_present_across_sample'] = (filled is not None
                                                      and allocation_before['exhausted'] is True
                                                      and row['allocation_after']['exhausted'] is True)
            if filled is not None and row['pressure_present_across_sample']:
                exhausted_samples += 1
                if exhausted_samples >= 3:
                    result['result'] = 'pass'
                    break
            else:
                exhausted_samples = 0
            time.sleep(2)
    except Exception as error:
        result['error_category'] = ('timeout' if isinstance(error, (TimeoutError, subprocess.TimeoutExpired))
                                    else 'probe_or_safety_guard_failed')
    finally:
        # Always request release before optional evidence collection, even when
        # EICAR was delivered. The supervisor alone owns killing/reaping filler.
        (control / 'release').touch(mode=0o600, exist_ok=False)
        if supervisor is not None:
            try:
                supervisor.wait(timeout=35)
            except subprocess.TimeoutExpired:
                result['error_category'] = 'release_unconfirmed_watchdog_still_active'
                result['result'] = 'fail'
        if (control / 'released.json').exists():
            result['release'] = read_json(control / 'released.json')
            result['released'] = result['release'].get('released') is True
        if supervisor is None:
            result['allocation_started'] = False
            result['released'] = not root.exists()
        else:
            result['allocation_started'] = True
        if not result['released']:
            result['result'] = 'fail'
        if capture is not None:
            result['capture'] = capture.close()
            result['capture']['evidence_status'] = ('fragments_captured' if result['capture'].get('fragments', 0)
                                                     else 'NO_RESPONSE_FRAGMENT_OBSERVED')
            positive = result.get('capture_positive_control', {}).get('pass') is True
            capture_ok = positive and capture_healthy(result['capture'])
            start = result.get('pressure_capture_start', {}).get('fragments')
            pressure_fragments = result['capture'].get('fragments', 0) - start if start is not None else None
            result['capture']['pressure_fragments'] = pressure_fragments
            result['capture']['collection_verdict'] = (
                'NO_PRESSURE_FRAGMENT_OBSERVED_WITH_PREFILL_CONTROL' if capture_ok and pressure_fragments == 0
                else 'BOUNDED_FRAGMENTS_RETAINED' if capture_ok else 'CAPTURE_INCOMPLETE')
            if not capture_ok:
                result['result'] = 'fail'
            result['capture']['causal_stream_completeness'] = 'NOT_PROVEN_passive_fragments_only'
            capture_path = control / 'clamd-response-fragments.jsonl'
            if capture_path.exists():
                raw = capture_path.read_bytes()
                need(len(raw) <= 1024 ** 2, 'capture_limit')
                result['capture'].update(sha256=sha(raw), bytes=len(raw), private_base64=base64.b64encode(raw).decode())
        # Retain only bounded tmpfs records. Root filler directory must be gone.
        result['root_pressure_directory_absent'] = not root.exists()
        if not result['root_pressure_directory_absent']:
            result['result'] = 'fail'
    return result


def run(config, backend, backend_module, worker, worker_source, capture_type):
    def interrupted(*unused):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise RuntimeError('guest_interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    bind_response_evidence(backend)
    backend.command = backend_module.command
    result = {'schema': 1, 'operation': config['operation'], 'result': 'fail', 'phases': [],
              'scope': 'narrow_enforcement_and_readiness_reproduction',
              'full_disk_pressure_lifecycle': 'NOT_QUALIFIED_backup_and_update_gates_not_run',
              'backup_under_pressure': 'NOT_RUN_both_locks_held',
              'update_under_pressure': 'NOT_RUN_both_locks_held', 'policy_restored': False}
    seen = set()
    before = None
    try:
        result['identity'] = backend.prepare()
        before = container_state(backend_module.command)
        backend.install_fixture()
        result['baseline'] = sample(backend, backend_module.fresh_body, seen, True)
        need(result['baseline']['pass'], 'baseline_failed')
        for mode in ('blocks', 'inodes'):
            row = phase(config, mode, backend, worker_source, worker, capture_type,
                        backend_module.fresh_body, seen)
            result['phases'].append(row)
            # No restart: wait for the current processes to recover naturally.
            backend.wait_ready(True)
            row['recovered'] = sample(backend, backend_module.fresh_body, seen, True)
            row['no_restart'] = container_state(backend_module.command) == before
            need(row['recovered']['pass'] and row['no_restart'], 'recovery_failed')
            need(row['result'] != 'fail', 'pressure_failed')
        result['result'] = 'pass' if all(x['result'] == 'pass' for x in result['phases']) else 'blocked'
    except Exception:
        result['error_category'] = 'qualification_failed'
    finally:
        try:
            result['policy_restored'] = backend.cleanup_fixture()
        except Exception:
            result['policy_cleanup_error'] = True
        if before is not None:
            try:
                result['no_restart'] = container_state(backend_module.command) == before
            except Exception:
                result['no_restart'] = False
        backend.close()
    if not result['policy_restored'] or not result.get('no_restart'):
        result['result'] = 'fail'
    return result
