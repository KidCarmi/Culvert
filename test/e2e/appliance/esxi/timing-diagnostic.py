#!/usr/bin/env python3
"""Controller-only timing observer. Never dispatches power or guest mutations.

Preload this helper before qualification. Start `observe --scope S --label R
--host IP` before reboot; immediately before the separately authorized reboot,
run `mark --scope S --label R`. Mark records operator intent, NOT proof dispatch
or reboot occurred. Output is new evidence/timing-R.jsonl, never raw responses.
Ports default to LAB_SSH_PORT/22 and LAB_PROXY_PORT/8080; /health uses HTTP as
the shared lab does. Operator SSH uses the existing pinned host key and only
the allowlisted `status-json` command. Boot identity remains a separate check.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

HERE = Path(__file__).resolve().parent
LIMIT = 64 * 1024
PHASES = {'ready', 'provisioned', 'provisioning', 'starting', 'network_required',
          'setup_required', 'error', 'unknown', 'running', 'waiting', 'failed'}


def stamp():
    return {'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
            'monotonic_ns': time.monotonic_ns()}


def bounded_command(args, timeout):
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               stdin=subprocess.DEVNULL)
    expired = threading.Event()
    def stop():
        expired.set()
        process.kill()
    timer = threading.Timer(timeout, stop)
    timer.start()
    try:
        raw = process.stdout.read(LIMIT + 1)
        if len(raw) > LIMIT:
            process.kill()
        code = process.wait(timeout=2)
        if len(raw) > LIMIT:
            return 'oversize', b''
        if expired.is_set():
            return 'timeout', b''
        if code:
            return 'command_failed', b''
        return 'ok', raw
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
            process.wait(timeout=2)
        process.stdout.close()


def public_status(raw):
    value = json.loads(raw)
    if not isinstance(value, dict) or value.get('schema_version') != 1:
        raise ValueError('invalid public status')
    return {'phase': value.get('phase') if value.get('phase') in PHASES else 'unknown',
            'application_responding': value.get('application_responding') is True,
            'management_available': value.get('management_available') is True,
            'operator_ready': value.get('phase') == 'ready'}


def tcp_probe(host, port):
    with socket.create_connection((host, port), timeout=2):
        return {}


def health_probe(host, port):
    # No environment proxy, redirect, cookie jar, credentials, or body export.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_args, **_kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(f'http://{host}:{port}/health', timeout=3) as response:
        if response.status != 200:
            raise ValueError('unexpected health status')
        return {'http_status': 200}


def ssh_probe(lab, host, port):
    args = lab.ssh_command(host)
    args[-1] = 'culvert-operator@' + host
    args[-1:-1] = ['-p', str(port)]
    result, raw = bounded_command(args + ['status-json'], 6)
    if result != 'ok':
        return {'result': result}
    return public_status(raw)


def measured(name, probe):
    row = {'event': 'probe', 'probe': name, 'started': stamp()}
    start = time.monotonic()
    try:
        row.update(probe())
        row.setdefault('result', 'ok')
    except (TimeoutError, socket.timeout):
        row['result'] = 'timeout'
    except Exception:
        row['result'] = 'failed'
    row.update(ended=stamp(), elapsed_seconds=round(time.monotonic() - start, 6))
    return row


def transition(states, row, armed):
    """Never label a still-live pre-reboot service as a returned service."""
    if not armed:
        row['observation_phase'] = 'before_dispatch_marker'
        return row
    state = states.setdefault(row['probe'], {'failed': False, 'returned': False})
    ready = row['result'] == 'ok' and (row['probe'] != 'operator_status' or row.get('operator_ready') is True)
    row['observation_phase'] = 'after_dispatch_marker'
    row['first_success_after_observed_failure'] = ready and state['failed'] and not state['returned']
    if row['first_success_after_observed_failure']:
        state['returned'] = True
    if not ready:
        state['failed'] = True
    row['failure_observed_since_marker'] = state['failed']
    return row


def paths(lab, label):
    if not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}', label):
        raise ValueError('invalid label')
    evidence = lab.run / 'evidence'
    if evidence.is_symlink() or evidence.resolve() != lab.ev.resolve():
        raise ValueError('invalid evidence location')
    return evidence / f'timing-{label}.jsonl', evidence / f'timing-{label}-dispatch.json'


def read_marker(path):
    if not path.exists():
        return None
    if path.is_symlink() or path.stat().st_size > 1024:
        raise ValueError('invalid marker')
    value = json.loads(path.read_text(encoding='utf-8'))
    if (set(value) != {'event', 'utc', 'monotonic_ns'} or value['event'] != 'dispatch_intent'
            or type(value['monotonic_ns']) is not int):
        raise ValueError('invalid marker')
    datetime.datetime.fromisoformat(value['utc'])
    return value


def write_marker(path):
    # Publish a complete record, exclusively, while the observer reads it.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix='.timing-', delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(json.dumps({'event': 'dispatch_intent', **stamp()}).encode('utf-8'))
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['observe', 'mark'])
    parser.add_argument('--scope', required=True, type=Path)
    parser.add_argument('--label', required=True)
    parser.add_argument('--host')
    parser.add_argument('--seconds', type=int, default=900)
    parser.add_argument('--interval', type=int, default=10)
    parser.add_argument('--ssh-port', type=int, default=int(os.getenv('LAB_SSH_PORT', '22')))
    parser.add_argument('--proxy-port', type=int, default=int(os.getenv('LAB_PROXY_PORT', '8080')))
    args = parser.parse_args(argv)
    if not (1 <= args.seconds <= 1800 and 5 <= args.interval <= 60
            and all(1 <= p <= 65535 for p in (args.ssh_port, args.proxy_port))):
        raise ValueError('invalid bounds')
    spec = importlib.util.spec_from_file_location('timing_lab', HERE / 'esxi-lab.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    lab = module.Lab(args.scope)
    module.validate_scope(lab.c)
    output, marker = paths(lab, args.label)
    if args.mode == 'mark':
        if not output.is_file():
            raise ValueError('observer must be started first')
        write_marker(marker)
        return 0
    host = str(ipaddress.IPv4Address(args.host))
    if (lab.vm(timeout=15).get('runtime', {}).get('powerState') != 'poweredOn'
            or lab.guest_ip(timeout=30) != host):
        raise ValueError('owned guest address mismatch')
    if marker.exists():
        raise ValueError('prior marker exists')
    if not (lab.sec / 'known_hosts').is_file() or not (lab.sec / 'id_ed25519').is_file():
        raise ValueError('existing pinned operator access required')
    probes = {'tcp_ssh': lambda: tcp_probe(host, args.ssh_port),
              'proxy_health': lambda: health_probe(host, args.proxy_port),
              'operator_status': lambda: ssh_probe(lab, host, args.ssh_port)}
    with output.open('x', encoding='utf-8') as stream, ThreadPoolExecutor(max_workers=3) as pool:
        def emit(row):
            stream.write(json.dumps(row, separators=(',', ':')) + '\n')
            stream.flush()
        emit({'event': 'observer_started', **stamp(), 'schema_version': 1,
              'ssh_port': args.ssh_port, 'proxy_port': args.proxy_port,
              'note': 'Readiness samples only; no proof of reboot or dispatch.'})
        deadline = time.monotonic() + args.seconds
        recorded = False
        states = {}
        while time.monotonic() < deadline:
            cycle = time.monotonic()
            pending = read_marker(marker)
            if pending and not recorded:
                emit(pending)
                recorded = True
            futures = [pool.submit(measured, name, probe) for name, probe in probes.items()]
            for future in futures:
                emit(transition(states, future.result(timeout=10), recorded))
            if recorded and len(states) == len(probes) and all(state['returned'] for state in states.values()):
                emit({'event': 'all_services_returned_after_failure', **stamp()})
                break
            time.sleep(max(0, min(args.interval - (time.monotonic() - cycle), deadline - time.monotonic())))
        emit({'event': 'observer_finished', **stamp(), 'dispatch_marker_observed': recorded})
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Timing observer failed; retain recorded samples; no action dispatched.', file=sys.stderr)
        sys.exit(90)
