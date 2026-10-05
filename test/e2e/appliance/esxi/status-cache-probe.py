#!/usr/bin/env python3
"""One authorized LAB cancellation, then bounded read-only cache observations.

No reboot, service change, console access, SSH or cancellation retry. Detailed
responses are private. This experiment cannot attribute a historical outage.
Keep all other status/backups callers idle throughout the experiment.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
import importlib.util
import json
from pathlib import Path
import socket
import ssl
import time
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('status_probe_recovery', HERE / 'production-recovery-probes.py')
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)
require = recovery.require
WAIT_SECONDS = 17
CANCEL_SECONDS = 0.1
POLL_SECONDS = 20
MAX_PRIVATE = 8 * 1024 * 1024


def private_json(path, root, limit=MAX_PRIVATE):
    require(path.resolve().is_relative_to(root.resolve()) and not path.is_symlink()
            and path.is_file() and path.stat().st_size <= limit, 'private bounded input required')
    return json.loads(path.read_bytes())


def verify_binding(lab, baseline, identity, receipt, raw, owner_uuid):
    require(str(uuid.UUID(owner_uuid)) == owner_uuid == lab.state['uuid'].lower(), 'owned UUID differs')
    require(baseline['source_sha'] == lab.c['source_sha'] and baseline['image_id'] == lab.c['image_id'], 'baseline differs')
    require(receipt['exit_code'] == 0 and receipt['raw_sha256'] == hashlib.sha256(raw).hexdigest(), 'identity transport differs')
    require(identity['identity']['source_revision'] == lab.c['source_sha']
            and identity['identity']['source_dirty'] is False, 'source differs')
    commands = {row['name']: row for row in identity['full']['commands']}
    require(commands['culvert_state']['result'] == 'ok'
            and json.loads(commands['culvert_state']['output'])['image_id'] == lab.c['image_id'], 'image differs')
    installation = identity['full']['sampler_installation_receipt']
    require(installation['result'] == 'ok' and installation['receipt']['owner_uuid'] == owner_uuid,
            'authenticated identity belongs to another VM')


class PrivateRows:
    def __init__(self, stream):
        self.stream, self.size, self.count = stream, 0, 0

    def emit(self, row):
        raw = json.dumps(row, separators=(',', ':')).encode() + b'\n'
        require(self.size + len(raw) <= MAX_PRIVATE and self.count < 32, 'evidence bound exceeded')
        self.stream.write(raw)
        self.stream.flush()
        self.size += len(raw)
        self.count += 1


def observation(client, path, timeout, kind):
    row = {'kind': kind, 'started': recovery.stamp()}
    try:
        code, raw, _ = client.request(9090, path, timeout, cookie=client.cookie, tls=True)
        row.update(http_status=code, body_utf8=raw.decode('utf-8'), body_sha256=hashlib.sha256(raw).hexdigest())
        row['value'] = json.loads(raw)
        row['transport_ok'] = True
    except Exception as exc:
        # Never copy exception messages: they can contain URLs or credentials.
        row.update(transport_ok=False, error_type=type(exc).__name__)
    row['ended'] = recovery.stamp()
    return row


def cancel_once(client, connection_factory=None, clock=time.monotonic_ns):
    """Complete TLS first, send one GET, then close at a fixed 100 ms deadline.

    A readable response before that deadline makes the attempt inconclusive;
    there is never a second cancellation to improve the result.
    """
    factory = connection_factory or (lambda: http.client.HTTPSConnection(
        client.host, 9090, timeout=3, context=ssl._create_unverified_context()))
    conn = factory()
    row = {'kind': 'single_cancellation', 'started': recovery.stamp(), 'cancel_budget_ns': 100_000_000}
    try:
        conn.connect()  # TLS handshake is deliberately outside the cancellation window.
        row['tls_connected_ns'] = clock()
        conn.request('GET', '/api/maintenance-agent', headers={
            'Cookie': client.cookie, 'Connection': 'close', 'Origin': 'https://' + client.host + ':9090'})
        sent = clock()
        row['headers_sent_ns'] = sent
        # One SSL read of one application byte has one fixed socket deadline;
        # do not parse headers with per-read timeouts. TLS session tickets do
        # not count as an HTTP response. Any application byte is inconclusive.
        conn.sock.settimeout(CANCEL_SECONDS)
        try:
            first = conn.sock.recv(1)
            row['response_data_before_cancel'] = True if first else None
        except (socket.timeout, TimeoutError):
            row['response_data_before_cancel'] = False
        except OSError as exc:
            row.update(response_data_before_cancel=None, error_type=type(exc).__name__)
        row['cancel_started_ns'] = clock()
        try:
            conn.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        row['cancelled'] = True
        row['cancel_elapsed_ns'] = row['cancel_started_ns'] - sent
        # Scheduling cannot guarantee 100 ms wall-clock precision. Record any
        # overrun instead of reporting an unearned bounded-cancellation proof.
        row['within_schedule_tolerance'] = 0 <= row['cancel_elapsed_ns'] <= 150_000_000
    finally:
        conn.close()
    row['ended'] = recovery.stamp()
    return row


def classify(cancel, statuses, backup, baseline):
    negatives = [r for r in statuses if r.get('transport_ok') and r.get('http_status') == 200
                 and r.get('value', {}).get('available') is False
                 and 'context canceled' in str(r.get('value', {}).get('reason', '')).lower()]
    recovered = [r for r in statuses if r.get('transport_ok') and r.get('http_status') == 200
                 and recovery.agent_verdict(r.get('value', {}))
                 and r['value'].get('agent_version') == baseline['agent_version']]
    entries = backup.get('value', {}).get('backups', [])
    expected = baseline['backup']
    backup_ok = (backup.get('transport_ok') is True and backup.get('http_status') == 200
                 and backup.get('value', {}).get('available') is True and isinstance(entries, list)
                 and backup['value'].get('count') == len(entries)
                 and sum(isinstance(x, dict) and all(x.get(k) == expected[k] for k in ('filename', 'size_bytes', 'encrypted'))
                         for x in entries) == 1)
    repeated = len(negatives) >= 2 and len({r['body_sha256'] for r in negatives}) == 1
    ordered_recovery = repeated and any(r['started']['monotonic_ns'] > negatives[-1]['ended']['monotonic_ns'] for r in recovered)
    attempted = cancel.get('cancelled') is True and cancel.get('response_data_before_cancel') is False and cancel.get('within_schedule_tolerance') is True
    observed = bool(attempted and repeated and ordered_recovery and backup_ok
                    and all(r.get('transport_ok') is True and r.get('http_status') == 200 for r in statuses))
    return {'result': 'observed' if observed else 'inconclusive',
            'cancellation_negative_cache_pattern': observed,
            'status_samples': len(statuses), 'context_cancelled_samples': len(negatives),
            'fresh_backup_listing_matches': backup_ok,
            'historical_A1_attribution': 'not_established'}


def experiment(client, baseline, emit, clock=time.monotonic, sleep=time.sleep,
               cancel=cancel_once, observe=observation):
    # Existing complete baseline checks include pinned read-only SSH, persisted
    # CA/policy/version, authenticated admin, real allow/block and public health.
    initial = recovery.sample(client, baseline)
    emit({'kind': 'baseline', 'observation': initial})
    require(initial['healthy'] is True, 'baseline unhealthy; cancellation refused')
    sleep(WAIT_SECONDS)  # Also expires the backups listing's 15-second cache.
    require(all(client.public(k, clock() + 3)['ok'] for k in ('health', 'ready')), 'pre-cancellation public health changed')
    cancelled = cancel(client)
    emit(cancelled)
    statuses = []
    start = clock()
    with ThreadPoolExecutor(max_workers=1) as pool:
        # Independent read-only path: exactly one listing, never cancel/retry it
        # deliberately. Fixed five-second request deadline preserves its cost.
        future = pool.submit(observe, client, '/api/backups', 5, 'fresh_backup_listing')
        for index in range(POLL_SECONDS):
            target = start + index
            sleep(max(0, target - clock()))
            if clock() >= start + POLL_SECONDS:
                break
            if clock() > target + 0.5:
                continue  # No burst of catch-up requests following a slow read.
            row = observe(client, '/api/maintenance-agent', 0.9, 'status')
            statuses.append(row)
            emit(row)
            if row.get('transport_ok') is not True:
                # A timeout can itself cancel another request; stop instead of
                # accidentally turning this into a repeated cancellation test.
                break
        backup = future.result(timeout=6)
        emit(backup)
    return classify(cancelled, statuses, backup, baseline)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', required=True, type=Path)
    parser.add_argument('--baseline', required=True, type=Path)
    parser.add_argument('--identity', required=True, type=Path, help='existing authenticated private full.json')
    parser.add_argument('--owner-uuid', required=True)
    args = parser.parse_args()
    from timing_capture import load_lab
    lab = load_lab(args.scope)
    bootstrap = importlib.util.spec_from_file_location('status_probe_bootstrap', HERE / 'bootstrap-checks.py')
    module = importlib.util.module_from_spec(bootstrap)
    bootstrap.loader.exec_module(module)
    with module.module.locked(lab.run):
        baseline = private_json(args.baseline, lab.sec)
        identity = private_json(args.identity, lab.sec)
        receipt = private_json(args.identity.with_name('full-receipt.json'), lab.sec, 65536)
        verify_binding(lab, baseline, identity, receipt, args.identity.read_bytes(), args.owner_uuid)
        lab.vm(timeout=30)
        host = lab.guest_ip(timeout=30)
        import shutil
        operator = {'ssh': shutil.which('ssh'), 'key': str(lab.sec / 'id_ed25519'),
                    'known_hosts': str(lab.sec / 'known_hosts'), 'alias': lab.state['name']}
        require(operator['ssh'] and all(Path(operator[k]).is_file() for k in ('key', 'known_hosts')), 'pinned operator prerequisites missing')
        password_path = lab.sec / 'admin-pass'
        require(not password_path.is_symlink() and password_path.stat().st_size <= 4096, 'private credential invalid')
        client = recovery.Client(host, 'labadmin', password_path.read_text().rstrip('\r\n'), operator)
        # Fixed exclusive name prevents repetition under a new cosmetic label.
        output = lab.sec / 'status-cache-probe.jsonl'
        with output.open('xb') as stream:
            rows = PrivateRows(stream)
            rows.emit({'kind': 'binding', 'owner_uuid': args.owner_uuid, 'source_sha': lab.c['source_sha'],
                       'image_id': lab.c['image_id'], 'baseline_sha256': hashlib.sha256(args.baseline.read_bytes()).hexdigest(),
                       'identity_sha256': receipt['raw_sha256'], 'helper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                       'tls_policy': 'existing authorized lab certificate exception; VM API ownership and pinned operator checks'})
            try:
                result = experiment(client, baseline, rows.emit)
            except Exception as exc:
                result = {'result': 'blocked', 'error_type': type(exc).__name__, 'historical_A1_attribution': 'not_established'}
            rows.emit({'kind': 'summary', **result})
        result['private_evidence_sha256'] = hashlib.sha256(output.read_bytes()).hexdigest()
        with (lab.ev / 'status-cache-probe-summary.json').open('x', encoding='utf-8') as stream:
            json.dump(result, stream, indent=2)
        print(json.dumps(result))
        return 0 if result['result'] == 'observed' else 90


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(json.dumps({'result': 'blocked', 'error_type': type(exc).__name__}))
        raise SystemExit(90)
