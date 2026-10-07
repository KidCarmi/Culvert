#!/usr/bin/env python3
"""Bounded external reboot observations. Never dispatches a reboot or guest command.

All detailed observations stay private. Orchestration supplies the authenticated
acceptance marker and post-hoc authenticated guest clock/boot evidence. A probe
streak alone is never a qualified reboot PASS.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
from http.cookies import SimpleCookie
import ipaddress
import json
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
import uuid

INTERVAL_NS = 5_000_000_000
BUDGET_NS = 120_000_000_000
MEASUREMENT_NS = 900_000_000_000
MAX_BODY = 1024 * 1024
REQUIRED_READY = ('setup_complete', 'session_secret', 'ca', 'policy_loaded', 'policy_posture', 'clamav')


def require(value, message):
    if not value:
        raise ValueError(message)


def stamp():
    return {'monotonic_ns': time.monotonic_ns(), 'realtime_ns': time.time_ns()}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def policy_digest(policy, action):
    require(policy.get('draft') is False and policy.get('persisted') is True and policy.get('rules'), 'policy not persisted')
    rules = [{key: value for key, value in row.items() if key not in ('hitCount', 'lastHit')} for row in policy['rules']]
    require(action == 'deny', 'default-deny fixture required')
    return digest({'rules': rules, 'default_action': action})


def health_verdict(code, value):
    return (code == 200 and value.get('status') == 'ok' and value.get('clamav') == 'connected'
            and value.get('ssl_inspection') == 'ready' and value.get('setup_complete') is True)


def ready_verdict(code, value):
    checks = value.get('checks', {})
    return code == 200 and value.get('status') == 'ready' and all(checks.get(key, {}).get('status') == 'ok' for key in REQUIRED_READY)


def agent_verdict(value):
    return (value.get('available') is True and value.get('compose_stack_up') is True
            and re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.]+)?', str(value.get('agent_version'))) is not None)


def operator_verdict(value):
    return (value.get('schema_version') == 1 and value.get('phase') == 'ready'
            and value.get('application_responding') is True and value.get('management_available') is True)


def operator_probe(config, host, deadline):
    require(config is not None, 'pinned operator access not configured')
    timeout = min(4, deadline - time.monotonic())
    require(timeout > 0, 'operator deadline exhausted')
    argv = [config['ssh'], '-T', '-n', '-F', 'none', '-i', config['key'], '-o', 'IdentitiesOnly=yes',
            '-o', 'IdentityAgent=none', '-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=publickey',
            '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + config['known_hosts'],
            '-o', 'GlobalKnownHostsFile=none', '-o', 'HostKeyAlias=' + config['alias'],
            '-o', 'ConnectTimeout=3', 'culvert-operator@' + host, 'status-json']
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    expired = threading.Event()
    def stop():
        expired.set()
        try:
            process.kill()
        except OSError:
            pass
    timer = threading.Timer(timeout, stop)
    timer.start()
    try:
        raw = process.stdout.read(65537)
        if len(raw) > 65536:
            stop()
        code = process.wait(timeout=0.5)
        require(not expired.is_set() and len(raw) <= 65536 and code == 0, 'operator status unavailable or exceeded bound')
        value = json.loads(raw)
        return {'ok': operator_verdict(value), 'phase': value.get('phase') if value.get('phase') == 'ready' else 'not_ready'}
    finally:
        timer.cancel()
        if process.poll() is None:
            stop()
            process.wait(timeout=0.5)
        process.stdout.close()


class Client:
    def __init__(self, host, username, password, operator=None):
        self.host = str(ipaddress.IPv4Address(host))
        self.username, self.password = username, password
        self.cookie, self.login_ns = '', None
        self.operator = operator

    def reset_session(self):
        self.cookie, self.login_ns = '', None

    def request(self, port, path, timeout, payload=None, cookie='', tls=False, proxy_host=None):
        require(timeout > 0, 'request deadline exhausted')
        connection = (http.client.HTTPSConnection(self.host, port, timeout=timeout,
                        context=ssl._create_unverified_context()) if tls else
                      http.client.HTTPConnection(self.host, port, timeout=timeout))
        expired = threading.Event()
        def stop():
            expired.set()
            sock = connection.sock
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection.close()
        timer = threading.Timer(timeout, stop)
        timer.start()
        try:
            headers = {'Connection': 'close'}
            if cookie:
                headers['Cookie'] = cookie
            if proxy_host:
                headers['Host'] = proxy_host
            if tls:
                headers['Origin'] = 'https://' + self.host + ':9090'
            data = None if payload is None else json.dumps(payload).encode()
            if data is not None:
                headers['Content-Type'] = 'application/json'
            connection.request('GET' if data is None else 'POST', path, body=data, headers=headers)
            response = connection.getresponse()
            # Traffic verdict is the actual proxy HTTP status, without following redirects.
            raw = b'' if proxy_host else response.read(MAX_BODY + 1)
            require(not expired.is_set() and len(raw) <= MAX_BODY, 'request deadline or body bound exceeded')
            return response.status, raw, response.getheaders()
        finally:
            timer.cancel()
            connection.close()

    def api(self, path, deadline, payload=None):
        code, raw, headers = self.request(9090, path, max(0, deadline - time.monotonic()), payload, self.cookie, tls=True)
        require(code == 200, 'authenticated API unavailable')
        value = json.loads(raw)
        if payload is not None:
            require(value.get('ok') is True and value.get('user') == self.username
                    and value.get('role') == 'admin', 'persisted administrator not authenticated')
            cookies = SimpleCookie()
            for key, data in headers:
                if key.lower() == 'set-cookie':
                    cookies.load(data)
            require(cookies, 'authenticated session cookie absent')
            self.cookie = '; '.join(key + '=' + morsel.value for key, morsel in cookies.items())
            self.login_ns = time.monotonic_ns()
        return value

    def authenticated(self, baseline, deadline):
        if not self.cookie:
            self.api('/api/auth/login', deadline, {'user': self.username, 'pass': self.password})
        agent = self.api('/api/maintenance-agent', deadline)
        scan = self.api('/api/security-scan/status', deadline)
        policy = self.api('/api/policy', deadline)
        action = self.api('/api/default-action', deadline)
        code, certificate, _ = self.request(9090, '/api/ca-cert', max(0, deadline - time.monotonic()), cookie=self.cookie, tls=True)
        require(code == 200, 'CA certificate unavailable')
        ca = hashlib.sha256(ssl.PEM_cert_to_DER_cert(certificate.decode('ascii'))).hexdigest()
        snapshot = {'policy_sha256': policy_digest(policy, action.get('defaultAction')), 'ca_sha256': ca,
                    'agent_version': agent.get('agent_version')}
        checks = {'admin': self.login_ns is not None, 'agent': agent_verdict(agent),
                  'clamav_scan': scan.get('enabled') is True and scan.get('clamav_status') == 'connected',
                  'policy': baseline is None or snapshot['policy_sha256'] == baseline['policy_sha256'],
                  'ca': baseline is None or ca == baseline['ca_sha256'],
                  'agent_version': baseline is None or snapshot['agent_version'] == baseline['agent_version']}
        return {'checks': checks, 'snapshot': snapshot, 'admin_login_monotonic_ns': self.login_ns}

    def public(self, kind, deadline):
        target = {'health': '/health', 'ready': '/ready', 'allow': 'http://example.com/', 'block': 'http://example.org/'}[kind]
        proxy = {'allow': 'example.com', 'block': 'example.org'}.get(kind)
        code, raw, _ = self.request(8080, target, max(0, deadline - time.monotonic()), proxy_host=proxy)
        if proxy:
            return {'ok': code == (200 if kind == 'allow' else 403), 'http_status': code}
        value = json.loads(raw)
        if kind == 'health':
            ok = health_verdict(code, value)
        else:
            ok = ready_verdict(code, value)
        return {'ok': ok, 'http_status': code}

    def backup(self, expected):
        attempt = time.monotonic_ns()
        row = {'event': 'first_ready_backup', 'attempt_started_monotonic_ns': attempt,
               'fresh_login': False}
        try:
            # Process-local session keys can change at reboot. This single
            # background attempt owns a separate fresh session, so observation
            # resets cannot invalidate or replace the first listing's cookie.
            fresh = Client(self.host, self.username, self.password, self.operator)
            fresh.api('/api/auth/login', time.monotonic() + 5,
                      {'user': fresh.username, 'pass': fresh.password})
            row['login_finished_monotonic_ns'] = time.monotonic_ns()
            row['login_elapsed_ns'] = row['login_finished_monotonic_ns'] - attempt
            require(fresh.cookie and fresh.login_ns is not None and row['login_elapsed_ns'] <= INTERVAL_NS,
                    'fresh backup login unavailable or exceeded bound')
            row['fresh_login'] = True
            row['started_monotonic_ns'] = time.monotonic_ns()
            value = fresh.api('/api/backups', time.monotonic() + 5)
            row['available'] = value.get('available') is True
            rows = value.get('backups')
            require(isinstance(rows, list) and type(value.get('count')) is int and value['count'] == len(rows), 'backup listing malformed')
            matches = [item for item in rows if item.get('filename') == expected['filename']]
            row['archive_matches'] = len(matches) == 1 and all(matches[0].get(key) == expected[key] for key in ('size_bytes', 'encrypted'))
            row['result'] = 'pass' if row['available'] and row['archive_matches'] else 'fail'
        except Exception as exc:
            row.update(result='fail', error=type(exc).__name__)
        row['ended_monotonic_ns'] = time.monotonic_ns()
        row['elapsed_ns'] = (row['ended_monotonic_ns'] - row['started_monotonic_ns']
                             if 'started_monotonic_ns' in row else None)
        if row['elapsed_ns'] is None or row['elapsed_ns'] > INTERVAL_NS:
            row['result'] = 'fail'
        return row


def sample(client, baseline):
    start = time.monotonic_ns()
    deadline = time.monotonic() + 4.5
    probes = {kind: (lambda name=kind: client.public(name, deadline)) for kind in ('health', 'ready', 'allow', 'block')}
    probes['authenticated'] = lambda: client.authenticated(baseline, deadline)
    probes['operator'] = lambda: operator_probe(client.operator, client.host, deadline)
    row = {'event': 'sample', 'started_monotonic_ns': start, 'started_realtime_ns': time.time_ns(), 'probes': {}}
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {kind: pool.submit(call) for kind, call in probes.items()}
        for kind, future in futures.items():
            try:
                row['probes'][kind] = future.result(timeout=6)
            except Exception as exc:
                row['probes'][kind] = {'ok': False, 'error': type(exc).__name__}
    auth = row['probes']['authenticated']
    row['healthy'] = all(row['probes'][key].get('ok') is True for key in ('health', 'ready', 'allow', 'block', 'operator')) and bool(auth.get('checks')) and all(value is True for value in auth['checks'].values())
    row['external_outage'] = 'error' in row['probes']['health'] or row['probes']['health'].get('http_status') != 200
    row['admin_login_monotonic_ns'] = auth.get('admin_login_monotonic_ns')
    row['ended_monotonic_ns'] = time.monotonic_ns()
    if row['ended_monotonic_ns'] - start > INTERVAL_NS:
        row['healthy'] = False
        row['overran_sample_interval'] = True
    return row


def acceptance_record(value, baseline):
    require(value.get('schema') == 1 and value.get('kind') == 'maintenance_accepted'
            and value.get('source_sha') == baseline['source_sha'] and value.get('image_id') == baseline['image_id']
            and isinstance(value.get('cycle_id'), str) and value['cycle_id']
            and isinstance(value.get('operation_id'), str) and value['operation_id']
            and type(value.get('controller_monotonic_ns')) is int and value['controller_monotonic_ns'] > 0,
            'authenticated acceptance binding invalid')
    require(str(uuid.UUID(value['old_boot_id'])) == value['old_boot_id'], 'invalid original boot')
    return value


def consecutive(left, right):
    gap = right['started_monotonic_ns'] - left['started_monotonic_ns']
    if not INTERVAL_NS - 500_000_000 <= gap <= INTERVAL_NS + 500_000_000:
        return False
    if 'scheduled_monotonic_ns' in left and 'scheduled_monotonic_ns' in right:
        return right['scheduled_monotonic_ns'] - left['scheduled_monotonic_ns'] == INTERVAL_NS
    return True


def capture_baseline(client, source_sha, image_id, backup_name=None):
    observed = sample(client, None)
    require(observed['healthy'], 'baseline enforcement, ClamAV, agent or persistence prerequisite failed')
    listing = client.api('/api/backups', time.monotonic() + 10)
    require(listing.get('available') is True and isinstance(listing.get('backups'), list), 'baseline backup unavailable')
    entries = listing['backups']
    require(type(listing.get('count')) is int and listing['count'] == len(entries), 'baseline backup count invalid')
    selected = [row for row in entries if row.get('filename') == backup_name] if backup_name else entries[:1]
    require(len(selected) == 1, 'exact baseline archive unavailable')
    entry = selected[0]
    require(isinstance(entry.get('filename'), str) and entry['filename'] and type(entry.get('size_bytes')) is int
            and entry['size_bytes'] > 0 and entry.get('encrypted') is True, 'baseline encrypted archive invalid')
    return {'schema': 1, 'source_sha': source_sha, 'image_id': image_id,
            **observed['probes']['authenticated']['snapshot'],
            'backup': {key: entry[key] for key in ('filename', 'size_bytes', 'encrypted')},
            'captured_at': stamp()}


def observe(client, baseline, marker, emit, clock=time.monotonic_ns, sleep=time.sleep, sampler=sample):
    """Observe one accepted reboot, returning candidate timing, not a reboot PASS."""
    start, accepted, outage, healthy, backup_future = clock(), None, False, [], None
    budget_expired = False
    acceptance_hash = None
    backup_trigger = None
    next_tick = start
    with ThreadPoolExecutor(max_workers=1) as backup_pool:
        while True:
            now = clock()
            if marker.exists():
                require(not marker.is_symlink() and marker.stat().st_size <= 65536, 'acceptance file invalid')
                value = acceptance_record(json.loads(marker.read_bytes()), baseline)
                current_hash = digest(value)
                require(acceptance_hash is None or acceptance_hash == current_hash, 'acceptance changed during observation')
                if accepted is None:
                    accepted, acceptance_hash = value, current_hash
                    require(accepted['controller_monotonic_ns'] <= now, 'future acceptance marker')
                    emit({'event': 'acceptance', **accepted})
            deadline = start + 300_000_000_000 if accepted is None else accepted['controller_monotonic_ns'] + MEASUREMENT_NS
            if accepted is not None and not budget_expired and now >= accepted['controller_monotonic_ns'] + BUDGET_NS:
                budget_expired = True
                emit({'event': 'readiness_budget_exceeded', 'result': 'fail', 'monotonic_ns': now,
                      'budget_seconds': 120, 'note': 'Later recovery is measured but cannot replace this failure.'})
            if now >= deadline:
                break
            row = sampler(client, baseline)
            row['scheduled_monotonic_ns'] = next_tick
            row['after_acceptance'] = accepted is not None and row['started_monotonic_ns'] >= accepted['controller_monotonic_ns']
            if row['after_acceptance']:
                if row['external_outage']:
                    outage = True
                    client.reset_session()
                if outage and row['healthy'] and row['ended_monotonic_ns'] <= deadline:
                    if healthy and not consecutive(healthy[-1], row):
                        healthy = []
                    healthy.append(row)
                    if backup_future is None:
                        # One attempt only: a later cache hit cannot erase first-list latency/failure.
                        backup_future = backup_pool.submit(client.backup, baseline['backup'])
                        backup_trigger = row['started_monotonic_ns']
                else:
                    healthy = []
            emit(row)
            if len(healthy) >= 3:
                if backup_future is not None:
                    emit(dict(backup_future.result(timeout=12), trigger_sample_started_monotonic_ns=backup_trigger))
                    backup_future = None
                late = budget_expired or healthy[-1]['ended_monotonic_ns'] > accepted['controller_monotonic_ns'] + BUDGET_NS
                return {'result': 'fail' if late else 'blocked',
                        'reason': 'recovered_after_120_second_budget' if late else 'pending_authenticated_boot_proof',
                        'measurement_complete': True,
                        'observed_ready_monotonic_ns': healthy[-1]['ended_monotonic_ns']}
            next_tick += INTERVAL_NS
            sleep(max(0, min(next_tick - clock(), deadline - clock())) / 1e9)
        if backup_future is not None:
            emit(dict(backup_future.result(timeout=12), trigger_sample_started_monotonic_ns=backup_trigger))
    return {'result': 'fail' if accepted is not None else 'blocked',
            'reason': 'not_recovered_within_900_seconds' if accepted is not None else 'acceptance_not_observed',
            'measurement_complete': False}


def boot_window(proof, accepted, baseline):
    require(proof.get('schema') == 1 and proof.get('cycle_id') == accepted['cycle_id']
            and proof.get('source_sha') == baseline['source_sha'] and proof.get('image_id') == baseline['image_id']
            and proof['boot_id'] != accepted['old_boot_id'] and str(uuid.UUID(proof['boot_id'])) == proof['boot_id'],
            'different exact-source boot not proven')
    c = proof['correlation']
    lo, hi = c['controller_started_monotonic_ns'], c['controller_finished_monotonic_ns']
    require(all(type(c[key]) is int and c[key] > 0 for key in ('controller_started_monotonic_ns', 'controller_finished_monotonic_ns',
            'controller_started_realtime_ns', 'controller_finished_realtime_ns', 'guest_monotonic_ns', 'guest_realtime_ns')),
            'clock correlation invalid')
    require(0 <= hi - lo <= 30_000_000_000, 'guest clock correlation too uncertain')
    require(abs((c['controller_finished_realtime_ns'] - c['controller_started_realtime_ns']) - (hi - lo)) <= 1_000_000_000,
            'controller realtime clock stepped')
    rows = proof['samples']
    require(isinstance(rows, list) and len(rows) >= 2, 'paired guest clock samples missing')
    offsets = []
    previous = -1
    for row in rows:
        require(row['boot_id'] == proof['boot_id'] and type(row['monotonic_ns']) is int and type(row['realtime_ns']) is int
                and row['monotonic_ns'] > previous, 'guest clock samples invalid')
        previous = row['monotonic_ns']
        offsets.append(row['realtime_ns'] - row['monotonic_ns'])
    offsets.append(c['guest_realtime_ns'] - c['guest_monotonic_ns'])
    require(max(offsets) - min(offsets) <= 1_000_000_000, 'guest realtime clock stepped')
    return lo - c['guest_monotonic_ns'], hi - c['guest_monotonic_ns']


def clamav_coverage(proof, selected, low, high):
    """Require current-container PONGs bracketing the entire uncertain interval."""
    require(proof.get('clamav_endpoint_binding_verified') is True,
            'current ClamAV container endpoint binding not verified')
    begin = selected[0]['started_monotonic_ns'] - high - 2_500_000_000
    finish = selected[-1]['ended_monotonic_ns'] - low + 2_500_000_000
    require(0 <= begin < finish, 'ClamAV coverage guest interval invalid')
    samples = proof['samples']
    before = [index for index, row in enumerate(samples) if row['monotonic_ns'] <= begin]
    after = [index for index, row in enumerate(samples) if row['monotonic_ns'] >= finish]
    require(before and after, 'direct ClamAV PONG coverage does not bracket readiness interval')
    covered = samples[before[-1]:after[0] + 1]
    points = []
    for row in covered:
        ping = row.get('clamav_ping')
        require(isinstance(ping, dict) and ping.get('pong') is True,
                'direct ClamAV PONG missing or failed during readiness interval')
        start, end, elapsed = (ping.get(key) for key in
                               ('started_monotonic_ns', 'ended_monotonic_ns', 'elapsed_ns'))
        require(all(type(value) is int for value in (start, end, elapsed))
                and row['monotonic_ns'] <= start <= row['monotonic_ns'] + 1_000_000_000
                and end - start == elapsed and 0 <= elapsed <= 1_000_000_000,
                'direct ClamAV PONG timestamps invalid or too slow')
        points.append(start)
    require(points[0] <= begin and points[-1] >= finish,
            'direct ClamAV PONG timestamps do not bracket readiness interval')
    gaps = [right - left for left, right in zip(points, points[1:])]
    require(gaps and all(0 < gap <= 3_000_000_000 for gap in gaps),
            'direct ClamAV PONG sampling gap exceeds three seconds')
    return {'guest_interval_start_ns': begin, 'guest_interval_end_ns': finish,
            'pong_samples': len(points), 'maximum_sample_gap_ns': max(gaps),
            'current_container_endpoint_verified': True}


def verify(rows, baseline, proof, confirmed_at=None):
    """Caller must authenticate the raw guest proof; no boolean substitutes for it."""
    budget_failed = False
    try:
        accepts = [row for row in rows if row.get('event') == 'acceptance']
        require(len(accepts) == 1, 'one immutable acceptance required')
        accepted = acceptance_record(accepts[0], baseline)
        budget_failed = any(row.get('event') == 'readiness_budget_exceeded'
                            and row.get('result') == 'fail' and row.get('budget_seconds') == 120
                            and type(row.get('monotonic_ns')) is int
                            and row['monotonic_ns'] >= accepted['controller_monotonic_ns'] + BUDGET_NS
                            for row in rows)
        low, high = boot_window(proof, accepted, baseline)
        require(high > accepted['controller_monotonic_ns'] and low <= high, 'new boot predates accepted reboot')
        deadline = accepted['controller_monotonic_ns'] + BUDGET_NS
        samples = [row for row in rows if row.get('event') == 'sample']
        outage, streak, winner, first_ready = False, [], None, None
        for row in samples:
            start, end = row['started_monotonic_ns'], row['ended_monotonic_ns']
            require(type(start) is int and type(end) is int and end >= start, 'sample timestamps invalid')
            if start < accepted['controller_monotonic_ns']:
                continue
            outage = outage or row.get('external_outage') is True
            if outage and row.get('healthy') is True and first_ready is None:
                first_ready = row
            qualifies = (outage and row.get('healthy') is True and start > high
                         and type(row.get('admin_login_monotonic_ns')) is int and row['admin_login_monotonic_ns'] > high)
            if not qualifies or (streak and not consecutive(streak[-1], row)):
                streak = []
            if qualifies:
                streak.append(row)
                if len(streak) >= 3:
                    winner = streak[-1]
                    break
        if winner is None:
            return {'result': 'fail', 'reason': 'three_post_reboot_healthy_samples_not_proven_within_120_seconds',
                    'controller_confirmed_at': confirmed_at or stamp()}
        if winner['ended_monotonic_ns'] > deadline or any(row.get('event') == 'readiness_budget_exceeded' for row in rows):
            return {'result': 'fail', 'reason': 'recovered_after_120_second_budget',
                    'observed_ready_monotonic_ns': winner['ended_monotonic_ns'],
                    'seconds_to_three_healthy_samples': (winner['ended_monotonic_ns'] - accepted['controller_monotonic_ns']) / 1e9,
                    'controller_confirmed_at': confirmed_at or stamp()}
        backups = [row for row in rows if row.get('event') == 'first_ready_backup']
        require(len(backups) == 1, 'exactly one first post-ready backup attempt required')
        backup_pass = (backups[0].get('result') == 'pass' and backups[0].get('available') is True
                and backups[0].get('archive_matches') is True and backups[0].get('fresh_login') is True
                and backups[0]['attempt_started_monotonic_ns'] > high
                and backups[0].get('trigger_sample_started_monotonic_ns') == first_ready['started_monotonic_ns']
                and 0 <= backups[0]['attempt_started_monotonic_ns'] - first_ready['ended_monotonic_ns'] <= 1_000_000_000
                and backups[0]['login_finished_monotonic_ns'] - backups[0]['attempt_started_monotonic_ns'] == backups[0]['login_elapsed_ns']
                and 0 <= backups[0]['login_elapsed_ns'] <= INTERVAL_NS
                and 0 <= backups[0]['started_monotonic_ns'] - backups[0]['login_finished_monotonic_ns'] <= 1_000_000_000
                and backups[0]['ended_monotonic_ns'] - backups[0]['started_monotonic_ns'] == backups[0]['elapsed_ns']
                and 0 <= backups[0]['elapsed_ns'] <= INTERVAL_NS)
        if not backup_pass:
            return {'result': 'fail', 'reason': 'first_post_ready_backup_failed_or_exceeded_five_seconds',
                    'controller_confirmed_at': confirmed_at or stamp()}
        clamav = clamav_coverage(proof, streak[-3:], low, high)
        return {'result': 'pass', 'cycle_id': accepted['cycle_id'],
                'accepted_monotonic_ns': accepted['controller_monotonic_ns'],
                'observed_ready_monotonic_ns': winner['ended_monotonic_ns'],
                'controller_confirmed_at': confirmed_at or stamp(),
                'seconds_to_three_healthy_samples': (winner['ended_monotonic_ns'] - accepted['controller_monotonic_ns']) / 1e9,
                'first_backup_seconds': backups[0]['elapsed_ns'] / 1e9,
                'first_backup_login_seconds': backups[0]['login_elapsed_ns'] / 1e9,
                'boot_window_controller_monotonic_ns': [low, high],
                'direct_clamav_coverage': clamav,
                'note': 'Service timing only; guest lock/disk/unit/persistence evidence is qualified separately.'}
    except (ValueError, KeyError, TypeError, IndexError) as exc:
        if budget_failed:
            return {'result': 'fail', 'reason': 'readiness_budget_exceeded',
                    'proof_status': 'blocked', 'proof_reason': str(exc),
                    'controller_confirmed_at': confirmed_at or stamp()}
        return {'result': 'blocked', 'reason': str(exc), 'controller_confirmed_at': confirmed_at or stamp()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('baseline', 'observe', 'verify'), nargs='?', default='observe')
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--baseline', type=Path, required=True)
    parser.add_argument('--acceptance', type=Path)
    parser.add_argument('--label')
    parser.add_argument('--backup-name')
    parser.add_argument('--rows', type=Path)
    parser.add_argument('--proof', type=Path)
    args = parser.parse_args()
    from timing_capture import load_lab
    lab = load_lab(args.scope)
    require(args.baseline.resolve().is_relative_to(lab.sec.resolve()) and not args.baseline.is_symlink(), 'baseline must remain private')
    if args.mode == 'verify':
        require(args.label is not None and re.fullmatch(r'[a-zA-Z0-9_-]{1,48}', args.label), 'invalid verification label')
        for path in (args.rows, args.proof):
            require(path is not None and path.resolve().is_relative_to(lab.sec.resolve())
                    and not path.is_symlink() and path.is_file() and path.stat().st_size <= 8 * MAX_BODY,
                    'private bounded observation/proof required')
        baseline = json.loads(args.baseline.read_bytes())
        require(baseline['source_sha'] == lab.c['source_sha'] and baseline['image_id'] == lab.c['image_id'], 'scope baseline differs')
        rows = [json.loads(line) for line in args.rows.read_bytes().splitlines()]
        result = verify(rows, baseline, json.loads(args.proof.read_bytes()))
        result.update(proof_sha256=hashlib.sha256(args.proof.read_bytes()).hexdigest(),
                      rows_sha256=hashlib.sha256(args.rows.read_bytes()).hexdigest())
        with (lab.ev / ('production-recovery-' + args.label + '-summary.json')).open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(result, stream, indent=2)
        print(json.dumps(result))
        return 0 if result['result'] == 'pass' else 90
    operator = {'ssh': shutil.which('ssh'), 'key': str(lab.sec / 'id_ed25519'),
                'known_hosts': str(lab.sec / 'known_hosts'), 'alias': lab.state['name']}
    require(operator['ssh'] is not None and (lab.sec / 'id_ed25519').is_file()
            and (lab.sec / 'known_hosts').is_file(), 'existing pinned operator access required')
    client = Client(lab.guest_ip(timeout=30), 'labadmin', (lab.sec / 'admin-pass').read_text().rstrip('\r\n'), operator)
    if args.mode == 'baseline':
        baseline = capture_baseline(client, lab.c['source_sha'], lab.c['image_id'], args.backup_name)
        with args.baseline.open('x', encoding='utf-8', newline='\n') as stream:
            json.dump(baseline, stream, indent=2)
        print('PASS: authorized baseline captured privately; no reboot dispatched.')
        return 0
    require(args.label is not None and re.fullmatch(r'[a-zA-Z0-9_-]{1,48}', args.label), 'invalid observation label')
    require(args.acceptance is not None and args.acceptance.resolve().is_relative_to(lab.sec.resolve())
            and not args.acceptance.is_symlink(), 'acceptance must remain private')
    baseline = json.loads(args.baseline.read_bytes())
    require(baseline['source_sha'] == lab.c['source_sha'] and baseline['image_id'] == lab.c['image_id'], 'scope baseline differs')
    output = lab.sec / ('production-recovery-' + args.label + '.jsonl')
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        def emit(row):
            stream.write(json.dumps(row, separators=(',', ':')) + '\n'); stream.flush()
        result = observe(client, baseline, args.acceptance, emit)
        emit({'event': 'observation_finished', **result})
    print(json.dumps(result))
    return 0 if result['measurement_complete'] else 90


if __name__ == '__main__':
    raise SystemExit(main())
