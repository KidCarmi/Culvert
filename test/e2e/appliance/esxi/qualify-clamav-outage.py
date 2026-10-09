#!/usr/bin/env python3
"""Explicitly approved LAB candidates only: fresh-body ClamAV outage and recovery qualification.

Uses the existing PAM/sudo console boundary. No live action occurs on import.
Temporarily adds one authenticated policy rule and stops the exact running
sidecar under both maintenance locks. Reports are private except fixed verdicts.
"""
import argparse
import base64
import contextlib
import hashlib
import http.client
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

SOURCE = 'd698a69c5192588d5ed3a85a9f7cd9009fb59b31'
IMAGE = 'sha256:2c03833c9641a1e24dc5a66b3faa4f0695ac44cdeac931018b9b744be301660e'
SIDECAR = 'sha256:86d71850ea1a01fdbb9c06b82c929d4485718c1d80f19a0824c2c454c2bce97e'
MAX_BODY = 1024 * 1024
PRIOR_CONTROLLER = '4f17cd9392cc293d17e70c6f95eb1ca0b24a8685'
PRIOR_HELPER = '7c016022b42de6d00aaf85e4fae9e1e6e9e6f2d5fcad1cceec276e5cf4e5bcab'
STAGES = {'prepare', 'lock_os', 'lock_agent', 'maintenance_idle', 'source_identity',
          'sidecar_build_identity', 'firstboot', 'proxy_identity', 'sidecar_identity',
          'api_login', 'av_posture', 'policy_snapshot', 'default_deny', 'bridge_network',
          'fixture', 'ready_before', 'probe_before', 'stop', 'ready_down', 'probe_down',
          'restore', 'ready_recovered', 'probe_recovered', 'policy_cleanup'}


class CheckFailure(ValueError):
    def __init__(self, reason, code):
        super().__init__(reason)
        self.code = code


def need(ok, reason, code='condition_failed'):
    if not ok:
        raise CheckFailure(reason, code)


def failure_detail(backend, error):
    stage = getattr(backend, 'stage', 'prepare')
    code = error.code if isinstance(error, CheckFailure) else 'unexpected_error'
    if isinstance(error, (TimeoutError, subprocess.TimeoutExpired)):
        code = 'timeout'
    if isinstance(error, FileNotFoundError):
        code = 'required_path_missing'
    if isinstance(error, PermissionError):
        code = 'permission_denied'
    return {'stage': stage if stage in STAGES else 'prepare', 'code': code}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def policy_identity(value):
    need(value.get('draft') is False and value.get('persisted') is True, 'persisted policy required')
    rules = [{k: v for k, v in row.items() if k not in ('hitCount', 'lastHit')}
             for row in value['rules']]
    return sha(json.dumps(rules, sort_keys=True, separators=(',', ':')).encode())


def fresh_body(kind):
    if kind == 'clean':
        return b'CULVERT LAB clean content ' + secrets.token_hex(32).encode() + b'\n'
    need(kind == 'eicar', 'unknown fixture')
    # Standard harmless test signature constructed only at runtime. Unique
    # trailing whitespace changes the body hash without changing its meaning.
    signature = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$' + b'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    bits = int.from_bytes(secrets.token_bytes(7), 'big')
    return signature + bytes(b' \t'[(bits >> i) & 1] for i in range(56))


def body_verdict(phase, kind, code, body, expected):
    if phase == 'down':
        return code == 403 and b'antivirus scanning is currently unavailable' in body.lower()
    if kind == 'clean':
        return code == 200 and body == expected
    return code == 403 and b'Blocked by CLAMAV scan' in body


def observe(backend, phase, seen):
    records = []
    for kind in ('clean', 'eicar'):
        body = fresh_body(kind)
        digest = sha(body)
        need(digest not in seen, 'fixture body reused')
        seen.add(digest)
        code, raw, fetched = backend.probe(kind, body)
        ok = body_verdict(phase, kind, code, raw, body)
        # The running scanner must consume the actual origin body. A policy
        # deny, forged response or body-cache reuse is not a live scan proof.
        if phase != 'down':
            ok = ok and fetched
        records.append({'kind': kind, 'http_status': code, 'body_sha256': digest,
                        'response_sha256': sha(raw), 'origin_fetched': fetched, 'pass': ok})
    return records


def qualify(backend):
    result = {'schema': 1, 'result': 'fail', 'phases': {}, 'readiness': {}, 'errors': [],
              'failure_details': [], 'restored_running': False, 'policy_restored': False}
    seen = set()
    stop_attempted = False
    try:
        backend.stage = 'prepare'
        result['identity'] = backend.prepare()
        backend.stage = 'fixture'
        backend.install_fixture()
        backend.stage = 'ready_before'
        result['readiness']['before'] = backend.wait_ready(True)
        backend.stage = 'probe_before'
        result['phases']['before'] = observe(backend, 'before', seen)
        need(all(x['pass'] for x in result['phases']['before']), 'initial content verdict mismatch')
        stop_attempted = True  # stop may time out after it already changed state.
        backend.stage = 'stop'
        backend.stop()
        backend.stage = 'ready_down'
        result['readiness']['down'] = backend.wait_ready(False)
        backend.stage = 'probe_down'
        result['phases']['down'] = observe(backend, 'down', seen)
        need(all(x['pass'] for x in result['phases']['down']), 'outage content verdict mismatch')
    except Exception as error:
        result['errors'].append('qualification_failed')
        result['failure_details'].append(failure_detail(backend, error))
    finally:
        if stop_attempted:
            try:
                backend.stage = 'restore'
                backend.restore()
                result['restored_running'] = True
                backend.stage = 'ready_recovered'
                result['readiness']['recovered'] = backend.wait_ready(True)
                backend.stage = 'probe_recovered'
                result['phases']['recovered'] = observe(backend, 'recovered', seen)
                need(all(x['pass'] for x in result['phases']['recovered']), 'recovered content verdict mismatch')
            except Exception as error:
                result['errors'].append('sidecar_recovery_failed')
                result['failure_details'].append(failure_detail(backend, error))
        try:
            backend.stage = 'policy_cleanup'
            result['policy_restored'] = backend.cleanup_fixture()
        except Exception as error:
            result['errors'].append('policy_cleanup_failed')
            result['failure_details'].append(failure_detail(backend, error))
        backend.close()
    if (not result['errors'] and result['restored_running'] and result['policy_restored']
            and set(result['phases']) == {'before', 'down', 'recovered'}):
        result['result'] = 'pass'
    return result


def command(argv, timeout=15):
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    timer = threading.Timer(timeout, process.kill)
    timer.start()
    try:
        raw = process.stdout.read(65537)
        need(len(raw) <= 65536, 'command output limit')
        need(process.wait(timeout=1) == 0, 'command failed')
        return raw.decode('utf-8').strip()
    finally:
        timer.cancel()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=2)
        process.stdout.close()


def trusted_directory(path, info, service_ids):
    need(stat.S_ISDIR(info.st_mode), 'lock ancestor is not a directory', 'lock_directory_type')
    if path == '/var/lib/culvert-maint':
        need(info.st_uid == service_ids[0] and info.st_gid == service_ids[1]
             and stat.S_IMODE(info.st_mode) == 0o750,
             'dedicated maintenance directory owner or mode differs', 'maintenance_directory_identity')
    else:
        need(info.st_uid == 0 and not info.st_mode & 0o022,
             'untrusted root lock ancestor', 'root_directory_identity')


def trusted_lock(info):
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_gid == 0
         and info.st_nlink == 1 and not info.st_mode & 0o022,
         'untrusted root lock file', 'lock_file_identity')


def same_inode(opened, named):
    need((opened.st_dev, opened.st_ino, stat.S_IFMT(opened.st_mode))
         == (named.st_dev, named.st_ino, stat.S_IFMT(named.st_mode)),
         'maintenance lock path replaced', 'lock_path_replaced')


class HeldLock:
    """Descriptor-relative acquisition, with the product's dedicated owner.

    The service account is trusted to honour its cooperative lock protocol.
    Holding a flock does not prevent that owner from renaming its own directory
    entries; rechecks reject observed replacement rather than claiming otherwise.
    """
    def __init__(self, path, service_ids):
        import fcntl
        need(path in ('/run/culvert-os-update.lock', '/var/lib/culvert-maint/host-maintenance.lock'),
             'unexpected maintenance lock path', 'lock_path_refused')
        self.service_ids = service_ids
        self.fds = []
        self.links = []
        self.directories = []
        try:
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
            parent = os.open('/', flags)
            self.fds.append(parent)
            self.directories.append(('/', parent))
            trusted_directory('/', os.fstat(parent), service_ids)
            current = ''
            parts = path.split('/')[1:]
            for name in parts[:-1]:
                current += '/' + name
                child = os.open(name, flags, dir_fd=parent)
                self.fds.append(child)
                self.links.append((parent, name, child))
                self.directories.append((current, child))
                trusted_directory(current, os.fstat(child), service_ids)
                same_inode(os.fstat(child), os.stat(name, dir_fd=parent, follow_symlinks=False))
                parent = child
            self.fd = os.open(parts[-1], os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=parent)
            self.fds.append(self.fd)
            self.links.append((parent, parts[-1], self.fd))
            trusted_lock(os.fstat(self.fd))
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise CheckFailure('maintenance lock held', 'maintenance_busy') from None
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for path, fd in self.directories:
            trusted_directory(path, os.fstat(fd), self.service_ids)
        trusted_lock(os.fstat(self.fd))
        for parent, name, fd in self.links:
            same_inode(os.fstat(fd), os.stat(name, dir_fd=parent, follow_symlinks=False))

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []


def service_identity():
    import grp
    import pwd
    account = pwd.getpwnam('culvert-maint')
    group = grp.getgrnam('culvert-maint')
    need(account.pw_uid > 0 and group.gr_gid > 0 and account.pw_gid == group.gr_gid,
         'dedicated maintenance account differs', 'maintenance_account_identity')
    return account.pw_uid, group.gr_gid


def maintenance_idle(maint=Path('/var/lib/culvert-maint'), state=Path('/var/lib/culvert-appliance/state')):
    for path in (maint / 'host-shutdown.pending', state / 'stack-resume-on-boot'):
        need(not os.path.lexists(path), 'pending host maintenance refused')
    journal = maint / 'reconcile'
    if os.path.lexists(journal):
        need(journal.is_dir() and not journal.is_symlink(), 'unexpected maintenance journal')
        with os.scandir(journal) as entries:
            for count, entry in enumerate(entries):
                need(count < 256, 'maintenance journal inventory limit')
                need(not entry.name.endswith('.json') and '.corrupt.' not in entry.name,
                     'interrupted maintenance refused')


class Guest:
    def __init__(self, config):
        self.config = config
        self.cookie = ''
        self.locks = []
        self.server = None
        self.thread = None
        self.before = None
        self.rule_name = 'lab-clamav-outage-' + config['operation']
        self.rule = None
        self.fixture_attempted = False
        self.payloads = {}
        self.fetched = set()

    def request(self, port, path, method='GET', payload=None, tls=False):
        connection = (http.client.HTTPSConnection('127.0.0.1', port, timeout=5,
                      context=ssl._create_unverified_context()) if tls else
                      http.client.HTTPConnection('127.0.0.1', port, timeout=5))
        def stop():
            if connection.sock is not None:
                try:
                    connection.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            connection.close()
        timer = threading.Timer(6, stop)
        timer.start()
        try:
            headers = {'Connection': 'close', 'Origin': 'https://127.0.0.1:9090'}
            if tls and self.cookie:
                headers['Cookie'] = self.cookie
            data = None
            if payload is not None:
                headers['Content-Type'] = 'application/json'
                data = json.dumps(payload).encode()
            connection.request(method, path, data, headers)
            response = connection.getresponse()
            raw = response.read(MAX_BODY + 1)
            need(len(raw) <= MAX_BODY, 'HTTP body limit')
            return response.status, raw, response.getheaders()
        finally:
            timer.cancel()
            connection.close()

    def api(self, path, method='GET', payload=None):
        changing_policy = method in ('POST', 'PUT', 'DELETE') and path.startswith('/api/policy')
        if changing_policy:
            self.check_locks()
        code, raw, headers = self.request(9090, path, method, payload, tls=True)
        if changing_policy:
            self.check_locks()
        need(code in (200, 201, 204), 'authenticated API failed')
        if path == '/api/auth/login':
            value = json.loads(raw)
            need(value.get('ok') is True and value.get('user') == 'labadmin'
                 and value.get('role') == 'admin', 'administrator login refused')
            cookies = SimpleCookie()
            for key, value in headers:
                if key.lower() == 'set-cookie':
                    cookies.load(value)
            need(bool(cookies), 'session absent')
            self.cookie = '; '.join(k + '=' + v.value for k, v in cookies.items())
        return json.loads(raw) if raw else {}

    def inspect(self, name):
        fmt = '{{json .Id}} {{json .Image}} {{json .State.Running}}'
        text = command(['docker', 'inspect', '--format', fmt, name])
        ident, image, running = text.split()
        return json.loads(ident), json.loads(image), json.loads(running)

    def prepare(self):
        need(os.geteuid() == 0, 'authenticated root required')
        ids = service_identity()
        self.stage = 'lock_os'
        self.locks.append(HeldLock('/run/culvert-os-update.lock', ids))
        self.stage = 'lock_agent'
        self.locks.append(HeldLock('/var/lib/culvert-maint/host-maintenance.lock', ids))
        self.stage = 'maintenance_idle'
        maintenance_idle()
        self.stage = 'source_identity'
        build = json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_bytes())
        need(build['source']['git_commit'] == SOURCE and build['source']['git_dirty'] is False,
             'candidate source differs')
        self.stage = 'sidecar_build_identity'
        need(build['application']['clamav_sidecar_image_id'] == SIDECAR, 'sidecar build differs')
        self.stage = 'firstboot'
        need(Path('/var/lib/culvert-appliance/state/complete.done').is_file(), 'firstboot incomplete')
        self.stage = 'proxy_identity'
        self.proxy_id, image, active = self.inspect('culvert')
        need(image == IMAGE and active is True, 'proxy identity or state differs')
        self.stage = 'sidecar_identity'
        self.sidecar_id, image, active = self.inspect('culvert-clamav')
        need(image == SIDECAR and active is True, 'sidecar identity or initial state differs')
        self.stage = 'api_login'
        self.api('/api/auth/login', 'POST', {'user': 'labadmin', 'pass': self.config['initial']})
        self.stage = 'av_posture'
        mode = self.api('/api/security-scan/av-settings')
        need(mode.get('av_unavailable') == 'closed', 'fail-closed posture required')
        self.stage = 'policy_snapshot'
        self.before = self.api('/api/policy')
        self.policy_sha = policy_identity(self.before)
        need(all(x.get('name') != self.rule_name for x in self.before['rules']), 'fixture exists')
        self.stage = 'default_deny'
        self.default_before = self.api('/api/default-action')
        need(self.default_before.get('defaultAction') == 'deny', 'default deny required')
        self.stage = 'bridge_network'
        networks = json.loads(command(['docker', 'inspect', '--format', '{{json .NetworkSettings.Networks}}', 'culvert']))
        gateways = {str(ipaddress.IPv4Address(x['Gateway'])) for x in networks.values() if x.get('Gateway')}
        need(len(gateways) == 1, 'unambiguous bridge gateway required')
        self.address = gateways.pop()
        need(ipaddress.IPv4Address(self.address).is_private and not ipaddress.IPv4Address(self.address).is_loopback,
             'private bridge gateway required')
        self.boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        return {'source_sha': SOURCE, 'image_id': IMAGE, 'sidecar_image_id': SIDECAR,
                'boot_id': self.boot,
                'policy_sha256': self.policy_sha, 'av_unavailable': 'closed', 'both_locks_held': True}

    def check_locks(self):
        need(len(self.locks) == 2, 'both maintenance locks required', 'locks_incomplete')
        for lock in self.locks:
            lock.check()

    def install_fixture(self):
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass

            def do_GET(self):
                data = owner.payloads.get(self.path)
                if data is None:
                    self.send_error(404)
                    return
                owner.fetched.add(self.path)
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store')
                self.end_headers()
                self.wfile.write(data)
        class Server(HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(3)
                return connection, address
        self.server = Server((self.address, 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.fixture_attempted = True
        priority = min([x['priority'] for x in self.before['rules']] or [100]) - 1
        need(priority >= 0, 'no nonconflicting fixture priority')
        self.rule = {'name': self.rule_name, 'priority': priority, 'action': 'Allow',
                     'destFQDN': self.address, 'sslAction': 'Bypass', 'enabled': True}
        self.api('/api/policy?ifVersion=' + str(self.before['version']), 'POST', self.rule)
        value = self.api('/api/policy')
        rows = [x for x in value['rules'] if x.get('name') == self.rule_name]
        need(len(rows) == 1 and all(rows[0].get(k) == v for k, v in self.rule.items()), 'fixture differs')
        need(policy_identity(dict(value, rules=[x for x in value['rules'] if x.get('name') != self.rule_name]))
             == self.policy_sha, 'unrelated policy changed')

    def probe(self, kind, body):
        need(len(self.payloads) < 16, 'origin request bound')
        path = '/' + secrets.token_hex(24) + '.bin'
        self.payloads[path] = body
        code, raw, _ = self.request(8080, 'http://' + self.address + ':' + str(self.server.server_port) + path)
        return code, raw, path in self.fetched

    def wait_ready(self, expected):
        started = time.monotonic_ns()
        deadline = time.monotonic() + (90 if expected else 45)
        while True:
            code, raw, _ = self.request(8080, '/ready')
            value = json.loads(raw)
            state = value.get('checks', {}).get('clamav', {}).get('status')
            good = code == 200 and value.get('status') == 'ready' and state == 'ok'
            down = code == 503 and value.get('status') == 'not_ready' and state == 'fail'
            if (good if expected else down):
                return {'pass': True, 'http_status': code, 'clamav_status': state,
                        'started_monotonic_ns': started, 'ended_monotonic_ns': time.monotonic_ns()}
            need(time.monotonic() < deadline, 'readiness deadline')
            time.sleep(1)

    def sidecar_guard(self, require_proxy=True):
        need(Path('/proc/sys/kernel/random/boot_id').read_text().strip() == self.boot, 'boot changed')
        if require_proxy:
            proxy, image, running = self.inspect('culvert')
            need(proxy == self.proxy_id and image == IMAGE and running is True, 'proxy changed')
        ident, image, active = self.inspect('culvert-clamav')
        need(ident == self.sidecar_id and image == SIDECAR, 'sidecar changed')
        return active

    def stop(self):
        need(self.sidecar_guard(), 'sidecar stopped externally')
        self.check_locks()
        command(['docker', 'stop', '--time', '10', self.sidecar_id], timeout=20)
        self.check_locks()
        need(self.sidecar_guard() is False, 'sidecar did not stop')

    def restore(self):
        # A proxy failure during the outage must not prevent restoration of the
        # exact sidecar we stopped. The final readiness/policy tests still fail.
        self.sidecar_guard(require_proxy=False)
        self.check_locks()
        command(['docker', 'start', self.sidecar_id], timeout=20)
        self.check_locks()
        need(self.sidecar_guard(require_proxy=False) is True, 'sidecar did not restart')

    def cleanup_fixture(self):
        if self.before is None:
            return not self.fixture_attempted
        value = self.api('/api/policy')
        rows = [x for x in value['rules'] if x.get('name') == self.rule_name]
        if rows:
            need(self.rule is not None and len(rows) == 1 and all(rows[0].get(k) == v for k, v in self.rule.items()),
                 'refuse removal of changed fixture')
            ident = rows[0].get('id', '')
            need(bool(re.fullmatch('[0-9A-HJKMNP-TV-Z]{26}', ident)), 'fixture ID invalid')
            self.api('/api/policy?id=' + ident + '&ifVersion=' + str(value['version']), 'DELETE')
        after = self.api('/api/policy')
        need(policy_identity(after) == self.policy_sha and self.api('/api/default-action') == self.default_before,
             'policy restoration differs')
        need(self.api('/api/security-scan/av-settings').get('av_unavailable') == 'closed', 'posture changed')
        return True

    def close(self):
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=5)
        for lock in reversed(self.locks):
            lock.close()


def run_guest(config):
    # A termination requests cleanup instead of leaking a deliberately stopped
    # sidecar. SIGKILL/host loss cannot be repaired by a Python finally block.
    def interrupted(*unused):
        raise RuntimeError('interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    result = qualify(Guest(config))
    result.update(operation=config['operation'], helper_sha256=config['helper_sha256'],
                  prior_failure_sha256=config['prior_failure_sha256'])
    print(json.dumps(result, sort_keys=True))
    return 0 if result['result'] == 'pass' else 90


# CONTROLLER: excluded from the guest payload.
HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload(config, profile=None):
    profiles = load('outage_payload_profiles', 'candidate-identities.py')
    profile = profiles.scope_profile(profile or profiles.source_profile(profiles.D698))
    source = Path(__file__).read_text(encoding='utf-8').split('# CONTROLLER:')[0]
    binding = '\nSOURCE, IMAGE, SIDECAR = ' + repr((profile['source_sha'], profile['image_id'], profile['clamav_sidecar_image_id'])) + '\n'
    tail = binding + '\nsys.exit(run_guest(json.loads(base64.b64decode(' + repr(base64.b64encode(json.dumps(config).encode()).decode()) + '))))\n'
    return ("set +x\nset -euo pipefail\npython3 - <<'CULVERT_AV_OUTAGE'\n" + source + tail + '\nCULVERT_AV_OUTAGE\n').encode()


def prior_failure(sec, expected, owner):
    need(isinstance(expected, str) and bool(re.fullmatch('[0-9a-f]{64}', expected)), 'prior failure hash required')
    directory = sec / 'clamav-outage'
    need(directory.is_dir() and not directory.is_symlink()
         and not (hasattr(directory, 'is_junction') and directory.is_junction()), 'retained original attempt required')
    need(not (directory / 'complete.json').exists(), 'original attempt completed')
    files = {}
    for name, limit in [('guest-result.json', 128 * 1024), ('intent.json', 8192), ('payload.sh', 1024 * 1024)]:
        path = directory / name
        need(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
             'retained evidence file refused')
        files[name] = path.read_bytes()
    value = json.loads(files['guest-result.json'])
    intent = json.loads(files['intent.json'])
    need(sha(files['guest-result.json']) == expected and value.get('result') == 'fail'
         and value.get('schema') == 1 and value.get('helper_sha256') == PRIOR_HELPER
         and 'identity' not in value and value.get('phases') == {} and value.get('readiness') == {}
         and value.get('restored_running') is False and value.get('policy_restored') is True
         and value.get('errors') == ['qualification_failed'], 'original pre-fixture failure differs')
    need(intent.get('owner_uuid') == owner and intent.get('controller_revision') == PRIOR_CONTROLLER
         and intent.get('source_sha') == SOURCE and intent.get('image_id') == IMAGE
         and intent.get('sidecar_image_id') == SIDECAR and intent.get('operation') == value.get('operation')
         and intent.get('payload_sha256') == sha(files['payload.sh']), 'original attempt identity differs')
    return {name: sha(raw) for name, raw in files.items()}


def attempt_context(sec, profile, attempt, previous_hash, owner):
    profiles = load('outage_attempt_profiles', 'candidate-identities.py')
    selected = profiles.scope_profile(profile)
    if selected['source_sha'] in (profiles.E2E3, profiles.CD8, profiles.E7E, profiles.E7C):
        need(attempt == 'initial' and previous_hash is None, 'fresh candidate requires initial attempt without prior failure')
        need(not list(sec.glob('clamav-outage*')), 'fresh candidate already has outage evidence; no retry')
        return sec / 'clamav-outage', {}
    need(selected['source_sha'] == profiles.D698, 'outage candidate is not approved')
    need(bool(re.fullmatch('[a-z][a-z0-9-]{0,47}', attempt)) and attempt != 'initial',
         'explicit new continuation attempt required')
    return sec / ('clamav-outage-' + attempt), prior_failure(sec, previous_hash, owner)


def run(args):
    ipaddress.IPv4Address(args.bind)
    console = load('outage_console', 'console-priv.py')
    profiles = load('outage_profiles', 'candidate-identities.py')
    freeze = load('outage_freeze', 'controller-freeze.py')
    lab = console.b.module.Lab(args.scope)
    console.b.private_directory(lab)
    console.b.module.validate_scope(lab.c)
    profile = profiles.scope_profile(lab.c)
    need(profile['source_sha'] in (profiles.D698, profiles.E2E3, profiles.CD8, profiles.E7E, profiles.E7C)
         and 'clamav_sidecar_image_id' in profile, 'exact approved outage candidate required')
    manifest = freeze.verify(Path(lab.c['controller_manifest']))
    helper_sha = sha(Path(__file__).read_bytes())
    need(manifest['files'].get('test/e2e/appliance/esxi/qualify-clamav-outage.py') == helper_sha, 'helper not frozen')
    with console.b.module.locked(lab.run):
        lab.vm(timeout=30)
        directory, prior = attempt_context(lab.sec, profile, args.attempt, args.prior_failure_sha256, lab.state['uuid'])
        directory.mkdir()  # One-shot; a failed attempt must be reviewed.
        initial = (lab.sec / 'admin-pass').read_text(encoding='utf-8').strip()
        need(1 <= len(initial) <= 256, 'private administrator credential unavailable')
        config = {'operation': secrets.token_hex(16), 'initial': initial, 'helper_sha256': helper_sha,
                  'prior_failure_sha256': args.prior_failure_sha256}
        body = payload(config, profile)
        (directory / 'payload.sh').write_bytes(body)
        (directory / 'intent.json').write_text(json.dumps({'operation': config['operation'],
            'owner_uuid': lab.state['uuid'], 'source_sha': profile['source_sha'], 'image_id': profile['image_id'],
            'sidecar_image_id': profile['clamav_sidecar_image_id'], 'payload_sha256': sha(body), 'controller_revision': manifest['revision'],
            'attempt': args.attempt, 'prior_attempt_file_hashes': prior}) + '\n')
        output = io.BytesIO()
        writer = io.TextIOWrapper(output, encoding='utf-8', write_through=True)
        with contextlib.redirect_stdout(writer):
            rc = console.execute(lab, SimpleNamespace(bind=args.bind, timeout=600, nowait=False, as_user=False), body)
        raw = output.getvalue()
        (directory / 'guest-result.json').write_bytes(raw)
        need(rc == 0 and len(raw) <= 128 * 1024, 'qualification or transport failed; inspect private evidence')
        result = json.loads(raw)
        need(result.get('result') == 'pass' and result.get('operation') == config['operation']
             and result.get('helper_sha256') == helper_sha
             and result.get('prior_failure_sha256') == args.prior_failure_sha256, 'result binding differs')
        identity = result.get('identity', {})
        need(all(identity.get(k) == profile[p] for k, p in (('source_sha', 'source_sha'),
             ('image_id', 'image_id'), ('sidecar_image_id', 'clamav_sidecar_image_id'))), 'guest identity binding differs')
        if prior:
            need(prior_failure(lab.sec, args.prior_failure_sha256, lab.state['uuid']) == prior,
                 'original evidence changed')
        receipt = {'result': 'pass', 'operation': config['operation'], 'helper_sha256': helper_sha,
                   'payload_sha256': sha(body), 'guest_result_sha256': sha(raw), 'controller_revision': manifest['revision'],
                   'attempt': args.attempt, 'prior_failure_sha256': args.prior_failure_sha256}
        (directory / 'complete.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
        print(json.dumps(receipt, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--attempt', required=True, help='initial for a fresh candidate; explicit new label for approved historical continuation')
    parser.add_argument('--prior-failure-sha256', help='required only for the approved d698 pre-fixture failure continuation')
    try:
        run(parser.parse_args())
        return 0
    except Exception:
        print('ClamAV outage qualification failed or blocked; retain private evidence and verify sidecar recovery.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
