#!/usr/bin/env python3
"""Owned d698 LAB only: fresh-body ClamAV outage and recovery qualification.

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


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


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
              'restored_running': False, 'policy_restored': False}
    seen = set()
    stop_attempted = False
    try:
        result['identity'] = backend.prepare()
        backend.install_fixture()
        result['readiness']['before'] = backend.wait_ready(True)
        result['phases']['before'] = observe(backend, 'before', seen)
        need(all(x['pass'] for x in result['phases']['before']), 'initial content verdict mismatch')
        stop_attempted = True  # stop may time out after it already changed state.
        backend.stop()
        result['readiness']['down'] = backend.wait_ready(False)
        result['phases']['down'] = observe(backend, 'down', seen)
        need(all(x['pass'] for x in result['phases']['down']), 'outage content verdict mismatch')
    except Exception:
        result['errors'].append('qualification_failed')
    finally:
        if stop_attempted:
            try:
                backend.restore()
                result['restored_running'] = True
                result['readiness']['recovered'] = backend.wait_ready(True)
                result['phases']['recovered'] = observe(backend, 'recovered', seen)
                need(all(x['pass'] for x in result['phases']['recovered']), 'recovered content verdict mismatch')
            except Exception:
                result['errors'].append('sidecar_recovery_failed')
        try:
            result['policy_restored'] = backend.cleanup_fixture()
        except Exception:
            result['errors'].append('policy_cleanup_failed')
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


def locked_file(path):
    import fcntl
    p = Path(path)
    for ancestor in (p.parent, *p.parent.parents):
        s = ancestor.lstat()
        need(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022,
             'untrusted lock ancestor')
    fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        s = os.fstat(fd)
        need(stat.S_ISREG(s.st_mode) and s.st_uid == 0 and s.st_nlink == 1
             and not s.st_mode & 0o022, 'untrusted lock file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


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
        code, raw, headers = self.request(9090, path, method, payload, tls=True)
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
        self.locks.append(locked_file('/run/culvert-os-update.lock'))
        self.locks.append(locked_file('/var/lib/culvert-maint/host-maintenance.lock'))
        maintenance_idle()
        build = json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_bytes())
        need(build['source']['git_commit'] == SOURCE and build['source']['git_dirty'] is False,
             'candidate source differs')
        need(build['application']['clamav_sidecar_image_id'] == SIDECAR, 'sidecar build differs')
        need(Path('/var/lib/culvert-appliance/state/complete.done').is_file(), 'firstboot incomplete')
        self.proxy_id, image, active = self.inspect('culvert')
        need(image == IMAGE and active is True, 'proxy identity or state differs')
        self.sidecar_id, image, active = self.inspect('culvert-clamav')
        need(image == SIDECAR and active is True, 'sidecar identity or initial state differs')
        self.api('/api/auth/login', 'POST', {'user': 'labadmin', 'pass': self.config['initial']})
        mode = self.api('/api/security-scan/av-settings')
        need(mode.get('av_unavailable') == 'closed', 'fail-closed posture required')
        self.before = self.api('/api/policy')
        self.policy_sha = policy_identity(self.before)
        need(all(x.get('name') != self.rule_name for x in self.before['rules']), 'fixture exists')
        self.default_before = self.api('/api/default-action')
        need(self.default_before.get('defaultAction') == 'deny', 'default deny required')
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
        command(['docker', 'stop', '--time', '10', self.sidecar_id], timeout=20)
        need(self.sidecar_guard() is False, 'sidecar did not stop')

    def restore(self):
        # A proxy failure during the outage must not prevent restoration of the
        # exact sidecar we stopped. The final readiness/policy tests still fail.
        self.sidecar_guard(require_proxy=False)
        command(['docker', 'start', self.sidecar_id], timeout=20)
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
        for fd in reversed(self.locks):
            os.close(fd)


def run_guest(config):
    # A termination requests cleanup instead of leaking a deliberately stopped
    # sidecar. SIGKILL/host loss cannot be repaired by a Python finally block.
    def interrupted(*unused):
        raise RuntimeError('interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    result = qualify(Guest(config))
    result.update(operation=config['operation'], helper_sha256=config['helper_sha256'])
    print(json.dumps(result, sort_keys=True))
    return 0 if result['result'] == 'pass' else 90


# CONTROLLER: excluded from the guest payload.
HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def payload(config):
    source = Path(__file__).read_text(encoding='utf-8').split('# CONTROLLER:')[0]
    tail = '\nsys.exit(run_guest(json.loads(base64.b64decode(' + repr(base64.b64encode(json.dumps(config).encode()).decode()) + '))))\n'
    return ("set +x\nset -euo pipefail\npython3 - <<'CULVERT_AV_OUTAGE'\n" + source + tail + '\nCULVERT_AV_OUTAGE\n').encode()


def run(args):
    ipaddress.IPv4Address(args.bind)
    console = load('outage_console', 'console-priv.py')
    profiles = load('outage_profiles', 'candidate-identities.py')
    freeze = load('outage_freeze', 'controller-freeze.py')
    lab = console.b.module.Lab(args.scope)
    console.b.private_directory(lab)
    console.b.module.validate_scope(lab.c)
    profile = profiles.scope_profile(lab.c)
    need(profile['source_sha'] == SOURCE and profile['clamav_sidecar_image_id'] == SIDECAR, 'd698 scope required')
    manifest = freeze.verify(Path(lab.c['controller_manifest']))
    helper_sha = sha(Path(__file__).read_bytes())
    need(manifest['files'].get('test/e2e/appliance/esxi/qualify-clamav-outage.py') == helper_sha, 'helper not frozen')
    with console.b.module.locked(lab.run):
        lab.vm(timeout=30)
        directory = lab.sec / 'clamav-outage'
        directory.mkdir()  # One-shot; a failed attempt must be reviewed.
        initial = (lab.sec / 'admin-pass').read_text(encoding='utf-8').strip()
        need(1 <= len(initial) <= 256, 'private administrator credential unavailable')
        config = {'operation': secrets.token_hex(16), 'initial': initial, 'helper_sha256': helper_sha}
        body = payload(config)
        (directory / 'payload.sh').write_bytes(body)
        (directory / 'intent.json').write_text(json.dumps({'operation': config['operation'],
            'owner_uuid': lab.state['uuid'], 'source_sha': SOURCE, 'image_id': IMAGE,
            'sidecar_image_id': SIDECAR, 'payload_sha256': sha(body), 'controller_revision': manifest['revision']}) + '\n')
        output = io.BytesIO()
        writer = io.TextIOWrapper(output, encoding='utf-8', write_through=True)
        with contextlib.redirect_stdout(writer):
            rc = console.execute(lab, SimpleNamespace(bind=args.bind, timeout=600, nowait=False, as_user=False), body)
        raw = output.getvalue()
        (directory / 'guest-result.json').write_bytes(raw)
        need(rc == 0 and len(raw) <= 128 * 1024, 'qualification or transport failed; inspect private evidence')
        result = json.loads(raw)
        need(result.get('result') == 'pass' and result.get('operation') == config['operation']
             and result.get('helper_sha256') == helper_sha, 'result binding differs')
        receipt = {'result': 'pass', 'operation': config['operation'], 'helper_sha256': helper_sha,
                   'payload_sha256': sha(body), 'guest_result_sha256': sha(raw), 'controller_revision': manifest['revision']}
        (directory / 'complete.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
        print(json.dumps(receipt, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--bind', required=True)
    try:
        run(parser.parse_args())
        return 0
    except Exception:
        print('ClamAV outage qualification failed or blocked; retain private evidence and verify sidecar recovery.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
