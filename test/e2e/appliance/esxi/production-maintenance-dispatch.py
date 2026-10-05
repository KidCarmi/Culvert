#!/usr/bin/env python3
"""Accept one authenticated local maintenance invocation; never retry a reboot.

The existing PAM/sudo console boundary remains the only administrative path.
The callback marks acceptance before the unchanged product command is invoked,
so lock acquisition and graceful shutdown are included in the recovery budget.
An acceptance is not proof that the product guard allowed or completed reboot.
"""
import argparse
import datetime
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import threading
import time

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('production_console', HERE / 'console-priv.py')
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)


def validate_acceptance(data, expected):
    if not isinstance(data, dict) or set(data) != {
        'schema', 'cycle_id', 'operation_id', 'old_boot_id', 'source_sha',
        'image_id', 'guest_monotonic_ns', 'guest_realtime_ns', 'nonce'}:
        raise ValueError('invalid acceptance fields')
    if data['schema'] != 1 or any(data[k] != v for k, v in expected.items()):
        raise ValueError('acceptance identity mismatch')
    if not re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', data['old_boot_id']):
        raise ValueError('invalid boot identity')
    for name in ('guest_monotonic_ns', 'guest_realtime_ns'):
        if type(data[name]) is not int or not 0 < data[name] < 10**20:
            raise ValueError('invalid acceptance clock')
    return data


def guest_script(cfg):
    # No change to the product script, maintenance lock or sudo policy.
    guest = r'''
import json, pathlib, subprocess, time, os
c=CONFIG
build=json.loads(pathlib.Path('/var/lib/culvert-appliance/build-info.json').read_text())
assert build['source']['git_commit']==c['source_sha'] and build['source']['git_dirty'] is False
assert pathlib.Path('/var/lib/culvert-appliance/state/complete.done').is_file()
image=subprocess.run(['docker','inspect','-f','{{.Image}}','culvert'],check=True,capture_output=True,text=True,timeout=20).stdout.strip()
assert image==c['image_id']
assert pathlib.Path('/usr/local/sbin/culvert-os-update').is_file()
boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
data={k:c[k] for k in ('cycle_id','operation_id','source_sha','image_id','nonce')}
data.update(schema=1,old_boot_id=boot,guest_monotonic_ns=time.monotonic_ns(),guest_realtime_ns=time.time_ns())
r=subprocess.run(['curl','-fsSk','--connect-timeout','5','--max-time','10','--pinnedpubkey',c['pin'],'--data-binary','@-',c['url']],input=json.dumps(data).encode(),capture_output=True,timeout=15)
assert r.returncode==0 and r.stdout==b'accepted\n'
os.execv('/usr/local/sbin/culvert-os-update',['culvert-os-update','reboot'])
'''.replace('CONFIG', repr(cfg))
    return ("set +x\nset -euo pipefail\npython3 - <<'CULVERT_PRODUCTION_DISPATCH'\n" + guest +
            '\nCULVERT_PRODUCTION_DISPATCH\n').encode()


def run(args):
    ipaddress.IPv4Address(args.bind)
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,47}', args.cycle):
        raise ValueError('invalid cycle')
    lab = console.b.module.Lab(args.scope)
    console.b.private_directory(lab)
    console.b.module.validate_scope(lab.c)
    lab.vm(timeout=30)
    directory = lab.sec / 'production-recovery' / args.cycle
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / 'dispatch-attempt.json'
    with marker.open('x') as out:
        json.dump({'status': 'started', 'uuid': lab.state['uuid']}, out)
    acceptance_path = directory / 'acceptance.json'
    if acceptance_path.exists():
        raise ValueError('acceptance already exists')
    guest = lab.guest_ip(timeout=30)
    tls = directory / 'acceptance-tls'
    tls.mkdir()
    context, pin = console.make_tls(tls)
    nonce = secrets.token_hex(32)
    route = '/' + secrets.token_hex(32)
    expected = {'cycle_id': args.cycle, 'operation_id': secrets.token_hex(16),
                'source_sha': lab.c['source_sha'], 'image_id': lab.c['image_id'], 'nonce': nonce}
    state = {'used': False, 'accepted': False}
    event = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *unused):
            pass

        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', '-1'))
                if (self.client_address[0] != guest or self.path != route or state['used']
                        or not 0 < length <= 8192):
                    raise ValueError('refused callback')
                state['used'] = True
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('incomplete callback')
                data = validate_acceptance(json.loads(body), expected)
                data.pop('nonce')
                data.update(kind='maintenance_accepted', controller_monotonic_ns=time.monotonic_ns(),
                            controller_realtime_ns=time.time_ns(),
                            utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                            acceptance_semantics='authenticated invocation accepted before unchanged product guard and graceful stop')
                console.b.module.atomic_json(acceptance_path, data)
                state['accepted'] = True
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'accepted\n')
                self.wfile.flush()
                event.set()
            except Exception:
                self.send_error(403)

    class Server(HTTPServer):
        def get_request(self):
            connection, address = self.socket.accept()
            connection.settimeout(12)
            try:
                return context.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close()
                raise

    server = Server((args.bind, 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cfg = dict(expected, pin=pin, url=f'https://{args.bind}:{server.server_port}{route}')
    payload = guest_script(cfg)
    try:
        with (directory / 'dispatch-stdout').open('xb') as stdout, (directory / 'dispatch-stderr').open('xb') as stderr:
            result = subprocess.run([sys.executable, str(HERE / 'console-priv.py'), '--scope',
                str(args.scope), '--bind', args.bind, '--nowait', '--timeout', '120'],
                input=payload, stdout=stdout, stderr=stderr, timeout=240)
        # console-priv owns the exclusive mutation lock and rechecks ownership.
        if result.returncode != 0 or not event.wait(40):
            raise ValueError('dispatch not acknowledged; do not retry')
        console.b.module.atomic_json(marker, {'status': 'accepted', 'uuid': lab.state['uuid'],
            'payload_sha256': hashlib.sha256(payload).hexdigest(),
            'acceptance_sha256': hashlib.sha256(acceptance_path.read_bytes()).hexdigest()})
        print('Maintenance invocation accepted; reboot and recovery remain unverified.')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=20)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope', type=Path, required=True)
    p.add_argument('--bind', required=True)
    p.add_argument('--cycle', required=True)
    args = p.parse_args()
    try:
        run(args)
        return 0
    except Exception:
        print('Maintenance dispatch blocked; preserve evidence, no automatic retry.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
