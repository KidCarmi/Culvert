#!/usr/bin/env python3
"""One-shot narrow ESXi pressure reproduction; requires a frozen continuation.

No VM power/reboot/delete operations. Only the approved owned 40-GiB guest is
filled, with a fresh datastore-capacity lease and independent guest backstop.
Private raw responses never appear in stdout. Backup/update pressure NOT_RUN.
"""
import argparse
import base64
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import io
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import sys
import threading
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
GIB = 1024 ** 3
RESERVE = 64 * GIB
HEADROOM = RESERVE + 40 * GIB + 2 * GIB


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def required_reserve(scope):
    value = scope['datastore_headroom_gib']
    need(type(value) is int and value >= 0, 'scope reserve missing')
    return max(RESERVE, value * GIB)


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def hardware_guard(vm):
    hw = vm['config']['hardware']
    need(hw.get('numCPU') == 2 and hw.get('memoryMB') == 4096, 'owned guest resource mismatch')
    disks = [x for x in hw.get('device', []) if 'capacityInKB' in x or 'capacityInBytes' in x]
    need(len(disks) == 1, 'one owned disk required')
    disk = disks[0]
    size = disk.get('capacityInBytes', disk.get('capacityInKB', 0) * 1024)
    need(size == 40 * GIB, '40 GiB disk required')


def capacity(lab):
    lab.vm(timeout=8)  # Existing owner UUID/host/datastore/network/snapshot fence.
    rows = lab.gov('datastore.info', lab.c['datastore'], timeout=8).get('datastores', [])
    need(len(rows) == 1 and rows[0]['self'] == lab.state['ds_ref'], 'datastore identity differs')
    value = rows[0]['summary']['freeSpace']
    need(type(value) is int and value >= 0, 'capacity missing')
    return value


class LeaseServer:
    def __init__(self, lab, bind, guest_ip, directory, tls_context):
        self.lab, self.guest_ip, self.directory = lab, guest_ip, directory
        self.token = secrets.token_hex(32)
        self.stop = threading.Event()
        self.valid_until = 0
        self.rows = []
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass

            def do_GET(self):
                permitted = (self.client_address[0] == owner.guest_ip
                             and secrets.compare_digest(self.path, '/' + owner.token)
                             and time.monotonic() < owner.valid_until and not owner.stop.is_set())
                raw = json.dumps({'permit': permitted}).encode()
                self.send_response(200 if permitted else 503)
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(raw)
        class Server(HTTPServer):
            request_queue_size = 4

            def get_request(self):
                sock, address = super().get_request()
                sock.settimeout(2)
                try:
                    if address[0] != owner.guest_ip:
                        raise ConnectionAbortedError('lease peer differs')
                    return tls_context.wrap_socket(sock, server_side=True), address
                except Exception:
                    sock.close()
                    raise
        self.server = Server((bind, 0), Handler)

    def refresh(self):
        # A failed/slow observation never extends the previous lease. Guest
        # refreshes every second; maximum stale observation age is 10 seconds.
        started = time.monotonic()
        try:
            free = capacity(self.lab)
            ok = free >= required_reserve(self.lab.c) + 2 * GIB and time.monotonic() - started < 8
            self.rows.append({'utc_ns': time.time_ns(), 'free_bytes': free, 'permit': ok})
            self.valid_until = started + 10 if ok else 0
        except Exception:
            self.valid_until = 0
            self.rows.append({'utc_ns': time.time_ns(), 'permit': False, 'error': 'capacity_or_owner_unavailable'})

    def watch(self):
        while not self.stop.is_set():
            self.refresh()
            self.stop.wait(2)

    def start(self):
        self.refresh()
        need(time.monotonic() < self.valid_until, 'initial lease refused')
        self.web = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.poll = threading.Thread(target=self.watch, daemon=True)
        self.web.start()
        self.poll.start()

    def close(self):
        self.stop.set()
        self.valid_until = 0
        if hasattr(self, 'web'):
            self.server.shutdown()
            self.web.join(timeout=3)
        self.server.server_close()
        if hasattr(self, 'poll'):
            self.poll.join(timeout=20)
        (self.directory / 'datastore-lease.json').write_text(json.dumps(self.rows), encoding='utf-8')


def payload(config, profile):
    sources = {name: (HERE / name).read_bytes() for name in (
        'qualify-clamav-outage.py', 'disk-pressure-worker.py', 'disk-pressure-guest.py', 'disk-pressure-observe.py')}
    sources['qualify-clamav-outage.py'] = sources['qualify-clamav-outage.py'].split(b'# CONTROLLER:')[0]
    bindings = repr((profile['source_sha'], profile['image_id'], profile['clamav_sidecar_image_id']))
    program = ['import base64,json,types', 'modules = {}']
    for name, raw in sources.items():
        program += ['raw = base64.b64decode(' + repr(base64.b64encode(raw).decode()) + ')',
                    'module = types.ModuleType(' + repr(name) + ')',
                    'exec(compile(raw, ' + repr(name) + ', "exec"), module.__dict__)',
                    'modules[' + repr(name) + '] = module']
    program += ["b = modules['qualify-clamav-outage.py']", 'b.SOURCE,b.IMAGE,b.SIDECAR = ' + bindings,
                'config = json.loads(base64.b64decode(' + repr(base64.b64encode(json.dumps(config).encode()).decode()) + '))',
                "result = modules['disk-pressure-guest.py'].run(config,b.Guest(config),b,modules['disk-pressure-worker.py'],",
                'base64.b64decode(' + repr(base64.b64encode(sources['disk-pressure-worker.py']).decode()) + '),',
                "modules['disk-pressure-observe.py'].ReplyCapture)",
                'result["helper_hashes"] = config["helper_hashes"]',
                'raw = json.dumps(result,sort_keys=True).encode()',
                'assert len(raw) <= 7*1024*1024',
                "w = modules['disk-pressure-worker.py']",
                "p = w.Path('/run')",
                'w.tmpfs_guard(p)',
                'w.os.close(w.safe_directory(p))',
                "name = p / ('culvert-lab-pressure-' + config['operation'] + '-result.json')",
                'fd = w.os.open(name,w.os.O_WRONLY|w.os.O_CREAT|w.os.O_EXCL|w.os.O_NOFOLLOW,0o600)',
                "with w.os.fdopen(fd,'wb') as private_result: private_result.write(raw)",
                'print(json.dumps(result,sort_keys=True))',
                'raise SystemExit(0 if result["result"] == "pass" else 90)']
    return ("set +x\nset -euo pipefail\npython3 - <<'CULVERT_PRESSURE'\n" + '\n'.join(program)
            + '\nCULVERT_PRESSURE\n').encode()


def run(args):
    bind = str(ipaddress.IPv4Address(args.bind))
    address = ipaddress.IPv4Address(bind)
    need(address.is_private and not address.is_unspecified and not address.is_loopback, 'specific private bind required')
    console, profiles, freeze = load('console-priv'), load('candidate-identities'), load('controller-freeze')
    recovery = load('fresh-recovery')
    lab = console.b.module.Lab(args.scope)
    console.b.private_directory(lab)
    console.b.module.validate_scope(lab.c)
    profile = profiles.scope_profile(lab.c)
    need(profile['source_sha'] == profiles.E91, 'only candidate91 approved')
    manifest = freeze.verify(Path(lab.c['controller_manifest']))
    hashes = {}
    for name in ('disk-pressure-control.py', 'disk-pressure-worker.py', 'disk-pressure-guest.py',
                 'disk-pressure-observe.py', 'qualify-clamav-outage.py'):
        hashes[name] = sha((HERE / name).read_bytes())
        need(manifest['files'].get('test/e2e/appliance/esxi/' + name) == hashes[name], 'helper not frozen')
    with console.b.module.locked(lab.run):
        hardware_guard(lab.vm(timeout=20))
        reserve = required_reserve(lab.c)
        need(capacity(lab) >= reserve + 40 * GIB + 2 * GIB, 'reserve plus entire owned disk growth unavailable')
        escrow = args.escrow.resolve()
        receipt = recovery.verify_export(escrow)
        owned = recovery.read_json(escrow / 'source-owned.json')
        need(owned.get('uuid') == lab.state['uuid'] and owned.get('endpoint') == lab.state['endpoint'],
             'prior backup belongs to another guest')
        directory = lab.sec / 'disk-pressure'
        directory.mkdir()  # one-shot; prior failures require separate reviewed continuation
        tls_context, _ = console.make_tls(directory)
        certificate = ssl.PEM_cert_to_DER_cert((directory / 'controller.crt').read_text())
        guest_ip = lab.guest_ip(timeout=20)
        server = LeaseServer(lab, bind, guest_ip, directory, tls_context)
        try:
            server.start()
            config = {'operation': secrets.token_hex(16), 'initial': (lab.sec / 'admin-pass').read_text().strip(),
                      'helper_hashes': hashes,
                      'lease': {'host': bind, 'port': server.server.server_port, 'token': server.token,
                                'certificate_sha256': sha(certificate)}}
            need(1 <= len(config['initial']) <= 256, 'admin credential unavailable')
            body = payload(config, profile)
            (directory / 'payload.sh').write_bytes(body)
            intent = {'schema': 1, 'operation': config['operation'], 'owner_uuid': lab.state['uuid'],
                      'controller_revision': manifest['revision'], 'helper_hashes': hashes,
                      'payload_sha256': sha(body), 'prior_export_receipt_sha256': sha((escrow / 'export-receipt.json').read_bytes()),
                      'source_sha': profile['source_sha'], 'image_id': profile['image_id'],
                      'sidecar_image_id': profile['clamav_sidecar_image_id'], 'reserve_bytes': reserve,
                      'full_disk_pressure_lifecycle': 'NOT_QUALIFIED_backup_and_update_gates_not_run',
                      'backup_update_pressure': 'NOT_RUN_both_locks_held'}
            (directory / 'intent.json').write_text(json.dumps(intent, sort_keys=True))
            output = io.BytesIO()
            writer = io.TextIOWrapper(output, encoding='utf-8', write_through=True)
            try:
                with contextlib.redirect_stdout(writer):
                    rc = console.execute(lab, SimpleNamespace(bind=bind, timeout=650, nowait=False, as_user=False), body)
            finally:
                (directory / 'guest-result.json').write_bytes(output.getvalue())
            raw = output.getvalue()
            need(len(raw) <= 7 * 1024 ** 2, 'result limit')
            value = json.loads(raw)
            need(value.get('operation') == config['operation'] and value.get('helper_hashes') == hashes, 'result binding')
            status = value.get('result')
            need(status in ('pass', 'fail', 'blocked'), 'result schema')
            need((rc == 0) == (status == 'pass'), 'exit/result mismatch')
            summary = dict(intent, result=status, guest_result_sha256=sha(raw),
                           policy_restored=value.get('policy_restored'), no_restart=value.get('no_restart'))
            (directory / 'complete.json').write_text(json.dumps(summary, sort_keys=True))
            print(json.dumps({'result': status, 'operation': config['operation'],
                              'backup_update_pressure': 'NOT_RUN', 'guest_result_sha256': sha(raw)}))
            return 0 if status == 'pass' else 90
        finally:
            server.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', required=True, type=Path)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--escrow', required=True, type=Path)
    try:
        sys.exit(run(parser.parse_args()))
    except Exception:
        print('Disk-pressure attempt failed or blocked; preserve private evidence and confirm automatic release.', file=sys.stderr)
        sys.exit(90)
