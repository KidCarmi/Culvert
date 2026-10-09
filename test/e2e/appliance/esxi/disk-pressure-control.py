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
import re
import stat
import ssl
import sys
import threading
import time
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
GIB = 1024 ** 3
RESERVE = 64 * GIB
HEADROOM = RESERVE + 40 * GIB + 2 * GIB
V3_PRESSURE_RESULT = 'ad947abb336bd5a7f2fd3e357e12b3df2bf160dd4c7da9a19855a2ba8fcac67c'
V2_PRESSURE_RESULT = 'beabb48a3c145a0adcdd3bacc6244d23f3e8d31068ea1ab6a299130c0bc031f8'
ORIGINAL_PRESSURE_RESULT = '695934c6111638c6a2838f17bf3112153a2cf8aebdd4533932056aeecb6e6ed1'


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
                "if config.get('mode') == 'capture_only':",
                " result = modules['disk-pressure-guest.py'].run_capture(config,b.Guest(config),b,modules['disk-pressure-worker.py'],modules['disk-pressure-observe.py'].ReplyCapture)",
                "else:",
                " result = modules['disk-pressure-guest.py'].run(config,b.Guest(config),b,modules['disk-pressure-worker.py'],",
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


def regular_bytes(path, limit=None):
    for parent in [path, *path.parents]:
        st = parent.lstat()
        need(not stat.S_ISLNK(st.st_mode) and not getattr(st, 'st_file_attributes', 0) & 0x400,
             'redirected admission evidence')
    need(path.is_file(), 'admission evidence not regular')
    if limit is not None:
        need(path.stat().st_size <= limit, 'admission evidence limit')
    return path.read_bytes()


def frozen_external(manifest, path, digest):
    need(any(Path(item['path']).resolve() == path.resolve() and item['sha256'] == digest
             for item in manifest.get('external_inputs', [])), 'evidence is not frozen')


def attempt_records(lab, name, manifest):
    directory = lab.sec / name
    records, hashes = {}, {}
    for key in ('intent', 'complete', 'guest-result'):
        path = directory / (key + '.json')
        data = regular_bytes(path, 7*1024**2)
        hashes[key] = sha(data)
        frozen_external(manifest, path, hashes[key])
        records[key] = json.loads(data)
    intent, complete, guest = (records[k] for k in ('intent', 'complete', 'guest-result'))
    need(intent['owner_uuid'] == lab.state['uuid'] and intent['source_sha'] == lab.c['source_sha']
         and intent['operation'] == complete['operation'] == guest['operation']
         and complete['guest_result_sha256'] == hashes['guest-result']
         and complete['helper_hashes'] == intent['helper_hashes'] == guest['helper_hashes'], 'attempt evidence binding')
    for key in ('owner_uuid', 'source_sha', 'image_id', 'controller_revision', 'helper_hashes'):
        need(complete.get(key) == intent.get(key), 'attempt completion identity differs')
    return records, hashes


def prior_capture_failure(lab, manifest):
    records, hashes = attempt_records(lab, 'disk-pressure-proof-v2', manifest)
    intent, complete, guest = (records[k] for k in ('intent', 'complete', 'guest-result'))
    need(hashes['guest-result'] == V2_PRESSURE_RESULT and guest['result'] == complete['result'] == 'fail'
         and guest.get('policy_restored') is True and guest.get('no_restart') is True, 'not reviewed capture refusal')
    phases = guest.get('phases', [])
    need(len(phases) == 1, 'capture refusal phase differs')
    phase = phases[0]
    need(phase.get('allocation_started') is False and phase.get('fill') is None
         and phase.get('released') is True and phase.get('root_pressure_directory_absent') is True
         and phase.get('no_restart') is True and phase.get('recovered', {}).get('pass') is True
         and phase.get('capture_positive_control', {}).get('pass') is False
         and phase['capture_positive_control']['sample']['pass'] is True
         and phase.get('capture', {}).get('fragments') == 0, 'v2 is not a clean pre-allocation capture refusal')
    return hashes


def prior_replenishment_failure(lab, manifest):
    records, hashes = attempt_records(lab, 'disk-pressure-proof-v3', manifest)
    complete, guest = records['complete'], records['guest-result']
    need(hashes['guest-result'] == V3_PRESSURE_RESULT and guest['result'] == complete['result'] == 'fail'
         and guest.get('policy_restored') is True and guest.get('no_restart') is True,
         'not reviewed replenishment failure')
    phases = guest.get('phases', [])
    need(len(phases) == 1, 'replenishment failure phase differs')
    phase = phases[0]
    need(phase.get('mode') == 'blocks' and phase.get('result') == 'fail'
         and phase.get('fill', {}).get('result') == 'exhausted' and phase['fill'].get('errno') == 'ENOSPC'
         and phase.get('released') is True and phase.get('root_pressure_directory_absent') is True
         and phase.get('no_restart') is True and phase.get('recovered', {}).get('pass') is True
         and phase.get('capture_positive_control', {}).get('pass') is True
         and phase.get('capture', {}).get('collection_verdict') == 'BOUNDED_FRAGMENTS_RETAINED',
         'v3 cleanup or capture differs')
    rows = phase.get('samples', [])
    need(len(rows) == 64 and sum(row.get('pressure_present_across_sample') is True for row in rows) == 1
         and all(row.get('pass') is True and row.get('readiness_truthful') is True
                 and len(row.get('probes', [])) == 3
                 and all(p.get('verdict') in ('av_unavailable', 'clean_delivered', 'eicar_blocked')
                         and not (p.get('kind') == 'eicar' and 200 <= p.get('http_status', 0) < 300)
                         for p in row['probes']) for row in rows),
         'v3 actual enforcement failure cannot be retried unchanged')
    return hashes


def capture_gate(lab, manifest, admission, version='v3'):
    need(version in ('v3', 'v4'), 'capture gate version')
    prior_key = 'v3' if version == 'v4' else 'v2'
    previous_hashes = (prior_replenishment_failure(lab, manifest) if version == 'v4'
                       else prior_capture_failure(lab, manifest))
    name = 'disk-pressure-capture-preflight-v4' if version == 'v4' else 'disk-pressure-capture-preflight'
    records, hashes = attempt_records(lab, name, manifest)
    intent, complete, guest = (records[k] for k in ('intent', 'complete', 'guest-result'))
    need(guest['result'] == complete['result'] == 'pass' and guest.get('scope') == 'healthy_capture_only'
         and guest.get('allocation_started') is False and guest.get('policy_restored') is True
         and guest.get('no_restart') is True and guest.get('capture_positive_control', {}).get('pass') is True
         and guest.get('capture', {}).get('packet_protocol') == 'ETH_P_ALL'
         and guest['capture']['collection_verdict'] == 'BOUNDED_FRAGMENTS_RETAINED', 'healthy capture unproven')
    for name, digest in intent['helper_hashes'].items():
        need(manifest['files'].get('test/e2e/appliance/esxi/' + name) == digest, 'capture-tested helper changed')
    need(intent.get('prior_capture_failure') == previous_hashes and intent.get('allocation_permitted') is False,
         'preflight was not bound to capture refusal')
    expected = {prior_key: previous_hashes, 'preflight': hashes}
    need(admission.get('capture_gate') == expected, 'capture gate admission differs')
    return expected


def capture_preflight(lab, args, profile, manifest, hashes, console, bind):
    need(args.attempt == 'disk-pressure' and args.prior_admission is None, 'capture-only uses fixed separate attempt')
    version = getattr(args, 'capture_attempt', 'initial')
    need(version in ('initial', 'v4'), 'capture preflight attempt differs')
    previous = (prior_replenishment_failure(lab, manifest) if version == 'v4'
                else prior_capture_failure(lab, manifest))
    directory = lab.sec / ('disk-pressure-capture-preflight-v4' if version == 'v4'
                           else 'disk-pressure-capture-preflight')
    directory.mkdir()  # Exclusive: no repeat of ambiguous authenticated execution.
    config = {'mode': 'capture_only', 'operation': secrets.token_hex(16), 'helper_hashes': hashes,
              'initial': (lab.sec / 'admin-pass').read_text().strip()}
    need(1 <= len(config['initial']) <= 256, 'admin credential unavailable')
    body = payload(config, profile)
    (directory / 'payload.sh').write_bytes(body)
    intent = {'schema': 1, 'scope': 'healthy_capture_only', 'operation': config['operation'],
              'owner_uuid': lab.state['uuid'], 'source_sha': profile['source_sha'], 'image_id': profile['image_id'],
              'sidecar_image_id': profile['clamav_sidecar_image_id'], 'controller_revision': manifest['revision'],
              'helper_hashes': hashes, 'payload_sha256': sha(body), 'prior_capture_failure': previous,
              'allocation_permitted': False}
    with (directory / 'intent.json').open('x') as out:
        json.dump(intent, out, sort_keys=True)
        out.flush()
        import os
        os.fsync(out.fileno())
    output = io.BytesIO()
    writer = io.TextIOWrapper(output, encoding='utf-8', write_through=True)
    try:
        with contextlib.redirect_stdout(writer):
            rc = console.execute(lab, SimpleNamespace(bind=bind, timeout=180, nowait=False, as_user=False), body)
    finally:
        (directory / 'guest-result.json').write_bytes(output.getvalue())
    raw = output.getvalue()
    need(len(raw) <= 7*1024**2, 'capture result limit')
    value = json.loads(raw)
    need(value['operation'] == config['operation'] and value['helper_hashes'] == hashes
         and value.get('scope') == 'healthy_capture_only' and value.get('allocation_started') is False,
         'capture result identity differs')
    status = value['result']
    need(status in ('pass', 'fail') and (rc == 0) == (status == 'pass'), 'capture result/exit mismatch')
    summary = dict(intent, result=status, guest_result_sha256=sha(raw),
                   policy_restored=value.get('policy_restored'), no_restart=value.get('no_restart'))
    with (directory / 'complete.json').open('x') as out:
        json.dump(summary, out, sort_keys=True)
    print(json.dumps({'result': status, 'scope': 'healthy_capture_only', 'guest_result_sha256': sha(raw)}))
    return 0 if status == 'pass' else 90


def attempt_admission(lab, args, profile, manifest):
    attempt = getattr(args, 'attempt', 'disk-pressure')
    admission_path = getattr(args, 'prior_admission', None)
    need(re.fullmatch(r'disk-pressure(?:-[a-z0-9]+(?:-[a-z0-9]+)*)?', attempt)
         and len(attempt) <= 64, 'invalid attempt name')
    if attempt == 'disk-pressure':
        need(admission_path is None, 'original attempt cannot be continuation')
        return attempt, None
    need(attempt in ('disk-pressure-proof-v2', 'disk-pressure-proof-v3', 'disk-pressure-proof-v4'), 'only reviewed pressure attempts admitted')
    need(admission_path is not None, 'named attempt requires prior-failure custody admission')
    raw = regular_bytes(admission_path, 65536)
    need(any(Path(item['path']).resolve() == admission_path.resolve() and item['sha256'] == sha(raw)
             for item in manifest.get('external_inputs', [])), 'admission is not frozen')
    admission = json.loads(raw)
    need(admission.get('prior_guest_result_sha256') == ORIGINAL_PRESSURE_RESULT, 'not the reviewed original failure')
    need(admission.get('schema') == 1 and admission.get('attempt') == attempt
         and admission.get('decision') == 'allow_prospective_pressure'
         and admission.get('custody_verified') is True
         and admission.get('owner_uuid') == lab.state['uuid']
         and admission.get('source_sha') == profile['source_sha'], 'retry admission identity')
    prior = Path(admission['prior_directory'])
    need(prior.resolve() == (lab.sec / 'disk-pressure').resolve(), 'only original failed attempt admissible')
    values = {}
    for name in ('intent', 'complete', 'guest-result'):
        data = regular_bytes(prior / (name + '.json'), 7 * 1024 ** 2)
        need(sha(data) == admission['prior_' + name.replace('-', '_') + '_sha256'], 'prior evidence hash differs')
        values[name] = json.loads(data)
    intent, complete, guest = (values[k] for k in ('intent', 'complete', 'guest-result'))
    need(intent['owner_uuid'] == lab.state['uuid'] and intent['source_sha'] == profile['source_sha']
         and intent['operation'] == complete['operation'] == guest['operation']
         and complete['result'] == guest['result'] == 'fail'
         and complete['guest_result_sha256'] == admission['prior_guest_result_sha256'], 'prior failed attempt binding')
    phases = guest.get('phases', [])
    need(guest.get('policy_restored') is True and guest.get('no_restart') is True
         and len(phases) == 1, 'prior cleanup or failure scope differs')
    phase = phases[0]
    need(phase.get('mode') == 'blocks' and phase.get('result') == 'fail'
         and phase.get('fill', {}).get('result') == 'exhausted'
         and phase.get('fill', {}).get('errno') == 'ENOSPC'
         and phase.get('released') is True and phase.get('root_pressure_directory_absent') is True
         and phase.get('recovered', {}).get('pass') is True and phase.get('no_restart') is True,
         'prior failure not released accounting/capture attempt')
    rows = phase.get('samples', [])
    need(len(rows) == 64 and all(row.get('pass') is True and row.get('readiness_truthful') is True
         and row.get('pressure_present_across_sample') is False
         and len(row.get('probes', [])) == 3
         and all(p.get('verdict') in ('av_unavailable', 'clean_delivered', 'eicar_blocked')
                 and not (p.get('kind') == 'eicar' and 200 <= p.get('http_status', 0) < 300)
                 for p in row['probes']) for row in rows), 'prior enforcement failure cannot be retried unchanged')
    for field in ('custody_receipt', 'custody_archive'):
        item = admission[field]
        need(sha(regular_bytes(Path(item['path']))) == item['sha256'], 'custody bytes differ')
    custody = json.loads(regular_bytes(Path(admission['custody_receipt']['path']), 65536))
    need(custody.get('schema') == 1 and custody.get('uuid') == lab.state['uuid']
         and Path(custody['run']).resolve() == lab.run.resolve()
         and Path(custody['archive']).resolve() == Path(admission['custody_archive']['path']).resolve()
         and custody.get('ciphertext_sha256') == admission['custody_archive']['sha256']
         and all(custody.get(key) is True for key in ('roundtrip_verified', 'source_unchanged',
                    'every_file_verified', 'original_retained_at_preservation')), 'custody verification incomplete')
    additional = (capture_gate(lab, manifest, admission, attempt.rsplit('-', 1)[1])
                  if attempt in ('disk-pressure-proof-v3', 'disk-pressure-proof-v4') else None)
    return attempt, {'capture_gate': additional, 'admission_sha256': sha(raw), 'prior_operation': intent['operation'],
                     'prior_guest_result_sha256': admission['prior_guest_result_sha256'],
                     'custody_archive_sha256': admission['custody_archive']['sha256']}


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
        if getattr(args, 'capture_only', False):
            return capture_preflight(lab, args, profile, manifest, hashes, console, bind)
        need(getattr(args, 'capture_attempt', 'initial') == 'initial', 'capture attempt applies only to capture-only')
        reserve = required_reserve(lab.c)
        need(capacity(lab) >= reserve + 40 * GIB + 2 * GIB, 'reserve plus entire owned disk growth unavailable')
        escrow = args.escrow.resolve()
        receipt = recovery.verify_export(escrow)
        owned = recovery.read_json(escrow / 'source-owned.json')
        need(owned.get('uuid') == lab.state['uuid'] and owned.get('endpoint') == lab.state['endpoint'],
             'prior backup belongs to another guest')
        attempt, admission = attempt_admission(lab, args, profile, manifest)
        directory = lab.sec / attempt
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
            intent = {'schema': 1, 'attempt': attempt, 'prior_admission': admission, 'operation': config['operation'], 'owner_uuid': lab.state['uuid'],
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
    parser.add_argument('--attempt', default='disk-pressure')
    parser.add_argument('--prior-admission', type=Path)
    parser.add_argument('--capture-only', action='store_true')
    parser.add_argument('--capture-attempt', choices=('initial', 'v4'), default='initial')
    try:
        sys.exit(run(parser.parse_args()))
    except Exception:
        print('Disk-pressure attempt failed or blocked; preserve private evidence and confirm automatic release.', file=sys.stderr)
        sys.exit(90)
