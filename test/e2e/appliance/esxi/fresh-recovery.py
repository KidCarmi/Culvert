#!/usr/bin/env python3
"""Encrypted export / fresh-appliance restore via existing authenticated tty1.

No VM lifecycle operations. Escrow must be pre-created with a private Windows
ACL, outside BOTH run directories. Successful restore is not a behavioral DR
verdict: the independent admin/CA/policy/traffic/log oracles must still run.
"""
import argparse
import contextlib
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('fresh_console', HERE / 'console-priv.py')
console = importlib.util.module_from_spec(spec)
spec.loader.exec_module(console)
observe_spec = importlib.util.spec_from_file_location('fresh_observe', HERE / 'fresh-recovery-observe.py')
observation = importlib.util.module_from_spec(observe_spec)
observe_spec.loader.exec_module(observation)
MAX_ARCHIVE = 512 * 1024 * 1024
MAX_METADATA = 64 * 1024
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
HISTORY_SOURCE = '7e53720d06f525f4e5fdbfec42f52840d5b734e2'
EXPORT_NAMES = ('recovery.tar.gz.enc', 'recovery-secrets.json', 'archive-metadata.json',
                'backup-passphrase', 'admin-pass', 'source-owned.json', 'provenance.json', 'source-observation.json')
HISTORY_NAMES = ('history.cvst', 'history-passphrase', 'rotated-log-passphrase')


def require(value, message='Fresh recovery prerequisite refused; inspect private evidence.'):
    if not value:
        raise ValueError(message)


def file_hash(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def private_escrow(path, run):
    require(path.is_absolute() and path.is_dir() and not path.is_symlink())
    path, run = path.resolve(), run.resolve()
    require(not path.is_relative_to(run) and not run.is_relative_to(path), 'Escrow must be outside the lab run directory.')
    require(os.name == 'nt', 'This authenticated-console fixture requires its Windows controller.')
    # Verify existing ACL; do not briefly publish secrets and repair it later.
    script = r"""$ErrorActionPreference='Stop'; $p=$env:CULVERT_FRESH_ESCROW;
$a=Get-Acl -LiteralPath $p; if (-not $a.AreAccessRulesProtected) {exit 1};
$allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18');
foreach($r in $a.Access) {if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {exit 1}};
foreach($f in Get-ChildItem -LiteralPath $p -Force -Recurse) {
  if (($f.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {exit 1};
  foreach($r in (Get-Acl -LiteralPath $f.FullName).Access) {if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed) {exit 1}}
};
$i=Get-Item -LiteralPath $p -Force; while($null -ne $i) {if (($i.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {exit 1}; $i=$i.Parent}
"""
    env = {k: v for k, v in os.environ.items() if k.upper() != 'PSMODULEPATH'}
    env['CULVERT_FRESH_ESCROW'] = str(path)
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            env=env, capture_output=True, timeout=20, check=False)
    require(result.returncode == 0, 'Escrow ACL verification failed.')
    return path


def write_new(path, data):
    with path.open('xb') as f:
        f.write(data); f.flush(); os.fsync(f.fileno())


def read_json(path, limit=MAX_METADATA):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= limit)
    return json.loads(path.read_bytes())


def read_private_text(path, limit=4096):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= limit)
    return path.read_text(encoding='utf-8').rstrip('\r\n')


def verify_export(escrow):
    receipt = read_json(escrow / 'export-receipt.json')
    require(receipt.get('schema') == 1 and receipt.get('result') == 'pass')
    names = EXPORT_NAMES + (HISTORY_NAMES if receipt.get('history') is True else ())
    require(set(receipt['sha256']) == set(names))
    for name in names:
        path = escrow / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= (MAX_ARCHIVE if name.endswith(('.enc', '.cvst')) else MAX_METADATA))
        require(file_hash(path) == receipt['sha256'][name])
    if receipt.get('history') is True:
        verify_history_metadata(read_json(escrow / 'archive-metadata.json'), escrow / 'history.cvst')
    return receipt


def archive_identity(cfg, metadata, scope, owned):
    """Name the exact state backup separately from newer encrypted history files."""
    require(cfg['mode'] in ('export', 'restore') and
            re.fullmatch(r'fresh-[a-f0-9]{24}\.tar\.gz\.enc', cfg['archive_name']))
    require(re.fullmatch(r'[a-f0-9]{64}', metadata['archive_sha256']) and
            type(metadata['archive_bytes']) is int and 0 < metadata['archive_bytes'] <= MAX_ARCHIVE)
    return {'schema': 1, 'result': 'pass', 'mode': cfg['mode'], 'uuid': owned['uuid'],
            **{key: scope[key] for key in ('source_sha', 'ova_sha256', 'image_id')},
            'filename': cfg['archive_name'], 'sha256': metadata['archive_sha256'],
            'size_bytes': metadata['archive_bytes']}


def verify_source_absent(lab, source, deleted, receipt):
    """The owner orchestrator supplies disk-deletion evidence; recheck inventory.

    A missing VM alone is not proof its virtual disks were removed. Require the
    independently collected datastore proof bound to the exported source UUID.
    """
    require(source['uuid'] != lab.state['uuid'])
    require(source['endpoint'] == lab.c['endpoint'] and deleted['endpoint'] == source['endpoint'])
    require(deleted['owner'] == source['owner'] and deleted['ref'] == source['ref'] and deleted['path'] == source['path'])
    require(deleted['uuid'] == source['uuid'] and deleted.get('deleted') is True and deleted.get('phase') == 'deleted')
    require(receipt['schema'] == 1 and receipt['source_uuid'] == source['uuid']
            and receipt['source_path'] == source['path'] and receipt['endpoint'] == lab.c['endpoint']
            and receipt['source_disks_deleted'] is True and receipt['one_vm_limit'] == 1)
    require(receipt.get('source_disk_paths') and all(isinstance(p, str) and p for p in receipt['source_disk_paths']))
    require(not (lab.gov('vm.info', source['path'], timeout=30).get('virtualMachines') or []))
    vm = lab.vm(timeout=30)
    disks = [x.get('backing', {}).get('fileName') for x in vm['config']['hardware']['device']]
    require(not set(receipt['source_disk_paths']).intersection(disks))
    require(lab.c['max_vms'] == 1)


class Transfer:
    """One-use exact-resource binary endpoint with bounded streaming writes."""
    def __init__(self, guest, files, upload, limits):
        self.guest, self.files, self.upload, self.limits = guest, files, upload, limits
        self.paths = {name: '/' + secrets.token_hex(24) for name in files}
        self.used, self.completed = set(), set()

    def admit(self, address, path, upload, length):
        names = [k for k, v in self.paths.items() if v == path]
        require(address == self.guest and upload == self.upload and len(names) == 1)
        name = names[0]
        require(name not in self.used)
        if upload:
            require(type(length) is int and 0 < length <= self.limits[name])
            require(not os.path.lexists(self.files[name]))
        self.used.add(name)  # Interrupted transfers cannot silently retry.
        return name

    def handler(self):
        transfer = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass

            def do_POST(self):
                try:
                    name = transfer.admit(self.client_address[0], self.path, True,
                                          int(self.headers.get('Content-Length', '-1')))
                    remaining = int(self.headers['Content-Length'])
                    with transfer.files[name].open('xb') as target:
                        while remaining:
                            chunk = self.rfile.read(min(65536, remaining))
                            require(chunk)
                            target.write(chunk); remaining -= len(chunk)
                        target.flush(); os.fsync(target.fileno())
                    transfer.completed.add(name)
                    self.send_response(200); self.end_headers()
                except Exception:
                    self.send_error(403)

            def do_GET(self):
                try:
                    name = transfer.admit(self.client_address[0], self.path, False, 0)
                    path = transfer.files[name]
                    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= transfer.limits[name])
                    self.send_response(200)
                    self.send_header('Content-Length', str(path.stat().st_size)); self.end_headers()
                    with path.open('rb') as source:
                        for chunk in iter(lambda: source.read(65536), b''):
                            self.wfile.write(chunk)
                    transfer.completed.add(name)
                except Exception:
                    self.send_error(403)
        return Handler


@contextlib.contextmanager
def endpoint(transfer, bind, tls_dir):
    ctx, pin = console.make_tls(tls_dir)
    class Server(HTTPServer):
        def get_request(self):
            connection, address = self.socket.accept()
            connection.settimeout(15)
            try:
                return ctx.wrap_socket(connection, server_side=True), address
            except Exception:
                connection.close()
                raise
    server = Server((bind, 0), transfer.handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield pin, {k: 'https://' + bind + ':' + str(server.server_port) + p for k, p in transfer.paths.items()}
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=20)


def run(args):
    require(ipaddress.ip_address(args.bind).version == 4 and not ipaddress.ip_address(args.bind).is_unspecified)
    lab = console.b.module.Lab(args.scope)
    profile_spec = importlib.util.spec_from_file_location('fresh_candidate_identities', HERE / 'candidate-identities.py')
    identities = importlib.util.module_from_spec(profile_spec); profile_spec.loader.exec_module(identities)
    source = identities.scope_profile(lab.c)['source_sha']
    history = getattr(args, 'history', False)
    require(not history or source in (identities.E7E, identities.E7C, identities.E91, identities.E72, identities.EBAD788), 'History qualification requires a reviewed history-capable candidate.')
    require(lab.c['source_sha'] == source and lab.c['max_vms'] == 1)
    console.b.module.validate_scope(lab.c)
    escrow = private_escrow(args.escrow, lab.run)
    files = {'archive': escrow / 'recovery.tar.gz.enc', 'secrets': escrow / 'recovery-secrets.json',
             'metadata': escrow / 'archive-metadata.json'}
    if history:
        files['history'] = escrow / 'history.cvst'
    with console.b.module.locked(lab.run):
        lab.vm(timeout=30)
        if args.mode == 'export':
            require(not any(escrow.iterdir()), 'Export requires an empty private escrow directory.')
            password = secrets.token_hex(32)
            write_new(escrow / 'backup-passphrase', password.encode('ascii'))
            admin_password = read_private_text(lab.sec / 'admin-pass')
            write_new(escrow / 'admin-pass', admin_password.encode('utf-8'))
            if history:
                for name in ('history-passphrase', 'rotated-log-passphrase'):
                    write_new(escrow / name, secrets.token_hex(32).encode('ascii'))
            write_new(escrow / 'source-owned.json', json.dumps(lab.state).encode())
            provenance = {k: lab.c[k] for k in ('source_sha', 'image_id', 'ova_sha256', 'endpoint')}
            write_new(escrow / 'provenance.json', json.dumps(provenance).encode())
            observed = observation.observe(lab.guest_ip(timeout=30), 'labadmin', admin_password)
            write_new(escrow / 'source-observation.json', json.dumps(observed).encode())
        else:
            require(args.source_ledger and args.deletion_receipt)
            receipt = verify_export(escrow)
            require((receipt.get('history') is True) == history, 'History mode must match the preserved export.')
            source_owned = read_json(escrow / 'source-owned.json')
            verify_source_absent(lab, source_owned, read_json(args.source_ledger), read_json(args.deletion_receipt))
            provenance = read_json(escrow / 'provenance.json')
            require(all(provenance[k] == lab.c[k] for k in provenance))
            metadata = read_json(files['metadata'])
            require(metadata['archive_sha256'] == file_hash(files['archive'])
                    and metadata['archive_bytes'] == files['archive'].stat().st_size <= MAX_ARCHIVE)
            require(metadata['source_sha'] == source and metadata['image_id'] == lab.c['image_id'])
            if history:
                verify_history_metadata(metadata, files['history'])
            password = (escrow / 'backup-passphrase').read_text(encoding='ascii')
            require(re.fullmatch(r'[a-f0-9]{64}', password))
            files.pop('metadata')
        transfer = Transfer(lab.guest_ip(timeout=30), files, args.mode == 'export',
                            {k: MAX_ARCHIVE if k in ('archive', 'history') else MAX_METADATA for k in files})
        transport_dir = escrow / ('transfer-' + args.mode + '-' + secrets.token_hex(8))
        transport_dir.mkdir()
        cfg = {'mode': args.mode, 'source_sha': source, 'image_id': lab.c['image_id'],
               'backup_password': password, 'archive_name': 'fresh-' + secrets.token_hex(12) + '.tar.gz.enc',
               'archive_limit': MAX_ARCHIVE, 'nonce': secrets.token_hex(12)}
        if args.mode == 'restore':
            cfg.update(archive_sha256=metadata['archive_sha256'], archive_bytes=metadata['archive_bytes'])
        if history:
            cfg['history'] = {'password': read_private_text(escrow / 'history-passphrase'),
                              'rotated_log_password': read_private_text(escrow / 'rotated-log-passphrase'),
                              'admin_password': read_private_text(escrow / 'admin-pass'),
                              'tag': 'freshhist' + secrets.token_hex(8)}
            require(all(re.fullmatch(r'[a-f0-9]{64}', cfg['history'][k])
                        for k in ('password', 'rotated_log_password')))
            if args.mode == 'restore':
                cfg['history'].update(metadata['history'])
        with endpoint(transfer, args.bind, transport_dir) as (pin, urls):
            cfg.update(pin=pin, urls=urls)
            guest = (HERE / 'fresh-recovery-guest.py').read_text(encoding='utf-8')
            payload = "set +x\nset -euo pipefail\npython3 - <<'CULVERT_FRESH_RECOVERY_PY'\n" + guest
            payload += '\nmain(' + repr(cfg) + ")\nCULVERT_FRESH_RECOVERY_PY\n"
            output = io.BytesIO()
            writer = io.TextIOWrapper(output, encoding='utf-8', write_through=True)
            options = SimpleNamespace(bind=args.bind, timeout=1800, nowait=False, as_user=False)
            with contextlib.redirect_stdout(writer):
                rc = console.execute(lab, options, payload.encode())
            report = output.getvalue()
            write_new(transport_dir / 'guest-result.json', report)
            require(rc == 0 and transfer.completed == set(files), 'Fresh recovery phase failed; no automatic retry.')
        if args.mode == 'export':
            metadata = read_json(files['metadata'])
            require(metadata['archive_bytes'] == files['archive'].stat().st_size
                    and metadata['archive_sha256'] == file_hash(files['archive']))
            require(set(read_json(files['secrets'])) == {'CULVERT_CA_PASSPHRASE', 'CULVERT_LOG_PASSPHRASE', 'CULVERT_SESSION_SECRET'})
            if history:
                verify_history_metadata(metadata, files['history'])
            names = EXPORT_NAMES + (HISTORY_NAMES if history else ())
            receipt = {'schema': 1, 'result': 'pass', 'sha256': {name: file_hash(escrow / name) for name in names}}
            if history:
                receipt['history'] = True
            write_new(escrow / 'export-receipt.json', json.dumps(receipt).encode())
        else:
            observed = observation.observe(lab.guest_ip(timeout=30), 'labadmin', read_private_text(escrow / 'admin-pass'),
                                           baseline=read_json(escrow / 'source-observation.json'))
            if history:
                checked = observation.observe_history(lab.guest_ip(timeout=30), 'labadmin',
                    read_private_text(escrow / 'admin-pass'), metadata['history'])
                write_new(transport_dir / 'restored-history.json', json.dumps(checked).encode())
                observed['historical_encrypted_log_recovery'] = checked
            write_new(transport_dir / 'restored-observation.json', json.dumps(observed).encode())
        # Created only after transfer, restore/export validation and behavioral
        # oracles pass. The recovery baseline must explicitly select this name;
        # inventory order can put a newer CVST history archive first.
        write_new(lab.sec / ('fresh-recovery-' + args.mode + '-archive.json'),
                  json.dumps(archive_identity(cfg, metadata, lab.c, lab.state)).encode())
        print(json.dumps({'phase': args.mode, 'result': 'pass', 'archive_sha256': metadata['archive_sha256'],
                          'behavioral_recovery': 'pass' if args.mode == 'restore' else 'not-yet-run',
                          'historical_encrypted_log_recovery': ('pass' if args.mode == 'restore' else 'exported-and-validated')
                          if history else 'blocked: supported archive excludes logs'}))


def verify_history_metadata(metadata, archive):
    h = metadata['history']
    require(set(h) == {'archive_sha256', 'archive_bytes', 'tag', 'markers', 'dry_run_verified', 'source_encrypted'})
    require(h['archive_sha256'] == file_hash(archive) and
            0 < h['archive_bytes'] == archive.stat().st_size <= MAX_ARCHIVE)
    require(h.get('dry_run_verified') is True and h.get('source_encrypted') is True)
    observation.validate_history(h['markers'], h['tag'], expected_count=12)
    with archive.open('rb') as stream:
        require(stream.read(8) == b'CVRTST01')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('export', 'restore'))
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--escrow', type=Path, required=True)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--source-ledger', type=Path)
    parser.add_argument('--deletion-receipt', type=Path)
    parser.add_argument('--history', action='store_true', help='Qualify separately encrypted history export and fresh recovery with a rotated log key (7e only).')
    args = parser.parse_args()
    try:
        run(args)
        return 0
    except Exception:
        print('Fresh recovery blocked; preserve private evidence and do not retry an ambiguous mutation.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
