#!/usr/bin/env python3
"""Local-only ESXi adapter. No host changes, snapshots, or shared-disk fills.

Credentials enter govc via environment only. Scope and run state are local,
operator-controlled inputs. Simulator/unit tests never qualify an appliance.
"""
import argparse
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import tarfile
import time
from urllib.parse import urlsplit
import uuid
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
ORIGINAL_SHA = 'e24eb542f973fb70360bad5124ef81fdab8b6f8d67af601720613cbcca3700a4'
ORIGINAL_SOURCE = '4c4b7728c0e6a1746e968d935b635fc652647e6f'
ORIGINAL_IMAGE = 'sha256:384f4c4b1bad91be93dc8b78adb974b6c57dd9b4c8f534bfdbafc2c1e4f1ab04'
OVF = '{http://schemas.dmtf.org/ovf/envelope/1}'
RASD = '{http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData}'
GIB = 1024 ** 3


class Refused(Exception):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


def digest(stream):
    h = hashlib.sha256()
    for block in iter(lambda: stream.read(1024 * 1024), b''):
        h.update(block)
    return h.hexdigest()


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    tmp.replace(path)


def credential_environment(c, inherited):
    """Decrypt only an explicitly configured Windows credential into child env."""
    env = dict(inherited)
    credential_file = c.get('credential_file')
    if credential_file:
        require(os.name == 'nt', 'credential_file requires Windows DPAPI')
        require(Path(credential_file).is_file(), 'run Set-LabCredential.ps1 in your Windows account first')
        loader_env = dict(os.environ, CULVERT_ESXI_CREDENTIAL_FILE=credential_file)
        script = ("$ErrorActionPreference='Stop'; "
                  "$c=Import-Clixml -LiteralPath $env:CULVERT_ESXI_CREDENTIAL_FILE; "
                  "if ($c -isnot [System.Management.Automation.PSCredential]) { throw 'Wrong credential type' }; "
                  "@{username=$c.UserName;password=$c.GetNetworkCredential().Password} | ConvertTo-Json -Compress")
        result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                                env=loader_env, capture_output=True, text=True, timeout=30)
        require(result.returncode == 0, 'Windows credential decryption failed for this account')
        data = json.loads(result.stdout)
        require(data.get('username') and data.get('password'), 'empty Windows credential')
        env.update(GOVC_USERNAME=data['username'], GOVC_PASSWORD=data['password'])
    return env


def stop_process(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def private_cleanup_entry(path, root):
    """Validate without following links; return identity for the deletion fence."""
    info = path.lstat()
    require(not stat.S_ISLNK(info.st_mode) and not
            getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400),
            'private cleanup refuses symlinks, junctions and reparse points')
    require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode),
            'private cleanup refuses nonregular entries')
    resolved = path.resolve(strict=True)
    require(resolved == path.absolute() and (resolved == root or root in resolved.parents),
            'private cleanup path escaped the run secrets directory')
    return info.st_dev, info.st_ino, info.st_mode


def cleanup_private_tree(run, sec):
    """Validate the COMPLETE private tree before removing any entry; retain SEC.

    No rmtree/shell recursion follows attacker-controlled paths. Recheck each
    identity/resolved path immediately before unlink/rmdir; unexpected changes
    stop cleanup and never produce a successful cleanup verdict.
    """
    expected = run.resolve(strict=True) / 'secrets'
    require(sec.absolute() == expected and sec.resolve(strict=True) == expected,
            'private cleanup requires this exact run secrets directory')
    root_identity = private_cleanup_entry(sec, expected)
    require(stat.S_ISDIR(root_identity[2]), 'private cleanup root must be a directory')
    pending, entries = [sec], []
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            identity = private_cleanup_entry(path, expected)
            entries.append((path, identity))
            if stat.S_ISDIR(identity[2]):
                pending.append(path)
    # All link/type/containment checks above finish before the first deletion.
    for path, identity in sorted(entries, key=lambda item: len(item[0].parts), reverse=True):
        require(private_cleanup_entry(sec, expected) == root_identity,
                'private cleanup root changed during cleanup')
        require(private_cleanup_entry(path, expected) == identity,
                'private cleanup entry changed during cleanup')
        if stat.S_ISDIR(identity[2]):
            path.rmdir()
        else:
            path.unlink()
    require(private_cleanup_entry(sec, expected) == root_identity and not any(sec.iterdir()),
            'private cleanup is incomplete; run secrets were retained')


class TunnelSupervisor:
    """Controller-owned reconnects; transport health never proves a guest reboot."""
    def __init__(self, resolve, start, ready, event, timeout=2400,
                 clock=time.monotonic, sleep=time.sleep):
        self.resolve, self.start, self.ready, self.event = resolve, start, ready, event
        self.timeout, self.clock, self.sleep = timeout, clock, sleep
        self.proc = None
        self.connections = 0

    def close(self):
        stop_process(self.proc)
        self.proc = None

    def ensure(self, budget=None):
        if self.proc is not None and self.proc.poll() is None:
            return
        self.close()
        deadline = self.clock() + min(self.timeout, self.timeout if budget is None else budget)
        while self.clock() < deadline:
            candidate = None
            try:
                # Re-resolve through the owned VM on EVERY reconnect, including
                # DHCP changes, then enforce CIDR and the stable SSH key alias.
                ip = self.resolve(min(30, max(1, int(deadline - self.clock()))))
                candidate = self.start(ip)
                attempt_deadline = min(deadline, self.clock() + 20)
                while candidate.poll() is None and self.clock() < attempt_deadline:
                    if self.ready(min(5, max(.1, attempt_deadline - self.clock()))):
                        self.proc = candidate
                        candidate = None
                        self.connections += 1
                        self.event('transport-connected' if self.connections == 1 else 'transport-reconnected',
                                   'pass', 'SSH forwarding ready; host key retained; guest reboot verdict remains separate')
                        return
                    self.sleep(min(.25, max(0, attempt_deadline - self.clock())))
            except (Refused, OSError, subprocess.TimeoutExpired):
                pass  # Retry only transport reads/connections; never VM mutations.
            finally:
                stop_process(candidate)
            self.sleep(min(2, max(0, deadline - self.clock())))
        self.event('transport-recovery', 'fail', 'SSH forwarding did not recover within its bounded deadline')
        raise Refused('SSH forwarding recovery deadline exceeded; guest availability is unproven')


def verify_ova(path, expected):
    """Stream hashes, never extract; refuse empty/partial/ambiguous manifests."""
    require(re.fullmatch('[0-9a-f]{64}', expected), 'expected SHA256 required')
    with path.open('rb') as f:
        actual = digest(f)
    require(actual == expected, 'OVA SHA256 mismatch')
    with tarfile.open(path, 'r:') as tf:
        members = tf.getmembers()
        names = [m.name for m in members]
        require(len(names) == len(set(names)), 'duplicate archive member')
        require(all(m.isfile() and re.fullmatch(r'[A-Za-z0-9_.-]+', m.name)
                    and m.name not in ('.', '..') for m in members), 'unsafe archive member')
        mfs = [n for n in names if n.endswith('.mf')]
        ovfs = [n for n in names if n.endswith('.ovf')]
        require(len(mfs) == len(ovfs) == 1, 'one manifest and one OVF required')
        require(tf.getmember(mfs[0]).size < 1024 * 1024, 'manifest too large')
        entries = {}
        for line in tf.extractfile(mfs[0]).read().decode('ascii').splitlines():
            if not line.strip():
                continue
            m = re.fullmatch(r'SHA256\(([^)]+)\)\s*=\s*([0-9a-fA-F]{64})', line.strip())
            require(m is not None, 'unsupported or malformed manifest line')
            name, want = m.groups()
            require(name not in entries, 'duplicate manifest entry')
            entries[name] = want.lower()
        require(set(entries) == set(names) - set(mfs), 'manifest must cover every payload exactly')
        for name, want in entries.items():
            require(digest(tf.extractfile(name)) == want, 'manifest digest mismatch: ' + name)
        require(tf.getmember(ovfs[0]).size < 4 * 1024 * 1024, 'OVF too large')
        xml = tf.extractfile(ovfs[0]).read()
        require(b'<!DOCTYPE' not in xml.upper() and b'<!ENTITY' not in xml.upper(), 'XML declarations refused')
        doc = ET.fromstring(xml)
        disk_bytes = 0
        for disk in doc.iter(OVF + 'Disk'):
            units = disk.get(OVF + 'capacityAllocationUnits', 'byte')
            scale = {'byte': 1, 'byte * 2^20': 1024**2, 'byte * 2^30': GIB}.get(units)
            require(scale is not None, 'unsupported disk capacity units')
            disk_bytes += int(disk.get(OVF + 'capacity')) * scale
        resources = {}
        for item in doc.iter(OVF + 'Item'):
            resources[item.findtext(RASD + 'ResourceType')] = item.findtext(RASD + 'VirtualQuantity')
            if item.findtext(RASD + 'ResourceType') == '4':
                require(item.findtext(RASD + 'AllocationUnits').lower() == 'byte * 2^20', 'memory units must be MiB')
        refs = [f.get(OVF + 'href') for f in doc.iter(OVF + 'File')]
        require(refs and all(n in entries for n in refs), 'OVF has unverified file references')
        require(disk_bytes > 0, 'no disk capacity found')
        return dict(ova_sha256=actual, disk_bytes=disk_bytes, cpus=int(resources['3']),
                    memory_mb=int(resources['4']), manifest=entries,
                    hardware=doc.findtext('.//{http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData}VirtualSystemType'),
                    networks=[n.get(OVF + 'name') for n in doc.iter(OVF + 'Network')])


def validate_scope(c):
    required = ('endpoint', 'host', 'datastore', 'network', 'folder', 'pool', 'ova',
                'ova_sha256', 'source_sha', 'image_id', 'run_dir', 'max_vms', 'max_vcpus',
                'max_memory_mb', 'max_disk_gib', 'datastore_headroom_gib',
                'host_headroom_mb', 'host_cpu_headroom_mhz', 'guest_cidr')
    missing = [k for k in required if c.get(k) in (None, '')]
    require(not missing, 'missing scope: ' + ', '.join(missing))
    u = urlsplit(c['endpoint'])
    require(u.scheme == 'https' and u.hostname and not u.username and not u.password,
            'endpoint must be HTTPS without credentials')
    require(not u.query and not u.fragment and u.path in ('', '/', '/sdk'), 'invalid endpoint')
    require(type(c.get('tls_insecure', False)) is bool, 'tls_insecure must be boolean')
    require(c.get('credential_mode', 'key') in ('key', 'none'), 'credential_mode must be key or none')
    if c.get('tls_insecure'):
        require(c.get('tls_exception_endpoint') == c['endpoint'], 'TLS exception must name this exact endpoint')
    for k in ('host', 'datastore', 'network', 'folder', 'pool'):
        require(c[k].startswith('/') and not any(x in c[k] for x in '*?[]\n\r'), 'exact inventory path required: ' + k)
    for k in ('max_vms', 'max_vcpus', 'max_memory_mb', 'max_disk_gib',
              'datastore_headroom_gib', 'host_headroom_mb', 'host_cpu_headroom_mhz'):
        require(type(c[k]) is int and c[k] > 0, 'positive integer required: ' + k)
    require(c['max_vms'] == 1, 'adapter supports one live VM per scope; use sequential fresh imports')
    require(re.fullmatch('[0-9a-f]{40}', c['source_sha']), 'source SHA required')
    require(re.fullmatch('sha256:[0-9a-f]{64}', c['image_id']), 'image ID required')
    if c['ova_sha256'] == ORIGINAL_SHA:
        require(c['source_sha'] == ORIGINAL_SOURCE and c['image_id'] == ORIGINAL_IMAGE,
                'original candidate provenance does not match recorded identity')
    ipaddress.ip_network(c['guest_cidr'])
    require(Path(c['run_dir']).is_absolute(), 'run_dir must be absolute')
    require(Path(c['ova']).is_absolute(), 'OVA path must be absolute')
    return c


def check_capacity(c, artifact, ds, host):
    require(artifact['cpus'] <= c['max_vcpus'], 'OVA exceeds vCPU budget')
    require(artifact['memory_mb'] <= c['max_memory_mb'], 'OVA exceeds RAM budget')
    require(artifact['disk_bytes'] <= c['max_disk_gib'] * GIB, 'OVA exceeds disk budget')
    require(ds['accessible'] and ds.get('maintenanceMode', 'normal') == 'normal', 'datastore unavailable')
    # Reserve room for ALL provisioned bytes, VM swap and conservative logs/metadata.
    reserve = artifact['disk_bytes'] + artifact['memory_mb'] * 1024**2 + 2 * GIB
    require(ds['freeSpace'] - reserve >= c['datastore_headroom_gib'] * GIB, 'insufficient datastore headroom')
    require(host['runtime']['connectionState'] == 'connected' and not host['runtime']['inMaintenanceMode'], 'host unavailable')
    hw, stats = host['hardware'], host['quickStats']
    free_mb = hw['memorySize'] // 1024**2 - stats['overallMemoryUsage']
    require(free_mb - artifact['memory_mb'] >= c['host_headroom_mb'], 'insufficient host RAM headroom')
    free_cpu = hw['numCpuCores'] * hw['cpuMhz'] - stats['overallCpuUsage']
    require(free_cpu - artifact['cpus'] * hw['cpuMhz'] >= c['host_cpu_headroom_mhz'], 'insufficient host CPU headroom')
    return dict(datastore_reserve_bytes=reserve, datastore_free_bytes=ds['freeSpace'],
                host_free_mb=free_mb, host_free_cpu_mhz=free_cpu)


def network_ref(listing, path):
    elements = listing.get('elements') or []
    require(len(elements) == 1 and elements[0].get('Path') == path,
            'one exact network path required')
    ref = elements[0].get('Object', {}).get('self', {})
    require(ref.get('type') in ('Network', 'DistributedVirtualPortgroup') and
            isinstance(ref.get('value'), str) and bool(ref['value']) and
            not any(ord(c) < 32 for c in ref['value']), 'one supported network required')
    return dict(type=ref['type'], value=ref['value'])


def assert_owned(vm, state, c):
    cfg = vm.get('config') or {}
    require(cfg.get('annotation') == state['owner'], 'ownership marker mismatch; refusing mutation')
    require(vm['name'] == state['name'], 'VM name mismatch')
    if state.get('uuid'):
        require(cfg.get('uuid') == state['uuid'] and vm['self'] == state['ref'], 'VM identity mismatch')
    require(vm.get('runtime', {}).get('host') == state['host_ref'], 'VM moved outside designated host')
    require(vm.get('datastore') == [state['ds_ref']], 'VM datastore changed')
    require(vm.get('network') == [state['network_ref']], 'VM network changed')
    require(not vm.get('snapshot') and not vm.get('rootSnapshot'), 'unexpected snapshots; manual review required')
    return vm


class Lab:
    def __init__(self, scope):
        self.scope_path = scope.resolve()
        self.c = json.loads(scope.read_text(encoding='utf-8-sig'))
        run = self.c.get('run_dir') or str(ROOT / '.tools/esxi-run')
        self.run = Path(run).resolve()
        self.ev = self.run / 'evidence'
        self.sec = self.run / 'secrets'
        self.state_file = self.run / 'owned.json'
        for p in (self.run, self.ev, self.sec):
            p.mkdir(parents=True, exist_ok=True)
        self.govc = self.c.get('govc', 'govc')
        self.state = json.loads(self.state_file.read_text()) if self.state_file.exists() else {}
        self._credential_env = None

    def record(self, check, result, detail):
        row = dict(step='ESXi', check=check, result=result, detail=detail,
                   timestamp=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        with (self.ev / 'adapter.jsonl').open('a', encoding='utf-8') as f:
            f.write(json.dumps(row) + '\n')
        print(f'{result.upper()}: {check}: {detail}', flush=True)

    def save(self):
        atomic_json(self.state_file, self.state)

    def gov(self, *args, timeout=120, json_output=True):
        # Do not inherit arbitrary govc target/debug settings from the terminal.
        env = {k: v for k, v in os.environ.items() if not k.startswith('GOVC_')}
        for k in ('GOVC_USERNAME', 'GOVC_PASSWORD', 'GOVC_TLS_CA_CERTS', 'GOVC_TLS_KNOWN_HOSTS',
                  'GOVC_CERTIFICATE', 'GOVC_PRIVATE_KEY'):
            if k in os.environ:
                env[k] = os.environ[k]
        if self.c.get('tls_insecure'):
            require(self.c.get('tls_exception_endpoint') == self.c['endpoint'], 'TLS exception endpoint mismatch')
        if self._credential_env is None:
            self._credential_env = credential_environment(self.c, env)
        env = dict(self._credential_env)
        env.update(GOVC_URL=self.c['endpoint'], GOVC_PERSIST_SESSION='false',
                   GOVC_INSECURE='true' if self.c.get('tls_insecure') else 'false')
        cmd = [self.govc, args[0]] + (['-json'] if json_output else []) + list(args[1:])
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout,
                               encoding='utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            raise Refused(f'govc {args[0]} timed out; reconcile owned state before retry') from None
        # Raw stderr can contain endpoint credentials or OVF properties: never export.
        # After up has created the restricted key directory, preserve failure
        # diagnostics privately so an import can be reconciled without guessing.
        if r.returncode and self.state and (self.sec / 'id_ed25519').is_file():
            atomic_json(self.sec / 'govc-error.json', dict(command=args[0],
                        returncode=r.returncode, stdout=r.stdout, stderr=r.stderr))
        require(r.returncode == 0, f'govc {args[0]} failed (exit {r.returncode}); no mutation retry')
        return json.loads(r.stdout) if json_output else r.stdout.strip()

    def vm(self, timeout=120):
        require(self.state and not self.state.get('deleted'), 'no active owned VM')
        require(self.state['endpoint'] == self.c['endpoint'], 'endpoint changed')
        vms = self.gov('vm.info', self.state['path'], timeout=timeout)['virtualMachines'] or []
        require(len(vms) == 1, 'expected exactly one owned VM')
        return assert_owned(vms[0], self.state, self.c)

    def preflight(self):
        validate_scope(self.c)
        artifact = verify_ova(Path(self.c['ova']), self.c['ova_sha256'])
        existing = self.gov('find', '-i', self.c['folder'], '-type', 'm', '-name', 'culvert-esxi-*', json_output=False)
        require(not existing, 'an ESXi lab VM already exists in this folder; one-VM scope refused')
        about = self.gov('about')['about']
        require('simulator' not in about['fullName'].lower(), 'simulator is not ESXi qualification')
        hs = self.gov('host.info', self.c['host'])['hostSystems']
        dss = self.gov('datastore.info', self.c['datastore'])['datastores']
        require(len(hs) == len(dss) == 1, 'exact host and datastore required')
        net = network_ref(self.gov('ls', '-i', self.c['network']), self.c['network'])
        require(hs[0]['self'] in [x['key'] for x in dss[0]['host']], 'datastore not mounted on designated host')
        capacity = check_capacity(self.c, artifact, dss[0]['summary'], hs[0]['summary'])
        sha = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(['git', '-C', str(ROOT), 'status', '--porcelain'], capture_output=True, text=True, check=True).stdout.strip()
        sources = {}
        for source in (Path(__file__), HERE / 'guest-checks.sh', HERE / 'guest-observe.py',
                       HERE / 'restore-checks.sh', HERE / 'console-checks.py', HERE / 'console-ocr.ps1',
                       HERE / 'bootstrap-checks.py', HERE / 'private-keystrokes.go', HERE / 'esxi-port-relay.py',
                       HERE / 'govc-sha256-negotiation.patch', HERE.parent / 'lab/appliance-lab.sh'):
            with source.open('rb') as f:
                sources[source.relative_to(ROOT).as_posix()] = digest(f)
        data = dict(artifact=artifact, expected_source=self.c['source_sha'], expected_image=self.c['image_id'],
                    original_candidate=artifact['ova_sha256'] == ORIGINAL_SHA,
                    harness_sha=sha, harness_dirty=bool(dirty), harness_file_sha256=sources,
                    govc_version=self.gov('version', json_output=False),
                    tls_verification='owner-authorized-exception' if self.c.get('tls_insecure') else 'verified',
                    hypervisor=hs[0]['summary']['config']['product'], capacity=capacity,
                    property_delivery='govc ImportVApp + InjectOvfEnv via VMware guestinfo',
                    credential_mode=self.c.get('credential_mode', 'key'),
                    host_ref=hs[0]['self'], ds_ref=dss[0]['self'], network_ref=net)
        if self.c.get('govc_build'):
            with Path(self.govc).open('rb') as f:
                actual_binary = digest(f)
            require(actual_binary == self.c['govc_build']['binary_sha256'], 'local govc binary identity changed')
            data['govc_local_build'] = self.c['govc_build']
        atomic_json(self.ev / 'preflight.json', data)
        self.record('preflight', 'pass', 'checksum, complete manifest, scope and measured capacity verified')
        return data

    def up(self):
        require(not self.state, 'run directory already has an import ledger; use down/reconcile, never reimport')
        data = self.preflight()
        require(len(data['artifact']['networks']) == 1, 'one OVA network required')
        self.state = dict(name='culvert-esxi-' + uuid.uuid4().hex[:12], owner='LOCAL-ESXI:' + str(uuid.uuid4()),
                          endpoint=self.c['endpoint'], host_ref=data['host_ref'], ds_ref=data['ds_ref'],
                          network_ref=data['network_ref'], phase='import-pending')
        self.state['path'] = self.c['folder'].rstrip('/') + '/' + self.state['name']
        self.save()  # Written BEFORE import, including timeout/partial-import recovery.
        self.sec.chmod(0o700)
        if os.name == 'nt':
            account = os.environ['USERDOMAIN'] + '\\' + os.environ['USERNAME']
            subprocess.run(['icacls', str(self.sec), '/inheritance:r', '/grant:r',
                            account + ':(OI)(CI)F', '*S-1-5-18:(OI)(CI)F'],
                           capture_output=True, check=True, timeout=30)
        key = self.sec / 'id_ed25519'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)], check=True, timeout=30)
        (self.sec / 'admin-pass').write_text('Qv7' + secrets.token_hex(18), encoding='ascii')
        props = {'instance-id': self.state['name'], 'hostname': self.state['name'],
                 'culvert.net.mode': 'dhcp'}
        if self.c.get('credential_mode', 'key') == 'key':
            props['public-keys'] = key.with_suffix('.pub').read_text().strip()
        static = self.c.get('static')
        if static:
            addr = ipaddress.ip_interface(static['address'])
            require(addr.ip in ipaddress.ip_network(self.c['guest_cidr']), 'static address outside approved CIDR')
            ipaddress.ip_address(static['gateway'])
            for ip in static['dns'].split(','):
                ipaddress.ip_address(ip)
            props.update({'culvert.net.mode': 'static', **{'culvert.net.' + k: static[k] for k in ('address', 'gateway', 'dns')}})
        opts = dict(Name=self.state['name'], Annotation=self.state['owner'], PowerOn=False,
                    InjectOvfEnv=True, WaitForIP=False, MarkAsTemplate=False, DiskProvisioning='thin',
                    PropertyMapping=[dict(Key=k, Value=v) for k, v in props.items()],
                    NetworkMapping=[dict(Name=data['artifact']['networks'][0], Network=self.c['network'])])
        optfile = self.sec / 'import.json'
        atomic_json(optfile, opts)
        require(not (self.gov('vm.info', self.state['path']).get('virtualMachines') or []), 'generated VM name already exists')
        self.gov('import.ova', '-m', '-options=' + str(optfile), '-name=' + self.state['name'],
                 '-ds=' + self.c['datastore'], '-host=' + self.c['host'], '-folder=' + self.c['folder'],
                 '-pool=' + self.c['pool'], self.c['ova'], timeout=1800, json_output=False)
        vm = self.vm()
        self.state.update(uuid=vm['config']['uuid'], ref=vm['self'], phase='imported')
        self.save()
        self.record('import', 'pass', 'owned VM imported powered off; VMware guestinfo injection enabled')
        self.gov('vm.power', '-on', self.state['path'], json_output=False)
        self.state['phase'] = 'powered-on'
        self.save()
        self.record('power-on', 'pass', 'owned VM powered on; guest qualification is separate')

    def guest_ip(self, timeout=150):
        started = time.monotonic()
        self.vm(timeout=max(1, timeout // 2))
        remaining = max(1, int(timeout - (time.monotonic() - started)))
        ip = self.gov('vm.ip', f'-wait={max(1, remaining-2)}s', '-a', '-v4', self.state['path'],
                      timeout=remaining, json_output=False)
        require(ip and ',' not in ip and '\n' not in ip, 'guest IP missing or ambiguous')
        require(ipaddress.ip_address(ip) in ipaddress.ip_network(self.c['guest_cidr']), 'guest IP outside approved CIDR')
        return ip

    def ssh_command(self, ip, strict=True):
        return ['ssh', '-F', 'none', '-i', str(self.sec / 'id_ed25519'), '-o', 'IdentitiesOnly=yes',
                '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=' + ('yes' if strict else 'accept-new'),
                '-o', 'HostKeyAlias=' + self.state['name'], '-o', 'UserKnownHostsFile=' + str(self.sec / 'known_hosts'),
                '-o', 'ConnectTimeout=5', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2', 'culvert@' + ip]

    def inspect(self):
        """Observe the owned VM without starting/restarting guest services."""
        vm = self.vm()
        cfg, runtime = vm['config'], vm['runtime']
        facts = dict(firmware=cfg.get('firmware', 'unknown'),
                     virtual_hardware=cfg.get('version'),
                     cpus=cfg.get('hardware', {}).get('numCPU'),
                     memory_mb=cfg.get('hardware', {}).get('memoryMB'),
                     power_state=runtime['powerState'],
                     tools_status=vm.get('guest', {}).get('toolsRunningStatus'),
                     ova_sha256=self.c['ova_sha256'])
        atomic_json(self.ev / 'boot-observation.json', facts)
        self.record('firmware-observed', 'info', facts['firmware'])
        require(runtime['powerState'] == 'poweredOn', 'console observation needs a powered-on owned VM')
        # Screens can show setup secrets: keep private until explicitly reviewed.
        self.gov('vm.console', '-capture=' + str(self.sec / ('console-' + str(time.time_ns()) + '.png')),
                 self.state['path'], json_output=False)
        self.record('console-captured', 'info', 'private screenshot captured; not automatically exported')
        ip = self.guest_ip(timeout=30)
        probe = (HERE / 'guest-observe.py').read_text(encoding='utf-8')
        result = subprocess.run(self.ssh_command(ip, strict=False) + ['python3 -'],
                                input=probe, capture_output=True, text=True, timeout=60)
        require(result.returncode == 0, 'read-only guest observation unavailable')
        guest = json.loads(result.stdout)
        atomic_json(self.ev / 'guest-observation.json', guest)
        self.record('kernel-observed', 'pass', 'SSH reached the owned guest and read its kernel version')
        self.record('firstboot-observed', 'pass' if guest['complete'] else 'info',
                    'completion marker present' if guest['complete'] else 'completion marker absent at observation')
        self.record('firstboot-ordering-cycle', 'fail' if guest['firstboot_cycle'] else 'info',
                    'current boot journal reports firstboot ordering cycle' if guest['firstboot_cycle'] else 'no matching cycle in current boot journal')
        self.record('vmware-property-observed', 'pass' if guest['instance_id'] == self.state['name'] else 'fail',
                    'guestinfo instance identity matched' if guest['instance_id'] == self.state['name'] else 'guestinfo identity missing or mismatched')

    def qualify(self):
        require(self.state.get('phase') == 'powered-on', 'qualify is single-use on a fresh import')
        sources = {}
        for source in (Path(__file__), HERE / 'guest-checks.sh', HERE / 'restore-checks.sh',
                       HERE / 'esxi-port-relay.py',
                       HERE.parent / 'lab/appliance-lab.sh'):
            with source.open('rb') as stream:
                sources[source.relative_to(ROOT).as_posix()] = digest(stream)
        revision = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                                  capture_output=True, text=True, check=True).stdout.strip()
        atomic_json(self.ev / 'qualification-harness.json',
                    dict(harness_sha=revision, harness_file_sha256=sources))
        bash = self.c.get('bash', 'bash')
        # Verify host prerequisites before guest mutations.
        probe = subprocess.run([bash, '-c', 'for t in ssh curl openssl timeout; do command -v "$t" || exit 3; done'], capture_output=True, timeout=30)
        require(probe.returncode == 0, 'Bash host needs ssh, curl, openssl and timeout')
        ip = self.guest_ip()
        ssh = self.ssh_command(ip, strict=False)
        deadline = time.monotonic() + 2400
        while True:
            r = subprocess.run(ssh + ['sudo test -f /var/lib/culvert-appliance/state/complete.done'], capture_output=True, timeout=60)
            if r.returncode == 0:
                break
            require(time.monotonic() < deadline, 'first boot did not finish in 2400 seconds')
            time.sleep(10)
        r = subprocess.run(ssh + ['cat /var/lib/culvert-appliance/build-info.json'], capture_output=True, text=True, timeout=60)
        require(r.returncode == 0, 'guest build-info unavailable')
        require(json.loads(r.stdout)['source']['git_commit'] == self.c['source_sha'], 'guest source identity mismatch')
        r = subprocess.run(ssh + ['sudo docker inspect -f "{{.Image}}" culvert'],
                           capture_output=True, text=True, timeout=60)
        require(r.returncode == 0 and r.stdout.strip() == self.c['image_id'], 'running image identity mismatch')
        # Actual VMware property transport must be readable inside this guest.
        r = subprocess.run(ssh + ["vmware-rpctool 'info-get guestinfo.ovfEnv'"], capture_output=True, text=True, timeout=60)
        require(r.returncode == 0, 'VMware guestinfo transport unavailable')
        props = {p.get('{http://schemas.dmtf.org/ovf/environment/1}key'): p.get('{http://schemas.dmtf.org/ovf/environment/1}value')
                 for p in ET.fromstring(r.stdout).iter('{http://schemas.dmtf.org/ovf/environment/1}Property')}
        require(props.get('instance-id') == self.state['name'], 'guestinfo instance identity mismatch')
        self.record('vmware-property-delivery', 'pass', 'guest read the imported instance-id through vmware-rpctool')
        ports = self.c.get('ports', [2222, 18080, 19090])
        require(len(set(ports)) == 3 and all(type(p) is int and 1024 <= p <= 65535 for p in ports), 'three distinct unprivileged local ports required')
        for port in ports:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', port))
        def start_tunnel(address):
            # The appliance intentionally disables SSH forwarding. A controller
            # loopback relay preserves that policy and exposes no LAN listener.
            tunnel = [sys.executable, str(HERE / 'esxi-port-relay.py'), '--target', address]
            for local, remote in zip(ports, (22, 8080, 9090)):
                tunnel += ['--map', f'{local}:{remote}']
            return subprocess.Popen(tunnel, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def forwarding_ready(timeout):
            command = self.ssh_command('127.0.0.1')
            probe = subprocess.run(command[:-1] + ['-p', str(ports[0]), command[-1], 'true'],
                                   capture_output=True, timeout=timeout)
            return probe.returncode == 0

        transport = TunnelSupervisor(self.guest_ip, start_tunnel, forwarding_ready, self.record)
        env = {k: v for k, v in os.environ.items() if not k.startswith(('LAB_', 'GOVC_'))}
        env.update(LAB_DIR=self.run.as_posix(), LAB_SSH_PORT=str(ports[0]), LAB_PROXY_PORT=str(ports[1]),
                   LAB_UI_PORT=str(ports[2]), LAB_EXPECT_IMAGE_ID=self.c['image_id'], ESXI_HOST_KEY_ALIAS=self.state['name'],
                   ESXI_ADAPTER=Path(__file__).resolve().as_posix(), ESXI_SCOPE=self.scope_path.as_posix(), ESXI_PYTHON=Path(sys.executable).as_posix())
        # Credentials required only for the alive read; no govc debug/session persistence.
        for k in ('GOVC_USERNAME', 'GOVC_PASSWORD', 'GOVC_TLS_CA_CERTS', 'GOVC_TLS_KNOWN_HOSTS',
                  'GOVC_CERTIFICATE', 'GOVC_PRIVATE_KEY'):
            if k in os.environ:
                env[k] = os.environ[k]
        self.state['phase'] = 'qualification-started'
        self.save()
        try:
            transport.ensure()
            with (self.sec / 'qualification.log').open('w', encoding='utf-8') as log:
                with subprocess.Popen([bash, (HERE / 'guest-checks.sh').as_posix(), 'qualify'], env=env,
                                      stdout=log, stderr=subprocess.STDOUT,
                                      start_new_session=os.name != 'nt') as guest_checks:
                    try:
                        deadline = time.monotonic() + 10800
                        while guest_checks.poll() is None:
                            require(time.monotonic() < deadline, 'guest suite exceeded 10800 seconds')
                            transport.ensure(budget=deadline - time.monotonic())
                            time.sleep(.25)
                        rc = guest_checks.returncode
                    except BaseException:
                        # Kill only this spawned check process and its descendants.
                        if os.name == 'nt':
                            subprocess.run(['taskkill', '/PID', str(guest_checks.pid), '/T', '/F'],
                                           capture_output=True, timeout=30)
                        else:
                            import signal
                            os.killpg(guest_checks.pid, signal.SIGKILL)
                        guest_checks.wait(timeout=30)
                        raise
            self.record('baseline-guest-checks', 'pass' if rc == 0 else 'fail',
                        'shared guest assertions completed; inspect each checks.jsonl verdict')
            require(rc == 0, 'baseline guest checks failed')
        finally:
            transport.close()
        self.state['phase'] = 'baseline-completed'
        self.save()

    def collect(self):
        """Export only structured results/provenance; raw diagnostics stay local."""
        rows = []
        for name in ('adapter.jsonl', 'checks.jsonl'):
            p = self.ev / name
            if p.exists():
                for line in p.read_text(encoding='utf-8').splitlines():
                    r = json.loads(line)
                    rows.append({k: r[k] for k in ('step', 'check', 'result')})
        recorded = {row['check'] for row in rows}
        for check in ('actual-restore', 'clamav-failure-posture', 'category-enforcement', 'interrupted-firstboot',
                      'dns-network-fault', 'two-import-identity', 'power-loss-boundary', 'F-DISK-1', 'alarm-delivery'):
            if check not in recorded:
                rows.append(dict(step='extended', check=check, result='not-run'))
        report = dict(schema=1, qualification='incomplete', results=rows,
                      known_failure='F-DISK-1 remains OPEN; recovery is not survival',
                      original_candidate_expected_sha256=ORIGINAL_SHA,
                      tested_artifact=None, vm_deleted=self.state.get('deleted', False))
        preflight = self.ev / 'preflight.json'
        if preflight.exists():
            report['tested_artifact'] = json.loads(preflight.read_text())
        out = self.run / 'share'
        out.mkdir(exist_ok=True)
        atomic_json(out / 'results.json', report)
        # Allowlist excludes console, cookies, import properties, environment,
        # backup payloads, raw API bodies, passwords and all private keys.
        bundle = self.run / 'esxi-evidence.tgz'
        with tarfile.open(bundle, 'w:gz') as tf:
            tf.add(out / 'results.json', arcname='results.json')
        with bundle.open('rb') as f:
            print('Evidence SHA256 ' + digest(f))
        print(bundle)

    def down(self):
        if not self.state.get('deleted'):
            vm = self.vm()  # refuses a same-name replacement or any scope drift
            if vm['runtime']['powerState'] != 'poweredOff':
                self.gov('vm.power', '-off', self.state['path'], json_output=False)
            self.vm()  # recheck identity immediately before deletion
            self.gov('vm.destroy', self.state['path'], timeout=300, json_output=False)
            require(not (self.gov('vm.info', self.state['path']).get('virtualMachines') or []), 'deletion not confirmed')
            self.state.update(deleted=True, phase='deleted')
            self.save()
        # A confirmed deletion may be followed by a failed local cleanup. Retry
        # local cleanup without repeating hypervisor operations on an absent VM.
        cleanup_private_tree(self.run, self.sec)
        self.record('cleanup', 'pass', 'owned VM deletion confirmed; private run files removed')


@contextlib.contextmanager
def locked(run):
    path = run / 'operation.lock'
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise Refused('operation lock exists; verify no command runs before removing it') from None
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        yield
    finally:
        path.unlink()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--scope', required=True, type=Path)
    p.add_argument('command', choices=('preflight', 'up', 'inspect', 'qualify', 'collect', 'down', 'alive'))
    args = p.parse_args()
    lab = Lab(args.scope)
    try:
        if args.command == 'alive':
            require(lab.vm()['runtime']['powerState'] == 'poweredOn', 'VM is not powered on')
        else:
            with locked(lab.run):
                getattr(lab, args.command)()
        return 0
    except (Refused, OSError, ValueError, KeyError, ET.ParseError, tarfile.TarError,
            subprocess.SubprocessError) as e:
        # Never print arbitrary library errors that may contain remote data.
        detail = str(e) if isinstance(e, Refused) else type(e).__name__ + '; inspect local configuration'
        lab.record(args.command, 'blocked', detail)
        return 3


if __name__ == '__main__':
    sys.exit(main())
