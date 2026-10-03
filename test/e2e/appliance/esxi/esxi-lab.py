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
import shutil
import socket
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
        env.update(GOVC_URL=self.c['endpoint'], GOVC_PERSIST_SESSION='false', GOVC_INSECURE='false')
        cmd = [self.govc, args[0]] + (['-json'] if json_output else []) + list(args[1:])
        try:
            r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=timeout,
                               encoding='utf-8', errors='replace')
        except subprocess.TimeoutExpired:
            raise Refused(f'govc {args[0]} timed out; reconcile owned state before retry') from None
        # Raw stderr can contain endpoint credentials or OVF properties: never export.
        require(r.returncode == 0, f'govc {args[0]} failed (exit {r.returncode}); no mutation retry')
        return json.loads(r.stdout) if json_output else r.stdout.strip()

    def vm(self):
        require(self.state and not self.state.get('deleted'), 'no active owned VM')
        require(self.state['endpoint'] == self.c['endpoint'], 'endpoint changed')
        vms = self.gov('vm.info', self.state['path'])['virtualMachines'] or []
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
        net = self.gov('ls', '-i', self.c['network'], json_output=False)
        require(re.fullmatch(r'(Network|DistributedVirtualPortgroup):[A-Za-z0-9-]+', net), 'one supported network required')
        kind, value = net.split(':')
        require(hs[0]['self'] in [x['key'] for x in dss[0]['host']], 'datastore not mounted on designated host')
        capacity = check_capacity(self.c, artifact, dss[0]['summary'], hs[0]['summary'])
        sha = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(['git', '-C', str(ROOT), 'status', '--porcelain'], capture_output=True, text=True, check=True).stdout.strip()
        sources = {}
        for source in (Path(__file__), HERE / 'guest-checks.sh', HERE.parent / 'lab/appliance-lab.sh'):
            with source.open('rb') as f:
                sources[source.relative_to(ROOT).as_posix()] = digest(f)
        data = dict(artifact=artifact, expected_source=self.c['source_sha'], expected_image=self.c['image_id'],
                    original_candidate=artifact['ova_sha256'] == ORIGINAL_SHA,
                    harness_sha=sha, harness_dirty=bool(dirty), harness_file_sha256=sources,
                    govc_version=self.gov('version', json_output=False),
                    hypervisor=hs[0]['summary']['config']['product'], capacity=capacity,
                    property_delivery='govc ImportVApp + InjectOvfEnv via VMware guestinfo',
                    host_ref=hs[0]['self'], ds_ref=dss[0]['self'], network_ref=dict(type=kind, value=value))
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
        (self.sec / 'admin-pass').write_text(secrets.token_hex(18), encoding='ascii')
        props = {'instance-id': self.state['name'], 'hostname': self.state['name'],
                 'public-keys': key.with_suffix('.pub').read_text().strip(), 'culvert.net.mode': 'dhcp'}
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

    def guest_ip(self):
        self.vm()
        ip = self.gov('vm.ip', '-wait=120s', '-a', '-v4', self.state['path'], timeout=150, json_output=False)
        require(ip and ',' not in ip and '\n' not in ip, 'guest IP missing or ambiguous')
        require(ipaddress.ip_address(ip) in ipaddress.ip_network(self.c['guest_cidr']), 'guest IP outside approved CIDR')
        return ip

    def qualify(self):
        require(self.state.get('phase') == 'powered-on', 'qualify is single-use on a fresh import')
        bash = self.c.get('bash', 'bash')
        # Verify host prerequisites before guest mutations.
        probe = subprocess.run([bash, '-c', 'for t in ssh curl openssl timeout; do command -v "$t" || exit 3; done'], capture_output=True, timeout=30)
        require(probe.returncode == 0, 'Bash host needs ssh, curl, openssl and timeout')
        ip = self.guest_ip()
        ssh = ['ssh', '-F', 'none', '-i', str(self.sec / 'id_ed25519'), '-o', 'IdentitiesOnly=yes',
               '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new',
               '-o', 'UserKnownHostsFile=' + str(self.sec / 'known_hosts'), '-o', 'ConnectTimeout=10',
               '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2', 'culvert@' + ip]
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
        tunnel = ssh[:-1] + ['-o', 'ExitOnForwardFailure=yes', '-N']
        for local, remote in zip(ports, (22, 8080, 9090)):
            tunnel += ['-L', f'127.0.0.1:{local}:127.0.0.1:{remote}']
        tunnel += [ssh[-1]]
        env = {k: v for k, v in os.environ.items() if not k.startswith(('LAB_', 'GOVC_'))}
        env.update(LAB_DIR=self.run.as_posix(), LAB_SSH_PORT=str(ports[0]), LAB_PROXY_PORT=str(ports[1]),
                   LAB_UI_PORT=str(ports[2]), LAB_EXPECT_IMAGE_ID=self.c['image_id'], ESXI_GUEST_IP=ip,
                   ESXI_ADAPTER=Path(__file__).resolve().as_posix(), ESXI_SCOPE=self.scope_path.as_posix(), ESXI_PYTHON=Path(sys.executable).as_posix())
        # Credentials required only for the alive read; no govc debug/session persistence.
        for k in ('GOVC_USERNAME', 'GOVC_PASSWORD', 'GOVC_TLS_CA_CERTS', 'GOVC_TLS_KNOWN_HOSTS',
                  'GOVC_CERTIFICATE', 'GOVC_PRIVATE_KEY'):
            if k in os.environ:
                env[k] = os.environ[k]
        self.state['phase'] = 'qualification-started'
        self.save()
        with subprocess.Popen(tunnel, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
            try:
                time.sleep(2)
                require(proc.poll() is None, 'SSH tunnel failed')
                with (self.sec / 'qualification.log').open('w', encoding='utf-8') as log:
                    with subprocess.Popen([bash, (HERE / 'guest-checks.sh').as_posix(), 'qualify'], env=env,
                                          stdout=log, stderr=subprocess.STDOUT,
                                          start_new_session=os.name != 'nt') as guest_checks:
                        try:
                            rc = guest_checks.wait(timeout=10800)
                        except subprocess.TimeoutExpired:
                            # Kill only this spawned check process and its descendants.
                            if os.name == 'nt':
                                subprocess.run(['taskkill', '/PID', str(guest_checks.pid), '/T', '/F'],
                                               capture_output=True, timeout=30)
                            else:
                                import signal
                                os.killpg(guest_checks.pid, signal.SIGKILL)
                            guest_checks.wait(timeout=30)
                            raise Refused('guest suite exceeded 10800 seconds; collect and down') from None
                self.record('baseline-guest-checks', 'pass' if rc == 0 else 'fail',
                            'shared guest assertions completed; inspect each checks.jsonl verdict')
                require(rc == 0, 'baseline guest checks failed')
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
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
        for check in ('actual-restore', 'clamav-failure-posture', 'category-enforcement', 'interrupted-firstboot',
                      'dns-network-fault', 'two-import-identity', 'power-loss-boundary', 'F-DISK-1', 'alarm-delivery'):
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
        if self.state.get('deleted'):
            return
        vm = self.vm()  # refuses a same-name replacement or any scope drift
        if vm['runtime']['powerState'] != 'poweredOff':
            self.gov('vm.power', '-off', self.state['path'], json_output=False)
        self.vm()  # recheck identity immediately before deletion
        self.gov('vm.destroy', self.state['path'], timeout=300, json_output=False)
        require(not (self.gov('vm.info', self.state['path']).get('virtualMachines') or []), 'deletion not confirmed')
        self.state.update(deleted=True, phase='deleted')
        self.save()
        # Delete only regular files created in this run's secrets directory.
        for p in self.sec.iterdir():
            if p.is_file() and not p.is_symlink():
                p.unlink()
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
    p.add_argument('command', choices=('preflight', 'up', 'qualify', 'collect', 'down', 'alive'))
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
