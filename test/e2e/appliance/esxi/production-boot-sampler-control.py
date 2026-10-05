#!/usr/bin/env python3
"""Generate LAB-only install/remove scripts; never contacts or modifies a VM.

Send the generated script through the existing authenticated console transport.
Installation enables collection for subsequent measured boots without starting
it now. Removal stops/disables the matching recorder and preserves /run data.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import uuid

HERE = Path(__file__).resolve().parent
UNIT = '''[Unit]
Description=Disposable Culvert LAB early boot sampler
DefaultDependencies=no
After=local-fs.target
Before=sysinit.target shutdown.target
Conflicts=shutdown.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -B /usr/local/libexec/culvert-lab-boot-sampler.py
User=root
Group=root
UMask=0077
RuntimeDirectory=culvert-lab-boot-sampler
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
RuntimeMaxSec=915s
TimeoutStopSec=3s
Restart=no
Nice=10
MemoryMax=32M
NoNewPrivileges=yes
StandardInput=null
StandardOutput=null
StandardError=null

[Install]
WantedBy=sysinit.target
'''
IO_ACCOUNTING = '[Manager]\nDefaultIOAccounting=yes\n'

GUEST = '''
import base64, hashlib, ipaddress, json, os, pathlib, re, stat, subprocess, uuid
def need(ok):
    if not ok:
        raise ValueError('lab sampler identity/precondition failed')
def vmware_guest_identity(owner, guest, vendor):
    # SMBIOS 2.6+ exposes the first 4/2/2 GUID bytes little-endian. VMware's
    # API UUID remains the owner identity; accept only that deterministic alias.
    need(vendor == 'VMware, Inc.')
    parsed_owner, parsed_guest = uuid.UUID(owner), uuid.UUID(guest)
    need(str(parsed_owner) == owner and str(parsed_guest) == guest)
    if guest == owner:
        return 'exact'
    need(guest == str(uuid.UUID(bytes_le=parsed_owner.bytes)))
    return 'smbios-byte-swapped'
need(os.geteuid() == 0)
guest_uuid = pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
guest_vendor = pathlib.Path('/sys/class/dmi/id/sys_vendor').read_text().strip()
uuid_binding = vmware_guest_identity(configuration['owner_uuid'], guest_uuid, guest_vendor)
build = json.loads(pathlib.Path('/var/lib/culvert-appliance/build-info.json').read_text())
need(build['source']['git_commit'] == configuration['source_sha'] and build['source']['git_dirty'] is False)
script = pathlib.Path('/usr/local/libexec/culvert-lab-boot-sampler.py')
unit = pathlib.Path('/etc/systemd/system/culvert-lab-boot-sampler.service')
accounting = pathlib.Path('/etc/systemd/system.conf.d/90-culvert-lab-io.conf')
clamav_config = pathlib.Path('/usr/local/libexec/culvert-lab-boot-sampler.clamav.json')
receipt = pathlib.Path('/usr/local/libexec/culvert-lab-boot-sampler.receipt.json')
enabled = pathlib.Path('/etc/systemd/system/sysinit.target.wants/culvert-lab-boot-sampler.service')
runtime = pathlib.Path('/run/culvert-lab-boot-sampler')
script_bytes, unit_bytes = base64.b64decode(configuration['sampler_b64']), base64.b64decode(configuration['unit_b64'])
accounting_bytes = base64.b64decode(configuration['accounting_b64'])
need(hashlib.sha256(script_bytes).hexdigest() == configuration['sampler_sha256'])
need(hashlib.sha256(unit_bytes).hexdigest() == configuration['unit_sha256'])
need(hashlib.sha256(accounting_bytes).hexdigest() == configuration['accounting_sha256'])
def run(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=15)
    need(result.returncode == 0)
def docker_json(args):
    result = subprocess.run(['docker'] + args, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    need(result.returncode == 0 and len(result.stdout) <= 32768 and len(result.stderr) <= 32768)
    return json.loads(result.stdout)
def write_new(path, content, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
record = {key: configuration[key] for key in ('owner_uuid', 'source_sha', 'sampler_sha256', 'unit_sha256', 'accounting_sha256', 'generator_sha256')}
record.update(guest_product_uuid=guest_uuid, guest_sys_vendor=guest_vendor, uuid_binding=uuid_binding)
if configuration['action'] == 'install':
    need(not any(os.path.lexists(path) for path in (script, unit, accounting, clamav_config, receipt, enabled, runtime)))
    container = docker_json(['inspect', '--format', '{"id":{{json .Id}},"networks":{{json .NetworkSettings.Networks}}}', 'culvert-clamav'])
    need(isinstance(container, dict) and re.fullmatch(r'[a-f0-9]{64}', container.get('id', '')))
    networks = container.get('networks')
    need(isinstance(networks, dict) and len(networks) == 1)
    network = next(iter(networks.values()))
    need(isinstance(network, dict) and re.fullmatch(r'[a-f0-9]{64}', network.get('NetworkID', '')))
    need(docker_json(['network', 'inspect', '--format', '{{json .Driver}}', network['NetworkID']]) == 'bridge')
    address = ipaddress.IPv4Address(network.get('IPAddress', ''))
    need(address.is_private and not any((address.is_loopback, address.is_link_local,
         address.is_unspecified, address.is_multicast, address.is_reserved)))
    endpoint = {'schema': 1, 'address': str(address), 'port': 3310, 'container_id': container['id']}
    endpoint_bytes = (json.dumps(endpoint, sort_keys=True) + '\\n').encode()
    record['clamav_config_sha256'] = hashlib.sha256(endpoint_bytes).hexdigest()
    record['clamav_endpoint'] = endpoint  # PRIVATE receipt; never product/public evidence.
    script.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    accounting.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    for parent in (script.parent, unit.parent, accounting.parent):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not (info.st_mode & 0o022))
    write_new(script, script_bytes, 0o700)
    write_new(unit, unit_bytes, 0o644)
    write_new(accounting, accounting_bytes, 0o644)
    write_new(clamav_config, endpoint_bytes, 0o600)
    # No start or restart: both A/B boots use these same installed bytes.
    # The manager reads DefaultIOAccounting at the next boot; no daemon-reexec.
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--no-reload', unit.name])
    record['action'] = 'installed-for-subsequent-boots'
    write_new(receipt, (json.dumps(record, sort_keys=True) + '\\n').encode(), 0o600)
else:
    for path, digest in ((script, configuration['sampler_sha256']), (unit, configuration['unit_sha256']),
                         (accounting, configuration['accounting_sha256'])):
        info = path.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0)
        need(hashlib.sha256(path.read_bytes()).hexdigest() == digest)
    info = receipt.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
    prior = json.loads(receipt.read_text())
    need(all(prior[key] == value for key, value in record.items()))
    info = clamav_config.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600)
    need(hashlib.sha256(clamav_config.read_bytes()).hexdigest() == prior['clamav_config_sha256'])
    need(enabled.is_symlink() and enabled.resolve() == unit)
    run(['systemctl', 'disable', '--now', unit.name])
    script.unlink()
    unit.unlink()
    accounting.unlink()
    clamav_config.unlink()
    receipt.unlink()
    run(['systemctl', 'daemon-reload'])
    record['action'] = 'removed-runtime-evidence-preserved'
print(json.dumps(record, sort_keys=True))
'''


def generate(action, owner_uuid, source_sha, sampler, generator_sha):
    if (action not in ('install', 'remove') or str(uuid.UUID(owner_uuid)) != owner_uuid
            or not re.fullmatch(r'[a-f0-9]{40}', source_sha)
            or not re.fullmatch(r'[a-f0-9]{64}', generator_sha) or len(sampler) > 64 * 1024):
        raise ValueError('invalid explicit lab sampler identity')
    unit, accounting = UNIT.encode('ascii'), IO_ACCOUNTING.encode('ascii')
    config = {'action': action, 'owner_uuid': owner_uuid, 'source_sha': source_sha,
              'sampler_sha256': hashlib.sha256(sampler).hexdigest(),
              'unit_sha256': hashlib.sha256(unit).hexdigest(), 'generator_sha256': generator_sha,
              'accounting_sha256': hashlib.sha256(accounting).hexdigest(),
              'sampler_b64': base64.b64encode(sampler).decode('ascii'),
              'accounting_b64': base64.b64encode(accounting).decode('ascii'),
              'unit_b64': base64.b64encode(unit).decode('ascii')}
    return ("#!/usr/bin/env bash\nset -euo pipefail\nset +x\numask 077\npython3 - <<'CULVERT_LAB_BOOT_SAMPLER'\n"
            + 'configuration = ' + repr(config) + '\n' + GUEST + '\nCULVERT_LAB_BOOT_SAMPLER\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('install', 'remove'))
    parser.add_argument('--owner-uuid', required=True)
    parser.add_argument('--source-sha', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    helper = (HERE / 'production-boot-sampler.py').read_bytes()
    body = generate(args.action, args.owner_uuid, args.source_sha, helper,
                    hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with args.output.open('x', encoding='utf-8', newline='\n') as output:
        output.write(body)
    print('Generated lab-only script SHA256 ' + hashlib.sha256(body.encode()).hexdigest())


if __name__ == '__main__':
    main()
