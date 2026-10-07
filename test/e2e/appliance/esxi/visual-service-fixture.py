#!/usr/bin/env python3
"""Generate an authenticated-console-only, one-boot LAB visual service fixture.

Generate install and removal with the same helper bytes and campaign. A new
generator must not remove a prior-generator fixture; retain its original helper.
"""
import argparse
import ast
import base64
import hashlib
import json
from pathlib import Path
import re
import uuid

HERE = Path(__file__).resolve().parent
SOURCE = 'cd8e44505bd329e5de675592ad4c23f92a534d55'
ROOT = '/var/lib/culvert-lab-visual-fixture'
NAMES = ('culvert-lab-visual-delay.service', 'culvert-lab-visual-failure.service')


def namespace(campaign=None):
    if campaign is None: return ROOT, NAMES
    if not isinstance(campaign, str) or len(campaign) > 32 or not re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', campaign):
        raise ValueError('bounded lowercase fixture campaign required')
    return ROOT + '-' + campaign, tuple(name.removesuffix('.service') + '-' + campaign + '.service' for name in NAMES)


def units(campaign=None):
    root, names = namespace(campaign)
    result = {}
    for name, action, marker in ((names[0], '/usr/bin/sleep 45', 'delay-fired'),
                                 (names[1], '/usr/bin/false', 'failure-fired')):
        result[name] = ('[Unit]\nDescription=Disposable LAB visual boot fixture\n'
            'Before=multi-user.target plymouth-quit.service plymouth-quit-wait.service\nConditionPathExists=!' + root + '/' + marker + '\n\n'
            '[Service]\nType=oneshot\nUser=root\nGroup=root\nUMask=0077\n'
            'ExecStartPre=/usr/bin/touch ' + root + '/' + marker + '\nExecStart=' + action + '\n'
            'TimeoutStartSec=50s\nTimeoutStopSec=3s\nRestart=no\nNoNewPrivileges=yes\n'
            'StandardInput=null\nStandardOutput=journal\nStandardError=journal\n\n'
            '[Install]\nWantedBy=multi-user.target\n')
    return result


def lock_code():
    path = HERE / 'qualify-clamav-outage.py'
    raw = path.read_bytes(); source = raw.decode('utf-8')
    names = ('CheckFailure', 'need', 'trusted_directory', 'trusted_lock', 'same_inode',
             'HeldLock', 'service_identity', 'maintenance_idle')
    nodes = {node.name: ast.get_source_segment(source, node) for node in ast.parse(source).body
             if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names}
    if set(nodes) != set(names): raise ValueError('reviewed lock helpers missing')
    return '\n\n'.join(nodes[name] for name in names), hashlib.sha256(raw).hexdigest()


GUEST = r'''
def regular(path, data=None):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
         and not info.st_mode & 0o022, 'fixture file ownership differs')
    need(info.st_size <= 65536, 'fixture file too large')
    if data is not None: need(path.read_bytes() == data, 'fixture file changed')

def trusted(path):
    for item in (path, *path.parents):
        info = item.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
             'fixture directory ownership differs')

def save(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())

def control(*args):
    result = subprocess.run(['systemctl', *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    need(result.returncode == 0 and len(result.stdout) < 16384, 'systemd fixture operation failed')
    return result.stdout.decode().strip()

def identity():
    need(os.geteuid() == 0, 'authenticated root required')
    owner = uuid.UUID(config['owner_uuid'])
    guest = Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower()
    need(Path('/sys/class/dmi/id/sys_vendor').read_text().strip() == 'VMware, Inc.'
         and guest in (str(owner), str(uuid.UUID(bytes_le=owner.bytes))), 'owned VMware identity differs')
    build = json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_bytes())
    need(build['source']['git_commit'] == config['source'] and build['source']['git_dirty'] is False,
         'candidate source differs')
    need(Path('/var/lib/culvert-appliance/state/complete.done').is_file(), 'first boot incomplete')

def fixture():
    campaign = config['campaign']
    need(campaign is None or (isinstance(campaign, str) and len(campaign) <= 32
         and re.fullmatch(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*', campaign)), 'fixture campaign refused')
    suffix = '-' + campaign if campaign is not None else ''
    root = Path('/var/lib/culvert-lab-visual-fixture' + suffix)
    need(config['fixture_root'] == root.as_posix() and set(config['units']) == {
         'culvert-lab-visual-delay' + suffix + '.service',
         'culvert-lab-visual-failure' + suffix + '.service'}, 'fixture namespace differs')
    identity()
    locks = []
    try:
        ids = service_identity()
        for path in ('/run/culvert-os-update.lock', '/var/lib/culvert-maint/host-maintenance.lock'):
            locks.append(HeldLock(path, ids))
        maintenance_idle()
        system = Path('/etc/systemd/system'); wants = system / 'multi-user.target.wants'
        trusted(system); trusted(wants); trusted(root.parent)
        paths = [(system / name, wants / name, raw.encode()) for name, raw in config['units'].items()]
        expected = {k: config[k] for k in ('source', 'owner_uuid', 'campaign', 'fixture_root', 'units', 'lock_source_sha256', 'generator_sha256')}
        if config['action'] == 'install':
            need(not os.path.lexists(root), 'fixture receipt already exists')
            for unit, link, raw in paths:
                need(not os.path.lexists(unit) and not os.path.lexists(link), 'preexisting fixture unit refused')
            root.mkdir(mode=0o700); trusted(root)
            save(root / 'install-started.json', json.dumps(expected, sort_keys=True).encode())
            for lock in locks: lock.check()
            for unit, link, raw in paths:
                save(unit, raw); os.symlink(str(unit), link)
            control('daemon-reload')
            for lock in locks: lock.check()
            save(root / 'installed.json', json.dumps(expected, sort_keys=True).encode())
        else:
            trusted(root)
            receipt = root / 'installed.json'; regular(receipt)
            need(json.loads(receipt.read_bytes()) == expected, 'fixture install receipt differs')
            need(not os.path.lexists(root / 'remove-started.json') and not os.path.lexists(root / 'removed.json'),
                 'cleanup already attempted')
            for unit, link, raw in paths:
                regular(unit, raw)
                need(link.is_symlink() and os.readlink(link) == str(unit), 'fixture enable link changed')
                need(control('show', unit.name, '-p', 'ActiveState', '--value') in ('inactive', 'failed'),
                     'fixture still active')
            maintenance_idle()
            save(root / 'remove-started.json', json.dumps(expected, sort_keys=True).encode())
            for lock in locks: lock.check()
            control('reset-failed', *config['units'])
            for unit, link, raw in paths:
                regular(unit, raw)
                need(link.is_symlink() and os.readlink(link) == str(unit), 'fixture link replaced')
                link.unlink(); unit.unlink()
            control('daemon-reload')
            for lock in locks: lock.check()
            save(root / 'removed.json', json.dumps(expected, sort_keys=True).encode())
        print(json.dumps({'fixture': config['action'], 'source': config['source'],
            'owner_uuid': config['owner_uuid'], 'campaign': campaign, 'unit_sha256': {
            name: hashlib.sha256(raw.encode()).hexdigest() for name, raw in config['units'].items()}}))
    finally:
        for lock in reversed(locks): lock.close()
fixture()
'''


def generate(action, owner, campaign=None):
    if action not in ('install', 'remove') or str(uuid.UUID(owner)) != owner:
        raise ValueError('explicit action and canonical owned UUID required')
    root, _ = namespace(campaign)
    locks, digest = lock_code()
    config = {'action': action, 'source': SOURCE, 'owner_uuid': owner, 'units': units(campaign),
              'campaign': campaign, 'fixture_root': root,
              'lock_source_sha256': digest, 'generator_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    code = ('import hashlib,json,os,re,stat,subprocess,uuid\nfrom pathlib import Path\n'
            + 'config = ' + repr(config) + '\n' + locks + '\n' + GUEST)
    compile(code, '<visual-service-fixture>', 'exec')
    return "#!/bin/sh\nset -eu\nexec python3 -B - <<'CULVERT_VISUAL_FIXTURE'\n" + code + '\nCULVERT_VISUAL_FIXTURE\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--action', choices=('install', 'remove'), required=True)
    parser.add_argument('--owner-uuid', required=True)
    parser.add_argument('--campaign', help='New explicit fixture namespace; omission preserves original paths')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    with args.output.open('x', encoding='utf-8', newline='\n') as out:
        out.write(generate(args.action, args.owner_uuid, args.campaign))


if __name__ == '__main__': main()
