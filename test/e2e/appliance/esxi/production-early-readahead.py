#!/usr/bin/env python3
"""LAB-only, authenticated-console initrd A/B controller. Never an OVA builder.

prepare -> export -> applyA -> reboot/verify -> applyB -> reboot/verify (three
boots) -> applyA -> reboot/verify -> restore -> reboot/verify. Reboots and all
production recovery criteria remain owned by the unchanged external runner.
Every mutation has an exclusive write-ahead record; incomplete work is not
automatically retried. Private initrd export must complete before any apply.
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
import os
from pathlib import Path
import re
import secrets
import sys
import threading
import time
from types import SimpleNamespace
import uuid

HERE = Path(__file__).resolve().parent
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
IMAGE = 'sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47'
KERNEL = '6.8.0-146-generic'
ORIGINAL_BYTES = 37347640
ORIGINAL_SHA = 'd22af6fa8e3b0c609ae3227b7e036b1262b3054b4f395ced2a4d3beedf32bf54'
MAX_INITRD = 128 * 1024**2
MAIN_OFFSET = 13732352
PREFIX_SHA = 'a0882502b00f90f80306735a373a1f96fbba53889ce2c6f0ac8a36a7a720b709'
MAX_MAIN = 512 * 1024**2
HOOK_NAME = 'culvert-lab-early-read-ahead'


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def file_hash(path):
    value = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(65536), b''):
            value.update(block)
    return value.hexdigest()


def private_facts(value):
    early = value['early']
    expected = {'kernel': KERNEL, 'bytes': ORIGINAL_BYTES, 'mode': '0o644', 'uid': 0, 'sha256': ORIGINAL_SHA}
    need(early['initrd'] == expected, 'unexpected original initrd identity')
    listing = early['initrd_listing_status']
    need(listing['exit_code'] == 0 and listing['result'] == 'ok' and listing['truncated'] is False
         and listing['timed_out'] is False and early['initrd_rule_entries'] == [], 'incomplete original initrd listing')
    for key in ('grub_menu', 'mounts', 'local_script'):
        row = early[key]
        need(row['exit_code'] == 0 and row['truncated'] is False and row['timed_out'] is False, 'incomplete boot facts')
    root_ids = set(re.findall(r'root=UUID=([a-f0-9-]{36})', early['grub_menu']['output']))
    need(len(root_ids) == 1, 'ambiguous root UUID')
    root_uuid = root_ids.pop()
    need(str(uuid.UUID(root_uuid)) == root_uuid, 'noncanonical root UUID')
    root = json.loads(early['mounts']['output'])['filesystems'][0]
    need((root['target'], root['source'], root['fstype']) == ('/', '/dev/sda1', 'ext4'), 'unexpected root filesystem')
    script = early['local_script']['output'].split('local_mount_root()', 1)[1].split('local_mount_fs()', 1)[0]
    need(script.index('ROOT="${DEV}"') < script.index('\n\tlocal_premount') < script.index('\n\tcheckfs ')
         < script.index('\n\tmount '), 'local-premount ordering not proven')
    return root_uuid


def boot_hook(owner, campaign, root_uuid, value):
    need(all(str(uuid.UUID(v)) == v for v in (owner, campaign, root_uuid)) and type(value) is int
         and value in (128, 1024), 'invalid boot fixture identity')
    alias = str(uuid.UUID(bytes_le=uuid.UUID(owner).bytes))
    return '''#!/bin/sh
PREREQ=""
case "${1:-}" in prereqs) echo "$PREREQ"; exit 0;; esac
. /scripts/functions
emit() {
    read -r up rest < /proc/uptime
    read -r boot < /proc/sys/kernel/random/boot_id
    printf '<6>CULVERT_LAB_EARLY_RA campaign=%s boot=%s profile=%s result=%s old=%s effective=%s uptime=%s reason=%s\\n' \\
      CAMPAIGN "$boot" VALUE "$1" "${old:-unknown}" "${effective:-unknown}" "$up" "$2" > /dev/kmsg
}
refuse() { emit refused "$1" || :; exit 0; }
vendor=$(cat /sys/class/dmi/id/sys_vendor) || refuse vendor
[ "$vendor" = 'VMware, Inc.' ] || refuse vendor
guest=$(tr 'A-F' 'a-f' < /sys/class/dmi/id/product_uuid) || refuse uuid
case "$guest" in OWNER|ALIAS) :;; *) refuse uuid;; esac
read -r kernel < /proc/sys/kernel/osrelease
[ "$kernel" = KERNEL ] || refuse kernel
[ "${ROOT:-}" = /dev/sda1 ] || refuse root
[ "$(readlink -f /dev/disk/by-uuid/ROOT_UUID)" = /dev/sda1 ] || refuse root_uuid
[ "$(get_fstype /dev/sda1)" = ext4 ] || refuse filesystem
read -r sectors < /sys/block/sda/size
[ "$sectors" = 83886080 ] || refuse size
for disk in /sys/block/*; do
    case "${disk##*/}" in sda|loop*|sr*) :;; *) refuse other_disk;; esac
done
read -r scheduler < /sys/block/sda/queue/scheduler
case "$scheduler" in *'[mq-deadline]'*) :;; *) refuse scheduler;; esac
read -r old < /sys/block/sda/queue/read_ahead_kb
[ "$old" = 128 ] || refuse default_readahead
printf '%s\\n' VALUE > /sys/block/sda/queue/read_ahead_kb || refuse write
read -r effective < /sys/block/sda/queue/read_ahead_kb
[ "$effective" = VALUE ] || refuse readback
emit applied verified || :
exit 0
'''.replace('CAMPAIGN', campaign).replace('OWNER', owner).replace('ALIAS', alias).replace('ROOT_UUID', root_uuid).replace('KERNEL', KERNEL).replace('VALUE', str(value)).encode('ascii')


# These functions also run offline in the tests; no guest activity on import.
COMMON = r'''
def newc_records(path, limit=512 * 1024**2):
    size = path.stat().st_size
    need(0 < size <= limit, 'newc size bound')
    rows, names, offset = [], set(), 0
    with path.open('rb') as source:
        while offset + 110 <= size:
            need(len(rows) < 100000, 'newc entry bound')
            source.seek(offset); header = source.read(110)
            need(header[:6] == b'070701' and re.fullmatch(b'[0-9a-fA-F]{104}', header[6:]), 'unsupported newc header')
            fields = [int(header[i:i+8], 16) for i in range(6, 110, 8)]
            length, namesize = fields[6], fields[11]
            need(1 < namesize <= 4096 and fields[12] == 0, 'newc name/checksum')
            name = source.read(namesize)
            need(len(name) == namesize and name[-1:] == b'\0' and b'\0' not in name[:-1], 'newc filename terminator')
            name = name[:-1]
            normalized = name[2:] if name.startswith(b'./') else name
            need(normalized == b'.' or (not normalized.startswith(b'/') and all(p not in (b'', b'.', b'..')
                 for p in normalized.split(b'/'))), 'unsafe newc path')
            need(normalized not in names, 'duplicate newc path'); names.add(normalized)
            data = (offset + 110 + namesize + 3) & ~3
            end = (data + length + 3) & ~3
            need(end <= size, 'truncated newc record')
            row = dict(start=offset, end=end, data=data, name=name, normalized=normalized, header=header, fields=fields)
            rows.append(row)
            if normalized == b'TRAILER!!!':
                need(length == 0 and size - end <= 4096, 'newc trailer shape')
                source.seek(end); need(not source.read().strip(b'\0'), 'data after newc trailer')
                return rows
            offset = end
    need(False, 'newc trailer missing')

def copy_span(source, target, start, length):
    source.seek(start)
    while length:
        block = source.read(min(65536, length))
        need(block, 'incomplete archive span')
        target.write(block); length -= len(block)

def rewrite_newc(source_path, target_path, hook, expected_order):
    rows = newc_records(source_path)
    index = {r['normalized']: r for r in rows}
    order_name = b'scripts/local-premount/ORDER'
    hook_name = b'scripts/local-premount/culvert-lab-early-read-ahead'
    need(order_name in index and hook_name not in index, 'original ORDER or absent fixture required')
    for name in (b'scripts', b'scripts/local-premount'):
        need(name in index and stat.S_ISDIR(index[name]['fields'][1]), 'premount parent must be a directory')
    order = index[order_name]
    need(stat.S_ISREG(order['fields'][1]) and order['fields'][4] == 1 and order['fields'][2:4] == [0, 0],
         'ORDER must be an unlinked root-owned regular file')
    need(0 < len(hook) <= 16384 and b'\r' not in hook and 0 < len(expected_order) <= 65536,
         'fixture/ORDER bounds')
    invocation = (b'/scripts/local-premount/culvert-lab-early-read-ahead "$@"\n'
                  b'[ -e /conf/param.conf ] && . /conf/param.conf\n')
    need(expected_order.endswith(b'\n') and hook_name not in expected_order, 'original ORDER termination/fixture')
    order_bytes = expected_order + invocation
    ino = max(r['fields'][0] for r in rows) + 1
    need(ino <= 0xffffffff, 'newc inode overflow')
    name = (b'./' if order['name'].startswith(b'./') else b'') + hook_name + b'\0'
    fields = [ino, stat.S_IFREG | 0o755, 0, 0, 1, order['fields'][5], len(hook),
              order['fields'][7], order['fields'][8], 0, 0, len(name), 0]
    hook_header = b'070701' + b''.join(('%08x' % value).encode('ascii') for value in fields)
    with source_path.open('rb') as incoming, target_path.open('xb') as output:
        incoming.seek(order['data'])
        need(incoming.read(order['fields'][6]) == expected_order, 'expanded/archive ORDER differs')
        for row in rows:
            if row is order:
                output.write(row['header'][:54] + ('%08x' % len(order_bytes)).encode('ascii') + row['header'][62:])
                copy_span(incoming, output, row['start'] + 110, row['data'] - row['start'] - 110)
                output.write(order_bytes); output.write(b'\0' * (-len(order_bytes) % 4))
            else:
                if row['normalized'] == b'TRAILER!!!':
                    output.write(hook_header + name); output.write(b'\0' * (-(110 + len(name)) % 4))
                    output.write(hook); output.write(b'\0' * (-len(hook) % 4))
                copy_span(incoming, output, row['start'], row['end'] - row['start'])
        copy_span(incoming, output, rows[-1]['end'], source_path.stat().st_size - rows[-1]['end'])
        # Keep the existing trailer/padding and complete the conventional cpio
        # 512-byte block with zeros; this changes no archive member.
        output.write(b'\0' * (-output.tell() % 512))
        output.flush(); os.fsync(output.fileno())
    # Independently parse generated bytes before handing them to compression.
    changed = newc_records(target_path)
    need([r['normalized'] for r in changed] == [r['normalized'] for r in rows[:-1]]
         + [hook_name, b'TRAILER!!!'], 'generated archive structure differs')
    return order_bytes

def campaign_state(parent, campaign):
    need(isinstance(campaign, str) and str(uuid.UUID(campaign)) == campaign, 'canonical campaign required')
    return parent / campaign

def target_profile(action, active, exported):
    need(exported is True, 'offguest export required before apply or restore')
    target = {'applyA': 'A', 'applyB': 'B', 'restore': 'original'}[action]
    need(active in ('original', 'A', 'B') and target != active, 'active profile already selected or invalid')
    need(target != 'B' or active == 'A', 'B requires preceding A')
    # Restore is available after either successful fixture boot regardless of
    # measured service recovery. No PASS marker is a prerequisite for rollback.
    return target
def manifest(path):
    result, total = {}, 0
    for entry in sorted(path.rglob('*')):
        info = entry.lstat()
        name = entry.relative_to(path).as_posix()
        need(len(result) < 100000, 'expanded manifest entry limit')
        row = {'mode': stat.S_IMODE(info.st_mode), 'uid': info.st_uid, 'gid': info.st_gid}
        if stat.S_ISDIR(info.st_mode):
            row['kind'] = 'directory'
        elif stat.S_ISLNK(info.st_mode):
            row.update(kind='symlink', target=os.readlink(entry))
        elif stat.S_ISREG(info.st_mode):
            total += info.st_size
            need(total <= 768 * 1024**2, 'expanded manifest byte limit')
            row.update(kind='file', size=info.st_size, sha256=file_hash(entry))
        else:
            need(False, 'unexpected expanded special file')
        result[name] = row
    return result
def compare_manifests(original, a, b, hook_a, hook_b, orders):
    candidates = [name for name in a if name.endswith('/scripts/local-premount/culvert-lab-early-read-ahead')]
    need(len(candidates) == 1, 'exactly one early boot fixture required')
    hook = candidates[0]
    order = hook.rsplit('/', 1)[0] + '/ORDER'
    need(order in original and order in a and order in b, 'original premount ORDER missing')
    invocation = (b'/scripts/local-premount/culvert-lab-early-read-ahead "$@"\n'
                  b'[ -e /conf/param.conf ] && . /conf/param.conf\n')
    need(orders['A'] == orders['B'] and orders['A'].count(invocation) == 1
         and orders['A'].replace(invocation, b'', 1) == orders['original'], 'unexpected premount ORDER rewrite')
    need(hook not in original and set(a) == set(b) and set(a) - set(original) == {hook}
         and not set(original) - set(a), 'unexpected initrd additions/removals')
    for name in original:
        if name == order:
            need(a[name] == b[name] and all(original[name][key] == a[name][key]
                 for key in ('kind', 'mode', 'uid', 'gid')), 'premount ORDER metadata differs')
            for tree, content in ((original, orders['original']), (a, orders['A']), (b, orders['B'])):
                need(tree[name]['kind'] == 'file' and tree[name]['size'] == len(content)
                     and tree[name]['sha256'] == hashlib.sha256(content).hexdigest(), 'ORDER manifest/content mismatch')
        else:
            need(original[name] == a[name] == b[name], 'unapproved initrd manifest difference: ' + name)
    for tree, content in ((a, hook_a), (b, hook_b)):
        need(tree[hook] == {'kind': 'file', 'mode': 0o755, 'uid': 0, 'gid': 0,
                           'size': len(content), 'sha256': hashlib.sha256(content).hexdigest()}, 'fixture content or mode differs')
    need(not any(name.endswith('/65-culvert-lab-read-ahead.rules') for name in a), 'rootfs rule must not precede early hook')
    return hook
def verify_boot_marker(text, campaign, value, boot):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*(?:<\d+>)?\[\s*(\d+(?:\.\d+)?)\]\s*(.*)$', line)
        if match:
            rows.append((float(match[1]), match[2]))
    markers = [(when, body) for when, body in rows if 'CULVERT_LAB_EARLY_RA ' in body]
    mounts = [when for when, body in rows if re.search(r'EXT4-fs \(sda1\): mounted filesystem', body)]
    need(len(markers) == 1 and mounts, 'unambiguous early marker and initial root mount required')
    when, message = markers[0]
    fields = dict(re.findall(r'([a-z_]+)=([^\s]+)', message))
    need(fields.get('campaign') == campaign and fields.get('boot') == boot
         and fields.get('profile') == str(value) and fields.get('result') == 'applied'
         and fields.get('old') == '128' and fields.get('effective') == str(value)
         and fields.get('reason') == 'verified' and when < min(mounts), 'early application not verified before root mount')
    return {'marker_monotonic_seconds': when, 'first_root_mount_monotonic_seconds': min(mounts),
            'boot_id': boot, 'profile': value}
'''


GUEST = r'''
import base64, contextlib, hashlib, io, json, os, pathlib, re, shutil, stat, subprocess, time, uuid
def need(ok, reason):
    if not ok:
        raise ValueError('early LAB refused: ' + reason)
def file_hash(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            result.update(chunk)
    return result.hexdigest()
def regular(path, mode, limit=128 * 1024**2):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode
         and info.st_nlink == 1 and 0 < info.st_size <= limit, 'unsafe file ' + str(path))
    return info
def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(fd)
    finally: os.close(fd)
def new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), mode); output.write(data); output.flush(); os.fsync(output.fileno())
    syncdir(path.parent)
def json_bytes(value): return (json.dumps(value, sort_keys=True) + '\n').encode()
def replace_json(path, value, operation):
    temporary = path.with_name(path.name + '.' + operation + '.new')
    new(temporary, json_bytes(value)); os.replace(temporary, path); syncdir(path.parent)
def bounded(args, timeout=30, limit=65536, binary_target=None):
    # Capture privately even on timeout/nonzero/oversize; never discard the cause.
    output_context = binary_target.open('xb') if binary_target is not None else tempfile.TemporaryFile()
    with output_context as stdout, tempfile.TemporaryFile() as stderr:
        preexec = None
        if binary_target is not None:
            import resource
            os.fchmod(stdout.fileno(), 0o600)
            def preexec(): resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
        started = time.monotonic_ns()
        error = None
        try:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=timeout, preexec_fn=preexec)
            returncode = result.returncode
        except (subprocess.TimeoutExpired, OSError) as exc:
            returncode, error = None, type(exc).__name__ + ': ' + str(exc)
        stdout.flush()
        if binary_target is not None:
            os.fsync(stdout.fileno()); syncdir(binary_target.parent)
        sizes = (stdout.tell(), stderr.tell())
        stdout.seek(0); stderr.seek(0)
        if error is not None or returncode != 0 or max(sizes) > limit:
            diagnostic = dict(argv=args, returncode=returncode, error=error,
                              timeout_seconds=timeout, elapsed_ns=time.monotonic_ns() - started,
                              stdout_bytes=sizes[0], stderr_bytes=sizes[1],
                              stdout=(stdout.read(min(limit, 16384)).decode('utf-8', errors='replace') if binary_target is None else '[private binary output]'),
                              stderr=stderr.read(min(limit, 16384)).decode('utf-8', errors='replace'))
            diagnostic['truncated'] = max(sizes) > min(limit, 16384)
            directory = globals().get('COMMAND_DIAGNOSTICS')
            if directory is not None:
                new(directory / ('command-failure-' + str(uuid.uuid4()) + '.json'), json_bytes(diagnostic))
            # Before campaign creation the authenticated transport still captures
            # this diagnostic in its private guest-result, never public stdout.
            raise ValueError('bounded command failed: ' + json.dumps(diagnostic, sort_keys=True))
        return stdout.read().decode('utf-8') if binary_target is None else None

def copy_exact(source, target, expected, size, mode=0o600):
    regular(source, stat.S_IMODE(source.lstat().st_mode))
    need(source.stat().st_size == size and file_hash(source) == expected, 'copy source mismatch')
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, mode)
    with os.fdopen(fd, 'wb') as output, source.open('rb') as incoming:
        os.fchmod(output.fileno(), mode)
        shutil.copyfileobj(incoming, output, 65536); output.flush(); os.fsync(output.fileno())
    syncdir(target.parent)
    need(target.stat().st_size == size and file_hash(target) == expected, 'copy verification failed')
def immutable_guard(c, ra):
    ra['trusted_dir'](ra['STATE'], 0o700)
    ra['trusted_dir'](ra['RULE'].parent)
    state = ra['observe']()
    prior = json.loads(ra['read_owned'](ra['STATE'] / 'receipt.json', 0o600))
    rc = dict(schema=1, action='verify', owner_uuid=c['owner_uuid'], campaign_uuid=c['ra_campaign'],
              transition_uuid=c['operation'], expect=prior['new_value'], value=prior['new_value'],
              source_sha=c['source_sha'], image_id=c['image_id'], generator_sha256=c['ra_generator'])
    need(prior['new_value'] in (128, 1024), 'owned readahead value')
    ra['validate'](rc, state, prior, ra['read_owned'](ra['RULE'], 0o644))
    need(not os.path.lexists(ra['STATE'] / 'transition.lock'), 'readahead transition incomplete')
    need(pathlib.Path('/proc/sys/kernel/osrelease').read_text().strip() == c['kernel'], 'kernel changed')
    need(bounded(['blkid', '-s', 'UUID', '-o', 'value', '/dev/sda1']).strip() == c['root_uuid'], 'root UUID changed')
    need(bounded(['findmnt', '-n', '-o', 'SOURCE,FSTYPE', '--target', '/boot']).split() == ['/dev/sda16', 'ext4'], 'boot filesystem changed')
    return state, prior, rc
def preserved_files(c):
    paths = ['/boot/grub/grub.cfg', '/etc/default/grub.d/99-culvert-splash.cfg',
             '/boot/vmlinuz-' + c['kernel'], '/boot/initrd.img-6.8.0-142-generic', '/boot/vmlinuz-6.8.0-142-generic']
    result = {}
    for name in paths:
        p = pathlib.Path(name); info = p.lstat()
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1, 'unsafe preserved boot file')
        result[name] = {'sha256': file_hash(p), 'mode': stat.S_IMODE(info.st_mode), 'bytes': info.st_size}
    result['/proc/cmdline'] = pathlib.Path('/proc/cmdline').read_text()
    return result
def expand(path, output):
    need(not os.path.lexists(output), 'existing expansion')
    bounded(['unmkinitramfs', str(path), str(output)], timeout=120, limit=65536)
    return manifest(output)
def boot_tools(expanded, rows):
    matches = [name for name in rows if name.endswith('/scripts/functions')]
    need(len(matches) == 1 and rows[matches[0]]['kind'] == 'file', 'original initrd functions unavailable')
    root = expanded / matches[0].split('/scripts/functions')[0]
    # Executes only the original package shell's tool discovery in an isolated
    # expanded initrd: no /proc,/sys,/dev mounts, no boot script execution.
    command = ('PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH; '
               'for tool in cat tr readlink; do command -v "$tool" || exit 1; done; '
               '. /scripts/functions || exit 1; command -v get_fstype || exit 1; '
               'command -v blkid || command -v fstype || exit 1')
    bounded(['chroot', str(root), '/bin/sh', '-c', command], timeout=15)
    return root
def prepare(c, state, ra, prior):
    need(prior['new_value'] == 128, 'prepare requires returned A128')
    need(not os.path.lexists(state), 'prepare already attempted')
    state.mkdir(mode=0o700); syncdir(state.parent)
    globals()['COMMAND_DIAGNOSTICS'] = state
    new(state / 'operation.lock', json_bytes({'operation': c['operation']}))
    record = {key: c[key] for key in ('schema', 'campaign', 'owner_uuid', 'source_sha', 'image_id', 'kernel', 'root_uuid', 'generator_sha256', 'ra_campaign', 'ra_generator')}
    record.update(status='preparing', operation=c['operation'])
    new(state / ('operation-' + c['operation'] + '.json'), json_bytes(record))
    need(shutil.disk_usage('/').free >= 4 * 1024**3 and shutil.disk_usage('/boot').free >= 3 * 128 * 1024**2, 'insufficient root/boot headroom')
    original = pathlib.Path('/boot/initrd.img-' + c['kernel'])
    regular(original, 0o644)
    record['preserved'] = preserved_files(c)
    copy_exact(original, state / 'original.initrd', c['original_sha'], c['original_bytes'])
    manifests = {'original': expand(state / 'original.initrd', state / 'expanded-original')}
    original_root = boot_tools(state / 'expanded-original', manifests['original'])
    order_path = 'scripts/local-premount/ORDER'
    orders = {'original': (original_root / order_path).read_bytes()}
    record['stages'] = {}
    original_copy = state / 'original.initrd'
    with original_copy.open('rb') as source:
        prefix = source.read(c['main_offset'])
        need(len(prefix) == c['main_offset'] and hashlib.sha256(prefix).hexdigest() == c['prefix_sha'], 'original prefix differs')
        need(source.read(4) == b'\x28\xb5\x2f\xfd', 'original main compression differs')
        source.seek(c['main_offset'])
        main = state / 'original-main.zstd'
        with main.open('xb') as output:
            os.fchmod(output.fileno(), 0o600)
            shutil.copyfileobj(source, output, 65536); output.flush(); os.fsync(output.fileno())
        syncdir(state)
    need('CONFIG_RD_ZSTD=y' in pathlib.Path('/boot/config-' + c['kernel']).read_text().splitlines(), 'kernel zstd support missing')
    raw = state / 'original-main.cpio'
    bounded(['zstd', '-q', '-d', '-c', str(main)], timeout=180, limit=c['max_main'], binary_target=raw)
    compressor = ['zstd', '-q', '-3', '--single-thread', '-c']
    record['archive_format'] = dict(main_offset=c['main_offset'], prefix_sha256=c['prefix_sha'],
                                  raw_original_sha256=file_hash(raw), compressor=compressor,
                                  compressor_version=bounded(['zstd', '--version']).strip())
    for profile in ('A', 'B'):
        fixture = base64.b64decode(c['hooks'][profile])
        edited = state / (profile + '-main.cpio')
        orders[profile] = rewrite_newc(raw, edited, fixture, orders['original'])
        os.chmod(edited, 0o600); syncdir(state)
        compressed = state / (profile + '-main.zstd')
        bounded(compressor + [str(edited)], timeout=180, limit=128 * 1024**2, binary_target=compressed)
        if profile == 'A':
            repeated_raw = state / 'A-main-repeat.cpio'
            need(rewrite_newc(raw, repeated_raw, fixture, orders['original']) == orders[profile]
                 and file_hash(repeated_raw) == file_hash(edited), 'newc rewrite is not deterministic')
            os.chmod(repeated_raw, 0o600); syncdir(state)
            repeated = state / 'A-main-repeat.zstd'
            bounded(compressor + [str(repeated_raw)], timeout=180, limit=128 * 1024**2, binary_target=repeated)
            need(file_hash(compressed) == file_hash(repeated) and compressed.stat().st_size == repeated.stat().st_size,
                 'compression is not deterministic')
            record['archive_format']['repeat_A_sha256'] = file_hash(repeated)
        staged = state / (profile + '.initrd')
        with staged.open('xb') as output, compressed.open('rb') as source:
            os.fchmod(output.fileno(), 0o600); output.write(prefix)
            shutil.copyfileobj(source, output, 65536); output.flush(); os.fsync(output.fileno())
        syncdir(state); info = regular(staged, 0o600)
        with staged.open('rb') as source:
            need(hashlib.sha256(source.read(c['main_offset'])).hexdigest() == c['prefix_sha'], 'staged prefix differs')
        manifests[profile] = expand(staged, state / ('expanded-' + profile))
        expanded_root = boot_tools(state / ('expanded-' + profile), manifests[profile])
        need((expanded_root / order_path).read_bytes() == orders[profile], 'staged ORDER differs')
        record['stages'][profile] = {'sha256': file_hash(staged), 'bytes': info.st_size,
                                    'main_raw_sha256': file_hash(edited), 'main_zstd_sha256': file_hash(compressed)}
    fixture_path = compare_manifests(manifests['original'], manifests['A'], manifests['B'],
                                    base64.b64decode(c['hooks']['A']), base64.b64decode(c['hooks']['B']), orders)
    need(preserved_files(c) == record['preserved'] and file_hash(original) == c['original_sha'], 'boot files changed during prepare')
    for name, rows in manifests.items():
        new(state / ('manifest-' + name + '.json'), json_bytes(rows))
    record.update(status='prepared', active='original', exported=False, fixture_path=fixture_path,
                  original_sha=c['original_sha'], original_bytes=c['original_bytes'], before_boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    new(state / 'receipt.json', json_bytes(record))
    finish(state, c, record)
    return record
def finish(state, c, record):
    replace_json(state / ('operation-' + c['operation'] + '.json'), dict(record, status='complete'), c['operation'])
    lock = state / 'operation.lock'
    need(json.loads(lock.read_text())['operation'] == c['operation'], 'lock ownership changed')
    lock.unlink(); syncdir(state)
def receipt_guard(c, state):
    regular(state / 'receipt.json', 0o600, 4 * 1024**2)
    record = json.loads((state / 'receipt.json').read_text())
    need(all(record[k] == c[k] for k in ('schema', 'campaign', 'owner_uuid', 'source_sha', 'image_id', 'kernel', 'root_uuid', 'generator_sha256', 'ra_campaign', 'ra_generator')), 'receipt ownership mismatch')
    need(record['status'] == 'prepared' and preserved_files(c) == record['preserved'], 'preserved boot files differ')
    for p in state.glob('operation-*.json'):
        regular(p, 0o600, 4 * 1024**2)
        need(json.loads(p.read_text()).get('status') == 'complete', 'prior transition incomplete')
    need(not os.path.lexists(state / 'operation.lock'), 'prior operation incomplete')
    path = pathlib.Path('/boot/initrd.img-' + c['kernel']); regular(path, 0o644)
    active = record['active']
    expected = c['original_sha'] if active == 'original' else record['stages'][active]['sha256']
    need(file_hash(path) == expected, 'active initrd changed')
    return record
def mutate_rule(ra, rc, value):
    if rc['value'] == value:
        return {'unchanged': True, 'effective': value}
    rc = dict(rc, action='set', value=value)
    output = io.StringIO()
    with contextlib.redirect_stdout(output): ra['guest_main'](rc)
    result = json.loads(output.getvalue())
    need(result['status'] == 'complete' and result['effective'] == value, 'root rule transition failed')
    return result
def main(c):
    import tempfile
    globals()['tempfile'] = tempfile
    need(os.geteuid() == 0, 'authenticated root required')
    ra = {}; exec(base64.b64decode(c['ra_guest_b64']), ra)
    for directory in (pathlib.Path('/boot'), pathlib.Path('/var/lib')): ra['trusted_dir'](directory)
    observed, prior, rc = immutable_guard(c, ra)
    state_parent = pathlib.Path('/var/lib/culvert-lab-early-read-ahead-campaigns')
    state = campaign_state(state_parent, c['campaign'])
    if c['action'] == 'prepare' and not os.path.lexists(state_parent):
        state_parent.mkdir(mode=0o700); syncdir(state_parent.parent)
    ra['trusted_dir'](state_parent, 0o700)
    if c['action'] == 'prepare':
        result = prepare(c, state, ra, prior)
        print(json.dumps({'result': 'pass', 'action': 'prepare', 'stages': result['stages']})); return
    ra['trusted_dir'](state, 0o700)
    globals()['COMMAND_DIAGNOSTICS'] = state
    record = receipt_guard(c, state)
    if c['action'] == 'verify':
        need(record['active'] == c['profile'], 'verification profile differs')
        value = 1024 if c['profile'] == 'B' else 128
        need(observed['effective'] == value, 'postboot effective value differs')
        boot = pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        need(boot != record['before_boot'], 'new boot not observed')
        result = {'profile': c['profile'], 'boot_id': boot}
        if c['profile'] != 'original':
            text = bounded(['dmesg', '--time-format=raw', '--color=never'], limit=4 * 1024**2)
            result.update(verify_boot_marker(text, c['campaign'], value, boot))
        need(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip() == boot, 'boot changed during proof')
        print(json.dumps(dict(result, result='pass', action='verify'))); return
    new(state / 'operation.lock', json_bytes({'operation': c['operation']}))
    intent = dict(action=c['action'], operation=c['operation'], status='pending', previous_active=record['active'])
    new(state / ('operation-' + c['operation'] + '.json'), json_bytes(intent))
    if c['action'] == 'export':
        need(record['active'] == 'original' and record['exported'] is False, 'export already performed or wrong active profile')
        original = state / 'original.initrd'; regular(original, 0o600)
        need(original.stat().st_size == c['original_bytes'] and file_hash(original) == c['original_sha'], 'original backup differs')
        reply = bounded(['curl', '--noproxy', '*', '--proto', '=https', '--tlsv1.2', '-fsSk', '--connect-timeout', '5',
                         '--max-time', '180', '--pinnedpubkey', c['pin'], '-H', 'Content-Type: application/octet-stream',
                         '--data-binary', '@' + str(original), c['url']], timeout=190, limit=65536)
        ack = json.loads(reply)
        need(ack == {'result': 'stored', 'sha256': c['original_sha'], 'bytes': c['original_bytes'],
                     'campaign': c['campaign'], 'owner_uuid': c['owner_uuid']}, 'offguest export not acknowledged')
        record['exported'] = True
        record['export_ack_sha256'] = hashlib.sha256(reply.encode()).hexdigest()
    else:
        target = target_profile(c['action'], record['active'], record['exported'])
        expected = {'sha256': c['original_sha'], 'bytes': c['original_bytes']} if target == 'original' else record['stages'][target]
        source = state / ('original.initrd' if target == 'original' else target + '.initrd')
        regular(source, 0o600)
        need(shutil.disk_usage('/boot').free >= expected['bytes'] + 128 * 1024**2, 'boot headroom changed')
        temporary = pathlib.Path('/boot/.culvert-lab-initrd-' + c['operation'] + '.new')
        copy_exact(source, temporary, expected['sha256'], expected['bytes'], 0o644)
        intent['rule_transition'] = mutate_rule(ra, rc, 1024 if target == 'B' else 128)
        active = pathlib.Path('/boot/initrd.img-' + c['kernel'])
        regular(active, 0o644)
        previous_hash = c['original_sha'] if record['active'] == 'original' else record['stages'][record['active']]['sha256']
        need(file_hash(active) == previous_hash and preserved_files(c) == record['preserved'], 'boot files changed before atomic replacement')
        os.replace(temporary, active); syncdir(active.parent)
        need(file_hash(active) == expected['sha256'] and preserved_files(c) == record['preserved'], 'published boot image verification failed')
        record.update(active=target, before_boot=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    replace_json(state / 'receipt.json', record, c['operation'])
    finish(state, c, dict(intent, active=record['active']))
    print(json.dumps({'result': 'pass', 'action': c['action'], 'active': record['active'],
                      'original_sha256': c['original_sha'], 'reboot_required': c['action'] != 'export'}))
'''


class Export:
    """Exactly one owned-IP upload; bytes are private and never served by HTTP."""
    def __init__(self, guest, route, directory, identity):
        self.guest, self.route, self.directory, self.identity = guest, route, directory, identity
        self.used = False
        self.complete = False

    def receive(self, peer, route, headers, stream):
        need(peer == self.guest and route == self.route and not self.used, 'unauthorized or repeated export')
        need(headers.get('Transfer-Encoding') is None and headers.get('Content-Length') == str(ORIGINAL_BYTES), 'exact bounded content length required')
        self.used = True
        target = self.directory / 'original.initrd'
        remaining, digest, deadline = ORIGINAL_BYTES, hashlib.sha256(), time.monotonic() + 180
        with target.open('xb') as output:
            while remaining:
                need(time.monotonic() < deadline, 'export deadline')
                chunk = stream.read(min(65536, remaining))
                need(chunk and len(chunk) <= remaining, 'incomplete export')
                output.write(chunk); digest.update(chunk); remaining -= len(chunk)
            output.flush(); os.fsync(output.fileno())
        need(digest.hexdigest() == ORIGINAL_SHA and target.stat().st_size == ORIGINAL_BYTES <= MAX_INITRD
             and file_hash(target) == ORIGINAL_SHA, 'export hash/size mismatch')
        ack = dict(result='stored', sha256=ORIGINAL_SHA, bytes=ORIGINAL_BYTES, **self.identity)
        with (self.directory / 'export-receipt.json').open('x', encoding='ascii', newline='\n') as output:
            json.dump(ack, output, sort_keys=True); output.flush(); os.fsync(output.fileno())
        need(json.loads((self.directory / 'export-receipt.json').read_bytes()) == ack, 'export receipt readback differs')
        self.complete = True
        return (json.dumps(ack, sort_keys=True) + '\n').encode()


@contextlib.contextmanager
def export_endpoint(console, transfer, bind, tls):
    context, pin = console.make_tls(tls)
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_POST(self):
            try:
                ack = transfer.receive(self.client_address[0], self.path, self.headers, self.rfile)
                self.send_response(200); self.send_header('Content-Length', str(len(ack))); self.end_headers()
                self.wfile.write(ack); self.wfile.flush()
            except Exception:
                self.send_error(403)
    class Server(HTTPServer):
        def get_request(self):
            sock, peer = self.socket.accept(); sock.settimeout(10)
            try: return context.wrap_socket(sock, server_side=True), peer
            except Exception:
                sock.close(); raise
    server = Server((bind, 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        yield pin, 'https://' + bind + ':' + str(server.server_port) + transfer.route
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=15)


def payload(config):
    return ("#!/usr/bin/env bash\nset +x\nset -euo pipefail\numask 077\ntimeout 1500s python3 - <<'CULVERT_LAB_EARLY_READ_AHEAD'\n"
            + GUEST + '\n' + COMMON + '\nmain(' + repr(config) + ')\nCULVERT_LAB_EARLY_READ_AHEAD\n').encode('ascii')


def run(args):
    need(str(uuid.UUID(args.campaign)) == args.campaign and str(uuid.UUID(args.ra_campaign)) == args.ra_campaign, 'canonical campaign IDs required')
    need(re.fullmatch(r'[a-f0-9]{64}', args.ra_generator) is not None, 'readahead generator SHA required')
    bind = ipaddress.IPv4Address(args.bind)
    need(not bind.is_unspecified and not bind.is_multicast and not bind.is_loopback, 'specific reachable bind IP required')
    console = load_module('early_console', 'console-priv.py')
    ra = load_module('early_ra', 'production-readahead-control.py')
    lab = console.b.module.Lab(args.scope)
    console.b.private_directory(lab)
    console.b.module.validate_scope(lab.c)
    need(lab.c['source_sha'] == SOURCE and lab.c['image_id'] == IMAGE and lab.c['max_vms'] == 1, 'exact one-VM candidate required')
    need(args.facts.resolve().is_relative_to(lab.sec.resolve()) and not args.facts.is_symlink(), 'facts must remain in private scope')
    root_uuid = private_facts(json.loads(args.facts.read_bytes()))
    directory = lab.sec / 'early-read-ahead' / args.campaign
    for path in (lab.sec / 'early-read-ahead', directory):
        need(not path.is_symlink() and not (hasattr(path, 'is_junction') and path.is_junction()), 'private directory redirection refused')
    directory.mkdir(parents=True, exist_ok=True)
    need(directory.resolve().is_relative_to(lab.sec.resolve()), 'unsafe private directory')
    operation = str(uuid.uuid4())
    attempt = directory / ('operation-' + operation)
    with console.b.module.locked(lab.run):
        lab.vm(timeout=30)
        guest = lab.guest_ip(timeout=30)
        attempt.mkdir()
        config = dict(schema=1, action=args.action, profile=args.profile, campaign=args.campaign,
                      operation=operation, owner_uuid=lab.state['uuid'], source_sha=SOURCE, image_id=IMAGE,
                      kernel=KERNEL, root_uuid=root_uuid, original_sha=ORIGINAL_SHA, original_bytes=ORIGINAL_BYTES,
                      main_offset=MAIN_OFFSET, prefix_sha=PREFIX_SHA, max_main=MAX_MAIN,
                      generator_sha256=file_hash(Path(__file__)), ra_campaign=args.ra_campaign,
                      ra_generator=args.ra_generator, ra_guest_b64=base64.b64encode(ra.GUEST.encode()).decode())
        config['hooks'] = {name: base64.b64encode(boot_hook(config['owner_uuid'], args.campaign, root_uuid, value)).decode()
                           for name, value in [('A', 128), ('B', 1024)]}
        namespace = {}; exec(ra.GUEST, namespace)
        config['rules'] = {name: base64.b64encode(namespace['rule_bytes']({'owner_uuid': config['owner_uuid'], 'campaign_uuid': args.ra_campaign}, value)).decode()
                           for name, value in [('A', 128), ('B', 1024)]}
        (attempt / 'intent.json').write_text(json.dumps({k: config[k] for k in ('action', 'profile', 'campaign', 'owner_uuid', 'operation', 'generator_sha256')}) + '\n', encoding='ascii')
        if args.action in ('applyA', 'applyB', 'restore'):
            for name in ('original.initrd', 'export-receipt.json'):
                path = directory / name
                need(path.is_file() and not path.is_symlink()
                     and not (hasattr(path, 'is_junction') and path.is_junction()), 'unsafe private escrow file')
            expected = dict(result='stored', sha256=ORIGINAL_SHA, bytes=ORIGINAL_BYTES,
                            campaign=args.campaign, owner_uuid=config['owner_uuid'])
            need(json.loads((directory / 'export-receipt.json').read_bytes()) == expected
                 and (directory / 'original.initrd').stat().st_size == ORIGINAL_BYTES
                 and file_hash(directory / 'original.initrd') == ORIGINAL_SHA, 'verified offguest original required')
        transfer = None
        endpoint = contextlib.nullcontext(None)
        if args.action == 'export':
            tls = attempt / 'tls'; tls.mkdir()
            transfer = Export(guest, '/' + secrets.token_hex(32), directory,
                              {'campaign': args.campaign, 'owner_uuid': config['owner_uuid']})
            endpoint = export_endpoint(console, transfer, args.bind, tls)
        with endpoint as addresses:
            if addresses: config.update(pin=addresses[0], url=addresses[1])
            body = payload(config)
            (attempt / 'payload.sh').write_bytes(body)
            output = io.BytesIO(); writer = io.TextIOWrapper(output, encoding='utf-8', write_through=True)
            with contextlib.redirect_stdout(writer):
                rc = console.execute(lab, SimpleNamespace(bind=args.bind, timeout=1500, nowait=False, as_user=False), body)
            result_bytes = output.getvalue(); (attempt / 'guest-result.json').write_bytes(result_bytes)
            need(rc == 0 and (transfer is None or transfer.complete), 'guest operation incomplete; do not retry')
            result = json.loads(result_bytes)
            need(result.get('result') == 'pass' and result.get('action') == args.action, 'guest result not verified')
        (attempt / 'complete.json').write_text(json.dumps({'result': 'pass', 'payload_sha256': hashlib.sha256(body).hexdigest(),
                 'guest_result_sha256': hashlib.sha256(result_bytes).hexdigest()}) + '\n', encoding='ascii')
    print(json.dumps({'action': args.action, 'result': 'pass', 'operation': operation,
                      'qualification': 'unchanged recovery gates remain required'}))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('prepare', 'export', 'applyA', 'applyB', 'verify', 'restore'))
    p.add_argument('--scope', type=Path, required=True)
    p.add_argument('--bind', required=True)
    p.add_argument('--campaign', required=True)
    p.add_argument('--ra-campaign', required=True)
    p.add_argument('--ra-generator', required=True)
    p.add_argument('--facts', type=Path, required=True)
    p.add_argument('--profile', choices=('A', 'B', 'original'))
    args = p.parse_args()
    try:
        need((args.action == 'verify') == (args.profile is not None), 'profile required only for verification')
        run(args); return 0
    except Exception:
        print('Early initrd LAB operation blocked; preserve private evidence and do not replay.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
