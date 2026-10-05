#!/usr/bin/env python3
"""Generate bounded LAB-only console scripts; never contacts a VM.

The owned udev rule applies in early userspace, NOT initramfs. Send generated
scripts only through console-priv's authenticated local PAM/sudo transport.
Keep script receipts and transition reports private. A partial transition is
not automatically recoverable: retain evidence and inspect it before proceeding.
"""
import argparse
import hashlib
from pathlib import Path
import uuid

SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
IMAGE = 'sha256:24b37bc217691058e56a838821b86dfbd45b927b1c0ea8ea867a28c54d4bcc47'

GUEST = r'''
import hashlib, json, os, pathlib, re, stat, subprocess, time, uuid
RULE = pathlib.Path('/etc/udev/rules.d/65-culvert-lab-read-ahead.rules')
STATE = pathlib.Path('/var/lib/culvert-lab-read-ahead')
READ_AHEAD = pathlib.Path('/sys/block/sda/queue/read_ahead_kb')
def need(ok, reason):
    if not ok:
        raise ValueError('lab readahead refused: ' + reason)
def canonical(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value
def sha(value):
    return hashlib.sha256(value).hexdigest()
def rule_bytes(c, value):
    return ('# Culvert LAB only; early userspace, not initramfs\n'
            '# owner=' + c['owner_uuid'] + ' campaign=' + c['campaign_uuid'] + '\n'
            'ACTION=="add|change", SUBSYSTEM=="block", KERNEL=="sda", ATTR{queue/read_ahead_kb}="'
            + str(value) + '"\n').encode('ascii')
def validate(c, observed, prior, content):
    need(c['schema'] == 1 and c['action'] in ('set', 'verify'), 'configuration schema')
    need(all(canonical(c[k]) for k in ('owner_uuid', 'campaign_uuid', 'transition_uuid')), 'canonical UUID')
    need(type(c['expect']) is int and type(c['value']) is int
         and c['expect'] in (128, 1024) and c['value'] in (128, 1024), 'approved value')
    need(observed['vendor'] == 'VMware, Inc.', 'VMware vendor')
    guest = observed['guest_uuid']
    need(canonical(guest) and guest in (c['owner_uuid'], str(uuid.UUID(bytes_le=uuid.UUID(c['owner_uuid']).bytes))), 'VM UUID binding')
    need(observed['source_sha'] == c['source_sha'] and observed['dirty'] is False
         and observed['image_id'] == c['image_id'], 'clean exact source/image')
    need(observed['root'] == '/dev/sda1 ext4' and observed['disks'] == ['sda']
         and observed['sectors'] == 40 * 1024**3 // 512, 'single approved root disk')
    need(observed['scheduler'].split().count('[mq-deadline]') == 1, 'mq-deadline scheduler')
    need(observed['effective'] == c['expect'], 'unexpected effective readahead')
    if prior is None:
        need(c['action'] == 'set' and c['expect'] == 128 and content is None, 'unowned rule or missing receipt')
    else:
        need(prior.get('schema') == 1 and prior.get('status') == 'complete', 'incomplete prior transition')
        need(all(prior.get(k) == c[k] for k in ('owner_uuid', 'campaign_uuid', 'source_sha', 'image_id', 'generator_sha256')), 'receipt ownership')
        need(prior.get('new_value') == c['expect'] and content == rule_bytes(c, c['expect'])
             and prior.get('rule_sha256') == sha(content), 'owned rule/receipt mismatch')
    if c['action'] == 'verify':
        need(c['value'] == c['expect'], 'verify cannot change value')
    elif prior is not None:
        need(c['value'] != c['expect'], 'transition must change one value')
def bounded(args):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    need(result.returncode == 0 and len(result.stdout) <= 32768 and len(result.stderr) <= 32768, 'bounded command failed')
    return result.stdout.decode('utf-8').strip()
def trusted_dir(path, mode=None):
    # Check every ancestor without accepting symlink traversal.
    for parent in [path] + list(path.parents):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe directory')
    if mode is not None:
        need(stat.S_IMODE(path.lstat().st_mode) == mode, 'private directory mode')
def read_owned(path, mode):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == mode
         and info.st_nlink == 1 and info.st_size <= 65536, 'unsafe owned file')
    return path.read_bytes()
def write_new(path, value, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as output:
        os.fchmod(output.fileno(), mode)
        output.write(value); output.flush(); os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode('ascii')
def replace_owned(path, data, mode, token):
    temporary = path.with_name(path.name + '.' + token + '.new')
    write_new(temporary, data, mode)
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
def observe():
    build = json.loads(pathlib.Path('/var/lib/culvert-appliance/build-info.json').read_text())
    return {'vendor': pathlib.Path('/sys/class/dmi/id/sys_vendor').read_text().strip(),
            'guest_uuid': pathlib.Path('/sys/class/dmi/id/product_uuid').read_text().strip().lower(),
            'source_sha': build['source']['git_commit'], 'dirty': build['source']['git_dirty'],
            'image_id': bounded(['docker', 'inspect', '--format', '{{.Image}}', 'culvert']),
            'root': ' '.join(bounded(['findmnt', '-n', '-o', 'SOURCE,FSTYPE', '--target', '/']).split()),
            'disks': sorted(p.name for p in pathlib.Path('/sys/block').iterdir()
                            if re.fullmatch(r'(?:sd|vd|xvd|hd)[a-z]+|nvme[0-9]+n[0-9]+|mmcblk[0-9]+', p.name)),
            'sectors': int(pathlib.Path('/sys/block/sda/size').read_text()),
            'scheduler': pathlib.Path('/sys/block/sda/queue/scheduler').read_text().strip(),
            'effective': int(READ_AHEAD.read_text()),
            'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'monotonic_ns': time.monotonic_ns(), 'realtime_ns': time.time_ns()}
def guest_main(c):
    need(os.geteuid() == 0, 'authenticated local root required')
    trusted_dir(RULE.parent)
    trusted_dir(STATE.parent)
    exists = os.path.lexists(STATE)
    prior, content = None, None
    if exists:
        trusted_dir(STATE, 0o700)
        need(not os.path.lexists(STATE / 'transition.lock'), 'transition already pending')
        prior = json.loads(read_owned(STATE / 'receipt.json', 0o600))
        content = read_owned(RULE, 0o644)
        for path in STATE.glob('transition-*.json'):
            need(json.loads(read_owned(path, 0o600)).get('status') == 'complete', 'incomplete transition history')
    else:
        need(not os.path.lexists(RULE), 'preexisting unowned rule')
    observed = observe()
    validate(c, observed, prior, content)
    record = {k: c[k] for k in ('schema', 'owner_uuid', 'campaign_uuid', 'source_sha', 'image_id', 'generator_sha256', 'transition_uuid')}
    record.update(action=c['action'], old_value=c['expect'], new_value=c['value'],
                  rule_sha256=sha(rule_bytes(c, c['value'])), before=observed,
                  applicability='early userspace only; initramfs unchanged',
                  timing_limit='postboot verification timestamps observation, not the exact early udev application')
    if c['action'] == 'verify':
        record.update(status='verified', effective=observed['effective'])
        print(json.dumps(record, sort_keys=True)); return
    if not exists:
        STATE.mkdir(mode=0o700)
    lock = STATE / 'transition.lock'
    write_new(lock, encoded({'transition_uuid': c['transition_uuid']}), 0o600)
    # Retain the lock and intent on EVERY failure; no blind retry after partial writes.
    need(int(READ_AHEAD.read_text()) == c['expect'], 'effective value changed before lock')
    if prior is None:
        need(not os.path.lexists(RULE) and not os.path.lexists(STATE / 'receipt.json'), 'ownership changed before lock')
    else:
        need(json.loads(read_owned(STATE / 'receipt.json', 0o600)) == prior
             and read_owned(RULE, 0o644) == content, 'receipt/rule changed before lock')
    transition = STATE / ('transition-' + c['transition_uuid'] + '.json')
    record['status'] = 'pending'
    write_new(transition, encoded(record), 0o600)
    if prior is None:
        write_new(RULE, rule_bytes(c, c['value']), 0o644)
    else:
        replace_owned(RULE, rule_bytes(c, c['value']), 0o644, c['transition_uuid'])
    started_mono, started_real = time.monotonic_ns(), time.time_ns()
    with READ_AHEAD.open('w', encoding='ascii') as output:
        output.write(str(c['value']) + '\n')
    effective = int(READ_AHEAD.read_text())
    ended_mono, ended_real = time.monotonic_ns(), time.time_ns()
    need(effective == c['value'] and read_owned(RULE, 0o644) == rule_bytes(c, c['value']), 'effective value/rule did not apply')
    record.update(status='complete', effective=effective,
                  effective_write={'started_monotonic_ns': started_mono, 'ended_monotonic_ns': ended_mono,
                                   'started_realtime_ns': started_real, 'ended_realtime_ns': ended_real})
    replace_owned(transition, encoded(record), 0o600, c['transition_uuid'])
    replace_owned(STATE / 'receipt.json', encoded(record), 0o600, c['transition_uuid'])
    # Only this exclusively-created fixed-path lock is removed; retain all receipts.
    lock.unlink()
    print(json.dumps(record, sort_keys=True))
'''


def generate(action, owner_uuid, campaign_uuid, expect, value, generator_sha256):
    if (action not in ('set', 'verify') or any(str(uuid.UUID(v)) != v for v in (owner_uuid, campaign_uuid))
            or type(expect) is not int or type(value) is not int or expect not in (128, 1024)
            or value not in (128, 1024) or (action == 'verify' and expect != value)
            or len(generator_sha256) != 64 or any(c not in '0123456789abcdef' for c in generator_sha256)):
        raise ValueError('invalid explicit LAB comparison configuration')
    config = dict(schema=1, action=action, owner_uuid=owner_uuid, campaign_uuid=campaign_uuid,
                  transition_uuid=str(uuid.uuid4()), expect=expect, value=value,
                  source_sha=SOURCE, image_id=IMAGE, generator_sha256=generator_sha256)
    return ("#!/usr/bin/env bash\nset -euo pipefail\nset +x\numask 077\ntimeout 60s python3 - <<'CULVERT_LAB_READ_AHEAD'\n"
            + GUEST + '\nconfiguration = ' + repr(config) + '\nguest_main(configuration)\nCULVERT_LAB_READ_AHEAD\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('set', 'verify'))
    parser.add_argument('--owner-uuid', required=True)
    parser.add_argument('--campaign-uuid', required=True)
    parser.add_argument('--expect', type=int, required=True)
    parser.add_argument('--value', type=int, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    script = generate(args.action, args.owner_uuid, args.campaign_uuid, args.expect, args.value,
                      hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with args.output.open('x', encoding='ascii', newline='\n') as output:
        output.write(script)
    print('Generated LAB-only payload SHA256 ' + hashlib.sha256(script.encode('ascii')).hexdigest())


if __name__ == '__main__':
    main()
