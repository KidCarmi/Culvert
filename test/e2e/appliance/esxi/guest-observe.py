#!/usr/bin/env python3
"""Read-only guest boot facts. No raw journal, tokens or keys in stdout."""
import hashlib
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET


def read_command(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=20).stdout.strip()


def main():
    unit = Path('/etc/systemd/system/culvert-firstboot.service')
    journal = read_command(['journalctl', '-b', '--no-pager', '-o', 'cat'])
    state = read_command(['systemctl', 'show', 'culvert-firstboot.service',
                          '-p', 'ActiveState', '-p', 'SubState', '-p', 'Result',
                          '-p', 'ExecMainStartTimestamp', '-p', 'ExecMainStatus'])
    build = json.loads(Path('/var/lib/culvert-appliance/build-info.json').read_text())
    ovf = read_command(['vmware-rpctool', 'info-get guestinfo.ovfEnv'])
    instance_id = None
    try:
        ns = '{http://schemas.dmtf.org/ovf/environment/1}'
        instance_id = next((p.get(ns + 'value') for p in ET.fromstring(ovf).iter(ns + 'Property')
                            if p.get(ns + 'key') == 'instance-id'), None)
    except ET.ParseError:
        pass
    facts = dict(kernel=read_command(['uname', '-r']),
                 complete=Path('/var/lib/culvert-appliance/state/complete.done').is_file(),
                 firstboot_cycle=any('culvert-firstboot' in line and
                                     any(s in line.lower() for s in ('cycle', 'deleted', 'skipping'))
                                     for line in journal.splitlines()),
                 firstboot_state=dict(line.split('=', 1) for line in state.splitlines() if '=' in line),
                 firstboot_unit_sha256=hashlib.sha256(unit.read_bytes()).hexdigest() if unit.exists() else None,
                 source_sha=build.get('source', {}).get('git_commit'),
                 instance_id=instance_id,
                 image_id=read_command(['docker', 'inspect', '-f', '{{.Image}}', 'culvert']),
                 machine_id_sha256=hashlib.sha256(Path('/etc/machine-id').read_bytes()).hexdigest(),
                 boot_id_sha256=hashlib.sha256(Path('/proc/sys/kernel/random/boot_id').read_bytes()).hexdigest())
    print(json.dumps(facts))


if __name__ == '__main__':
    main()
