#!/usr/bin/env python3
"""Fail closed on incomplete target-specific GA/HWE engine/module evidence."""
import argparse
from collections import Counter
import json
from pathlib import Path
import re
import sys

MODULES = frozenset('sctp nfsd kvm kvm_amd kvm_intel ksmbd cifs can can_raw can_bcm '
                    'can_gw can_isotp can_j1939 pppoe pppox ib_core ib_cm iw_cm rdma_cm '
                    'ib_uverbs rdma_ucm ib_umad dccp tipc'.split())
DENYLIST_SHA256 = 'e4ac913a799845e42de1f5804d4ea9732a4d9fb447a8793ec16ef2c9e4c1aae3'
LEGACY = '7c7b29ee3be40af6a0809c73ad04d4337303263d'
PROFILES = json.loads(Path(__file__).with_name('engine-surface-profiles.json').read_bytes())


def verify(text, source=LEGACY):
    if source not in PROFILES:
        raise ValueError('unreviewed engine candidate')
    profile = PROFILES[source]
    expected = frozenset(profile['modules'])
    lines = text.splitlines()
    failures = []
    modules = [line for line in lines if line.startswith('module ')]
    names = Counter(line.split()[1] for line in modules)
    if names != Counter({name: 1 for name in expected}):
        failures.append(f'expected exactly one observation for each of the {len(expected)} denied modules')
    for line in modules:
        match = re.fullmatch(r'module (\w+) before=0 final=install /bin/false '
                             r'rc=([1-9][0-9]*) refused-by=(\w+) after=0', line)
        if not match or match[3] not in expected:
            failures.append('target denial not proven: ' + line.split()[1])
    effective = [line.split() for line in lines if line.startswith('effective ')]
    for name in expected:
        for kind, suffix in [('install', ['/bin/false']), ('softdep', []), ('blacklist', [])]:
            rules = [row[3:] for row in effective if len(row) >= 3 and row[1:3] == [kind, name]]
            # kmod lists the shipped override first, followed by the module's
            # built-in softdeps. Their presence is normal; the final resolution
            # and real refusal above prove that the first empty override won.
            accepted = bool(rules) and rules[0] == [] if kind == 'softdep' else rules == [suffix]
            if not accepted:
                failures.append(name + ': missing, duplicate or conflicting effective ' + kind)
    if lines.count('denylist-file ' + profile['denylist_sha256']) != 1:
        failures.append('shipped denylist digest differs from reviewed candidate source')
    for name in ('nvmet_tcp', 'ib_srpt'):
        if 'kernel' in profile:
            rows = [line for line in lines if line.startswith('extra-module ' + name + ' ')]
            match = re.fullmatch(r'extra-module ' + name + r' files=[1-9][0-9]* rc=[1-9][0-9]* '
                                r'loaded-after=0 refused-by=(\w+)', rows[0]) if len(rows) == 1 else None
            if not match or match[1] not in expected:
                failures.append(name + ': HWE load refusal not proven')
        else:
            rows = [line for line in lines if line.startswith('module-file ' + name + ' ')]
            if rows != ['module-file ' + name + ' 0']:
                failures.append(name + ': disk absence not proven')
    if 'kernel' in profile:
        hwe_proof(lines, profile, failures)
    sctp = [line for line in lines if line.startswith('sctp-socket=')]
    if len(sctp) != 1 or not re.fullmatch(r'sctp-socket=refused:.+ loaded-after=0', sctp[0]):
        failures.append('real SCTP socket refusal not proven')
    # Shared checks evaluate these rows; require their observations to exist so
    # an interrupted transport cannot turn a missing negative result into PASS.
    for prefix in ('running=', 'installed=', 'snapd-status=', 'snap-dir=',
                   'docker-ce=', 'containerd.io=', 'docker-compose-plugin=',
                   'sock /run/containerd/containerd.sock ', 'sock /run/docker.sock ',
                   'docker-group=', 'dockerd-argv ', 'disabled-plugins '):
        if sum(line.startswith(prefix) for line in lines) != 1:
            failures.append('missing or ambiguous observation: ' + prefix)
    for prefix in ('listen ', 'published ', 'plugin '):
        if not any(line.startswith(prefix) for line in lines):
            failures.append('missing observation: ' + prefix)
    if lines.count('=== containerd tracing') != 1:
        failures.append('collector did not reach the final tracing section')
    if not any(line.startswith('tracing ') for line in lines):
        for plugin in ('plugin io.containerd.tracing.processor.v1 otlp skip',
                       'plugin io.containerd.internal.v1 tracing skip'):
            if plugin not in lines:
                failures.append('empty tracing config requires both tracing plugins skipped')
    if failures:
        raise ValueError('; '.join(failures))
    return len(expected)


def hwe_proof(lines, profile, failures):
    """The kernel CVE dispositions depend on these concrete guest observations."""
    def one(prefix):
        values = [line[len(prefix):].strip() for line in lines if line.startswith(prefix)]
        if len(values) != 1:
            failures.append('missing or ambiguous HWE observation: ' + prefix)
            return ''
        return values[0]
    kernel = profile['kernel']
    if (one('kernel-running=') != kernel or one('running=') != kernel
            or one('installed=') != kernel or one('kernel-images=') != 'linux-image-' + kernel
            or not one('kernel-meta=').startswith('linux-image-virtual-hwe-24.04=')
            or one('kernel-ga-meta=')):
        failures.append('reviewed HWE kernel identity differs')
    if one('denied-count ') != str(len(profile['modules'])):
        failures.append('HWE denylist count differs')
    if one('drm-rule ') != profile['drm_rule_sha256']:
        failures.append('DRM root-only rule digest differs')
    if one('drm-nomodeset ') != 'yes' or one('drm-vmwgfx-loaded ') != '0':
        failures.append('shipped ESXi nomodeset/unbound vmwgfx posture differs')
    drm = [line for line in lines if line.startswith('drm ')]
    if drm:
        if any(not re.fullmatch(r'drm /dev/dri/(card|renderD)[0-9]+ root:root 600 acl=', line) for line in drm):
            failures.append('DRM node not exclusively root accessible')
    minimum = {'kernel.unprivileged_bpf_disabled': (1, 2), 'kernel.perf_event_paranoid': range(2, 10),
               'kernel.apparmor_restrict_unprivileged_userns': (1,), 'kernel.kptr_restrict': (1, 2),
               'kernel.dmesg_restrict': (1,), 'dev.tty.ldisc_autoload': (0,)}
    for name, allowed in minimum.items():
        if one('sysctl ' + name + '=') not in {str(n) for n in allowed}:
            failures.append('kernel prerequisite differs: ' + name)
    containers = [line for line in lines if line.startswith('container ')]
    names = Counter(line.split()[1] for line in containers)
    if any(names[name] != 1 for name in ('/culvert', '/culvert-clamav')):
        failures.append('app and scanner container observations required exactly once')
    if not containers or any(not re.search(r' privileged=false capadd=(\[\]|<no value>) devices=0 ', line)
                             or 'unconfined' in line for line in containers):
        failures.append('container capability/device isolation not proven')
    if one('perf-tool ') != 'absent' or one('fuse-mounts ') != '0 btrfs-mounts 0 nfs-mounts 0':
        failures.append('unexpected perf tool or filesystem attack surface')
    if one('net-reviewed-file ') != profile['net_reviewed_sha256']:
        failures.append('network autoload reviewed list differs from candidate source')
    if one('net-autoload-unreviewed=') != '[]':
        failures.append('unreviewed network autoload surface')
    counts = re.fullmatch(r'total=([0-9]+) denied=([0-9]+) reviewed=([0-9]+)', one('net-autoload '))
    if not counts or int(counts[1]) == 0 or int(counts[1]) != int(counts[2]) + int(counts[3]):
        failures.append('incomplete network autoload inventory')
    ext4 = [line.split() for line in lines if line.startswith('ext4 ')]
    if not ext4 or any(len(row) < 3 or 'ea_inode' in row[2:] for row in ext4):
        failures.append('ext4 feature prerequisite not proven')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--source', choices=sorted(PROFILES), default=LEGACY)
    parser.add_argument('--inventory', type=Path, help='Authenticated supplemental inventory, retained separately')
    args = parser.parse_args()
    try:
        evidence = args.evidence.read_text(encoding='utf-8')
        if args.inventory is not None:
            evidence += '\n' + args.inventory.read_text(encoding='utf-8')
        count = verify(evidence, args.source)
    except (OSError, UnicodeError, ValueError) as error:
        print('Engine evidence rejected: ' + str(error), file=sys.stderr)
        sys.exit(1)
    print(f'Complete target-specific evidence: {count} modules; reviewed denylist digest; engine observations.')
