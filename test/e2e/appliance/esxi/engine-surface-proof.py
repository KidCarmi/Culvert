#!/usr/bin/env python3
"""Fail closed on incomplete target-specific 7c engine/module evidence."""
from collections import Counter
from pathlib import Path
import re
import sys

MODULES = frozenset('sctp nfsd kvm kvm_amd kvm_intel ksmbd cifs can can_raw can_bcm '
                    'can_gw can_isotp can_j1939 pppoe pppox ib_core ib_cm iw_cm rdma_cm '
                    'ib_uverbs rdma_ucm ib_umad dccp tipc'.split())
DENYLIST_SHA256 = 'e4ac913a799845e42de1f5804d4ea9732a4d9fb447a8793ec16ef2c9e4c1aae3'


def verify(text):
    lines = text.splitlines()
    failures = []
    modules = [line for line in lines if line.startswith('module ')]
    names = Counter(line.split()[1] for line in modules)
    if names != Counter({name: 1 for name in MODULES}):
        failures.append('expected exactly one observation for each of the 24 denied modules')
    for line in modules:
        match = re.fullmatch(r'module (\w+) before=0 final=install /bin/false '
                             r'rc=([1-9][0-9]*) refused-by=(\w+) after=0', line)
        if not match or match[3] not in MODULES:
            failures.append('target denial not proven: ' + line.split()[1])
    effective = [line.split() for line in lines if line.startswith('effective ')]
    for name in MODULES:
        for kind, suffix in [('install', ['/bin/false']), ('softdep', []), ('blacklist', [])]:
            rules = [row[3:] for row in effective if len(row) >= 3 and row[1:3] == [kind, name]]
            # kmod lists the shipped override first, followed by the module's
            # built-in softdeps. Their presence is normal; the final resolution
            # and real refusal above prove that the first empty override won.
            accepted = bool(rules) and rules[0] == [] if kind == 'softdep' else rules == [suffix]
            if not accepted:
                failures.append(name + ': missing, duplicate or conflicting effective ' + kind)
    if lines.count('denylist-file ' + DENYLIST_SHA256) != 1:
        failures.append('shipped denylist digest differs from reviewed 7c source')
    for name in ('nvmet_tcp', 'ib_srpt'):
        rows = [line for line in lines if line.startswith('module-file ' + name + ' ')]
        if rows != ['module-file ' + name + ' 0']:
            failures.append(name + ': disk absence not proven')
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
    return len(MODULES)


if __name__ == '__main__':
    try:
        count = verify(Path(sys.argv[1]).read_text(encoding='utf-8'))
    except (OSError, UnicodeError, ValueError) as error:
        print('Engine evidence rejected: ' + str(error), file=sys.stderr)
        sys.exit(1)
    print(f'Complete target-specific evidence: {count} modules; reviewed denylist digest; engine observations.')
