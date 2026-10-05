#!/usr/bin/env python3
"""Validate the guarded restore's exact policy evidence after maintenance reboot."""
import json
from pathlib import Path
import re
import sys


def validate(policy, mutation):
    if not isinstance(mutation, str) or not re.fullmatch(r'esxi-post-backup-block-\d+-\d+', mutation):
        return False
    if not isinstance(policy, dict) or not isinstance(policy.get('rules'), list):
        return False
    rules = policy['rules']
    if not all(isinstance(rule, dict) for rule in rules):
        return False
    return (not any(rule.get('name') == mutation for rule in rules)
            and any(rule.get('name') == 'lab-allow-example' and rule.get('enabled') is True
                    for rule in rules))


def main(args):
    if len(args) != 2:
        return 1
    try:
        policy_path, mutation_path = map(Path, args)
        if policy_path.stat().st_size > 1024 * 1024 or mutation_path.stat().st_size > 200:
            return 1
        policy = json.loads(policy_path.read_text(encoding='utf-8'))
        mutation = mutation_path.read_text(encoding='utf-8').strip()
        return 0 if validate(policy, mutation) else 1
    except (OSError, ValueError):
        return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
