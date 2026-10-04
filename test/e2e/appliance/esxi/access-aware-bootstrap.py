#!/usr/bin/env python3
"""Default-credential tty1 bootstrap only; never grants administrative SSH."""
import argparse
import importlib.util
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bootstrap_checks', HERE / 'bootstrap-checks.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--resume-initial-observation', action='store_true',
                        help='Extend observation only after initial-capture expired without sending credentials')
    args = parser.parse_args()
    lab = bootstrap.module.Lab(args.scope)
    with bootstrap.module.locked(lab.run):
        bootstrap.module.validate_scope(lab.c)
        bootstrap.ensure(lab.c.get('credential_mode') == 'none', 'default import required')
        bootstrap.private_directory(lab)
        lab.vm(timeout=15)
        props = json.loads((lab.sec / 'import.json').read_text())['PropertyMapping']
        bootstrap.ensure(not any(p.get('Value') and any(k in p.get('Key', '').lower()
                         for k in ('password', 'public-key', 'ssh')) for p in props),
                         'default import has supplied credentials')
        marker = lab.sec / 'access-bootstrap-attempt.json'
        if args.resume_initial_observation:
            previous = json.loads(marker.read_text(encoding='utf-8'))
            bootstrap.ensure(previous == {'status': 'blocked', 'stage': 'initial-capture', 'uuid': lab.state['uuid']},
                             'only a blocked initial observation may resume')
            bootstrap.ensure(not (lab.sec / 'bootstrap-console-password').exists(), 'authentication already started')
            marker = lab.sec / 'access-bootstrap-observation-extension.json'
        with marker.open('x', encoding='utf-8') as out:
            json.dump({'status': 'started', 'uuid': lab.state['uuid']}, out)
        flow = None
        try:
            flow = bootstrap.Bootstrap(lab, bootstrap.PrivateKeyboard(lab),
                    initial_timeout=900 if args.resume_initial_observation else 300,
                    capture_prefix=('bootstrap-extension' if args.resume_initial_observation else 'bootstrap') +
                                   ('-pixels' if os.environ.get('CULVERT_ESXI_CONSOLE_FONT') else ''))
            flow.authenticate()
            bootstrap.module.atomic_json(marker, {'status': 'passed', 'uuid': lab.state['uuid']})
            lab.record('access-aware-bootstrap', 'pass',
                       'default import reached authenticated tty1 through PAM forced password change; no SSH administration added')
        except Exception:
            stage = flow.stage if flow else 'private-tool-preparation'
            bootstrap.module.atomic_json(marker, {'status': 'blocked', 'stage': stage, 'uuid': lab.state['uuid']})
            lab.record('access-aware-bootstrap', 'blocked',
                       'stopped at ' + stage + '; no credential retry and no SSH bypass')
            raise SystemExit(1) from None


if __name__ == '__main__':
    main()
