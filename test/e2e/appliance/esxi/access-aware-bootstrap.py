#!/usr/bin/env python3
"""Default-credential tty1 bootstrap only; never grants administrative SSH."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('bootstrap_checks', HERE / 'bootstrap-checks.py')
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def precheck_private_tool(root=bootstrap.module.ROOT):
    """Fail before recording an attempt when offline build inputs are absent."""
    bootstrap.ensure((root / '.tools/govmomi-v0.56.0-src/go.mod').is_file(),
                     'existing local govmomi source unavailable; no bootstrap attempt started')
    bootstrap.ensure((HERE / 'private-keystrokes.go').is_file() and shutil.which('go') is not None,
                     'private keyboard source/compiler unavailable; no bootstrap attempt started')


def tool_preparation_continuation(lab, marker):
    bootstrap.ensure(marker.is_file() and not marker.is_symlink() and marker.stat().st_size <= 4096,
                     'original bounded preparation marker required')
    raw = marker.read_bytes()
    bootstrap.ensure(json.loads(raw) == {'status': 'blocked', 'stage': 'private-tool-preparation',
                                       'uuid': lab.state['uuid']},
                     'only the same VM blocked before private tool preparation may continue')
    forbidden = {'private-keystrokes.exe', 'private-keyboard-build.json', 'go-cache',
                 'access-bootstrap-observation-extension.json', 'access-bootstrap-tool-preparation-extension.json'}
    for entry in lab.sec.iterdir():
        name = entry.name.lower()
        bootstrap.ensure(name not in forbidden
                         and not name.startswith(('bootstrap-', 'capture-', 'console-', 'transport-', 'go-build'))
                         and not name.endswith(('.png', '.jpg', '.jpeg', '.bmp', '.ansi')),
                         'prior capture, credential, private build or continuation refuses tool preparation resume')
    return {'prior_marker_sha256': hashlib.sha256(raw).hexdigest(),
            'bootstrap_helper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'keyboard_source_sha256': hashlib.sha256((HERE / 'private-keystrokes.go').read_bytes()).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--initial-timeout', type=int, default=900)
    resume = parser.add_mutually_exclusive_group()
    resume.add_argument('--resume-initial-observation', action='store_true',
                        help='Extend observation only after initial-capture expired without sending credentials')
    resume.add_argument('--resume-tool-preparation', action='store_true',
                        help='Continue once after a proven pre-build prerequisite failure; never retry credentials')
    args = parser.parse_args()
    precheck_private_tool()
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
        binding = {}
        if args.resume_tool_preparation:
            binding = tool_preparation_continuation(lab, marker)
            marker = lab.sec / 'access-bootstrap-tool-preparation-extension.json'
        if args.resume_initial_observation:
            previous = json.loads(marker.read_text(encoding='utf-8'))
            bootstrap.ensure(previous == {'status': 'blocked', 'stage': 'initial-capture', 'uuid': lab.state['uuid']},
                             'only a blocked initial observation may resume')
            bootstrap.ensure(not (lab.sec / 'bootstrap-console-password').exists(), 'authentication already started')
            marker = lab.sec / 'access-bootstrap-observation-extension.json'
        with marker.open('x', encoding='utf-8') as out:
            json.dump({'status': 'started', 'uuid': lab.state['uuid'], **binding}, out)
        if binding:
            print('Tool preparation continuation; prior marker SHA256 ' + binding['prior_marker_sha256'] +
                  '; bootstrap helper SHA256 ' + binding['bootstrap_helper_sha256'] +
                  '; unchanged keyboard source SHA256 ' + binding['keyboard_source_sha256'])
        flow = None
        try:
            flow = bootstrap.Bootstrap(lab, bootstrap.PrivateKeyboard(lab),
                    initial_timeout=args.initial_timeout,
                    capture_prefix=('bootstrap-tool-extension' if args.resume_tool_preparation else
                                    'bootstrap-extension' if args.resume_initial_observation else 'bootstrap') +
                                   ('-pixels' if os.environ.get('CULVERT_ESXI_CONSOLE_FONT') else ''))
            flow.authenticate()
            bootstrap.module.atomic_json(marker, {'status': 'passed', 'uuid': lab.state['uuid'], **binding})
            lab.record('access-aware-bootstrap', 'pass',
                       'default import reached authenticated tty1 through PAM forced password change; no SSH administration added')
        except Exception:
            stage = flow.stage if flow else 'private-tool-preparation'
            bootstrap.module.atomic_json(marker, {'status': 'blocked', 'stage': stage, 'uuid': lab.state['uuid'], **binding})
            lab.record('access-aware-bootstrap', 'blocked',
                       'stopped at ' + stage + '; no credential retry and no SSH bypass')
            raise SystemExit(1) from None


if __name__ == '__main__':
    main()
