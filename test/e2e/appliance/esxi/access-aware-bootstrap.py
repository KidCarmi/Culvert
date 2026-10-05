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


TOOL_OBSERVATION_HELPER_SHA256 = 'bae39b5cf1a864125bb7f018f4699b36d14bb61dd8f0e727d8266867e0fe72be'


def observation_continuation(lab, marker):
    """Observe once more only when every preceding attempt stopped before auth."""
    def read_record(path):
        bootstrap.ensure(path.is_file() and not path.is_symlink() and path.stat().st_size <= 4096,
                         'bounded observation marker required')
        raw = path.read_bytes()
        return raw, json.loads(raw)

    bootstrap.ensure(not (lab.sec / 'bootstrap-console-password').exists(), 'authentication already started')
    bootstrap.ensure(not (lab.sec / 'access-bootstrap-observation-extension.json').exists(),
                     'observation continuation already attempted')
    original, record = read_record(marker)
    exact = {'status': 'blocked', 'stage': 'initial-capture', 'uuid': lab.state['uuid']}
    extension = lab.sec / 'access-bootstrap-tool-preparation-extension.json'
    if record == exact:
        bootstrap.ensure(not extension.exists(), 'unexpected tool continuation refuses observation')
        prior = original
    else:
        bootstrap.ensure(record == dict(exact, stage='private-tool-preparation'),
                         'only a blocked pre-authentication observation may resume')
        prior, continued = read_record(extension)
        required = set(exact) | {'prior_marker_sha256', 'bootstrap_helper_sha256', 'keyboard_source_sha256'}
        bootstrap.ensure(set(continued) == required and all(continued.get(k) == v for k, v in exact.items()),
                         'tool continuation has not stopped at initial observation')
        bootstrap.ensure(continued['prior_marker_sha256'] == hashlib.sha256(original).hexdigest(),
                         'original preparation marker binding mismatch')
        # This is the only preceding controller permitted to create that extension.
        bootstrap.ensure(continued['bootstrap_helper_sha256'] == TOOL_OBSERVATION_HELPER_SHA256,
                         'unrecognized tool continuation helper')
        bootstrap.ensure(continued['keyboard_source_sha256'] == hashlib.sha256((HERE / 'private-keystrokes.go').read_bytes()).hexdigest(),
                         'keyboard source changed across observation continuation')
    return {'prior_marker_sha256': hashlib.sha256(prior).hexdigest(),
            'original_marker_sha256': hashlib.sha256(original).hexdigest(),
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
            binding = observation_continuation(lab, marker)
            marker = lab.sec / 'access-bootstrap-observation-extension.json'
        with marker.open('x', encoding='utf-8') as out:
            json.dump({'status': 'started', 'uuid': lab.state['uuid'], **binding}, out)
        if binding:
            print('Bootstrap continuation; prior marker SHA256 ' + binding['prior_marker_sha256'] +
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
