#!/usr/bin/env python3
"""One explicitly requested visual key, excluding every text/PAM action.

Review a recent private frame first. ESC is for the visible splash only. The
operation lock excludes import, bootstrap and privileged-console interaction.
An already built, source/hash-verified keyboard helper is required.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys
import time

HERE = Path(__file__).resolve().parent
KEYS = {'esc': 'KEY_ESC', 'alt-f12': 'KEY_ALT_F12', 'alt-f1': 'KEY_ALT_F1'}


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--key', choices=tuple(KEYS), required=True)
    parser.add_argument('--expected-screen-sha256', required=True,
                        help='SHA256 of the privately reviewed current screen; changed screen refuses input')
    args = parser.parse_args()
    try:
        visual = load('visual_frame', 'visual-capture.py')
        console = load('visual_console', 'console-priv.py')
        lab = console.b.module.Lab(args.scope)
        console.b.module.validate_scope(lab.c)
        visual.need(lab.c['source_sha'] == visual.SOURCE and re.fullmatch('[a-z][a-z0-9-]{0,47}', args.label), 'exact visual scope/label required')
        visual.need(re.fullmatch('[a-f0-9]{64}', args.expected_screen_sha256), 'reviewed screen hash required')
        console.b.private_directory(lab)
        with console.b.module.locked(lab.run):
            visual.preflight(lab)
            visual.identity(lab.state)
            visual.no_identity_reset(lab)
            directory = lab.sec / ('visual-key-' + args.label); directory.mkdir(mode=0o700)
            keyboard = console.Keyboard(lab)
            rows = []
            for phase in ('before', 'after'):
                visual.need(lab.vm(timeout=10)['runtime']['powerState'] == 'poweredOn', 'owned VM not running')
                path = directory / (phase + '.png')
                lab.gov('vm.console', '-capture=' + str(path), lab.state['path'], timeout=10, json_output=False)
                lab.vm(timeout=10)
                rows.append({'phase': phase, 'monotonic_ns': time.monotonic_ns(), **visual.image_metadata(path, visual.MAX_IMAGE)})
                if phase == 'before':
                    visual.need(rows[-1]['sha256'] == args.expected_screen_sha256, 'reviewed screen changed; no key sent')
                    # The marker is durable BEFORE the single key. No input retry.
                    (directory / 'intent.json').write_text(json.dumps({'key': args.key, 'uuid': lab.state['uuid'],
                        'expected_screen_sha256': args.expected_screen_sha256, 'frames': rows}))
                    keyboard.send(KEYS[args.key]); time.sleep(1)
            (directory / 'complete.json').write_text(json.dumps({'key': args.key, 'uuid': lab.state['uuid'], 'frames': rows}))
        print('Visual key sent once; private before/after frames require review.')
        return 0
    except Exception:
        print('BLOCKED: visual key incomplete; preserve private evidence; never retry ambiguous input.', file=sys.stderr)
        return 90


if __name__ == '__main__': sys.exit(main())
