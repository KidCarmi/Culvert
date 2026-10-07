#!/usr/bin/env python3
"""One Esc on an exact reviewed splash, privately observed for at most 45 seconds.

No credentials, fuzzy matching, input retry, or automatic reentry. Color alone
may differ as permitted by the frozen exact glyph decoder. Preserve all evidence.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import time

ORIGINAL = '91fd17fba173c555d5ab275f0143d8a582993689'
GEOMETRY = '7acb405c4e18e8fa8d77734e812b11bb91483208'
REFERENCES = {
    'visual-continuation-clean-boot-esc/frame-0022.png': '29f24751af7db08fd64e759c6b27c8250749d16f521112c728296f5c89958606',
    'visual-continuation-followup-early/frame-0032.png': 'dc2d98454739f69ac8176d9af4b409673cdb8114ae33e4cc88419b1f1244b8a6',
}


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verified(root, scope_path, revision):
    scope = json.loads(scope_path.read_bytes())
    manifest_path = Path(scope['controller_manifest'])
    manifest = json.loads(manifest_path.read_bytes())
    need(manifest.get('revision') == revision, 'frozen revision mismatch')
    relative = 'test/e2e/appliance/esxi/controller-freeze.py'
    need(digest(root / relative) == manifest['files'][relative], 'freeze verifier mismatch')
    load('esc_freeze_' + revision[:8], root / relative).verify(manifest_path, root)
    return scope


def decoded(path, visual, pixel, fonts):
    metadata = visual.image_metadata(path, visual.MAX_IMAGE)
    need((metadata['width'], metadata['height']) == (720, 400), 'exact VGA dimensions required')
    text = pixel.decode(path, fonts, cell_width=9)
    need('\ufffd' not in text and len(text.split('\n')) == 25, 'unrecognized console cells')
    return metadata, text


def references(sec, visual, pixel, fonts):
    result = []
    for relative, expected in REFERENCES.items():
        metadata, text = decoded(sec / relative, visual, pixel, fonts)
        need(metadata['sha256'] == expected, 'reviewed reference bytes differ')
        result.append(text)
    return tuple(result)


def matches(text, reviewed):
    return '\ufffd' not in text and text in reviewed


def durable(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(value, output, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def observe(lab, directory, visual, pixel, fonts, keyboard, reviewed,
            clock=time.monotonic, pause=time.sleep):
    pinned = visual.identity(visual.read_json(lab.state_file))
    scope_hash = digest(lab.scope_path)
    deadline = clock() + 45
    total = 0

    def owned():
        need(digest(lab.scope_path) == scope_hash, 'scope changed')
        state = visual.read_json(lab.state_file)
        need(visual.identity(state) == pinned, 'owner changed')
        visual.no_identity_reset(lab)
        lab.state = state
        need(lab.vm(timeout=5)['runtime']['powerState'] == 'poweredOn', 'owned VM not running')

    def capture(name):
        nonlocal total
        owned()
        path = directory / (name + '.png')
        need(total < visual.MAX_TOTAL, 'capture byte budget exhausted')
        lab.gov('vm.console', '-capture=' + str(path), lab.state['path'], timeout=5, json_output=False)
        owned()
        meta = visual.image_metadata(path, visual.MAX_TOTAL - total)
        total += meta['bytes']
        return path, meta

    for number in range(45):
        need(clock() < deadline, 'reviewed splash observation expired')
        path, metadata = capture('frame-%04d' % number)
        # Firmware and unmatched exact text remain observations, never key triggers.
        text = ''
        if (metadata['width'], metadata['height']) == (720, 400):
            text = pixel.decode(path, fonts, cell_width=9)
        matched = matches(text, reviewed)
        durable(directory / ('frame-%04d.json' % number), {
            'frame': path.name, **metadata, 'matched': matched,
            'monotonic_ns': time.monotonic_ns(), 'realtime_ns': time.time_ns()})
        if matched:
            owned()
            need(clock() < deadline, 'splash match exceeded deadline; no input')
            durable(directory / 'intent.json', {'key': 'KEY_ESC', 'identity': pinned,
                'reference_sha256': list(REFERENCES.values()), 'frame': path.name,
                'screen_sha256': metadata['sha256'], 'monotonic_ns': time.monotonic_ns()})
            keyboard.send('KEY_ESC')
            durable(directory / 'sent.json', {'key': 'KEY_ESC', 'monotonic_ns': time.monotonic_ns()})
            pause(1)
            after, after_meta = capture('after')
            durable(directory / 'complete.json', {'key_sent_once': True, 'after': after.name,
                **after_meta, 'visual_result_requires_review': True})
            return
        pause(min(1, max(0, deadline - clock())))
    raise ValueError('reviewed splash absent; no input')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original-root', type=Path, required=True)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--geometry-root', type=Path, required=True)
    parser.add_argument('--geometry-scope', type=Path, required=True)
    parser.add_argument('--label', required=True)
    args = parser.parse_args()
    directory = None
    try:
        need(re.fullmatch(r'[a-z][a-z0-9-]{0,47}', args.label), 'invalid exclusive label')
        original = verified(args.original_root.resolve(), args.scope, ORIGINAL)
        geometry = verified(args.geometry_root.resolve(), args.geometry_scope, GEOMETRY)
        need(geometry.get('console_cell_width') == 9, 'nine-pixel geometry required')
        for name in ('run_dir', 'source_sha', 'image_id', 'ova_sha256', 'endpoint'):
            need(original[name] == geometry[name], 'controller scope binding differs')
        visual = load('esc_visual', args.original_root / 'test/e2e/appliance/esxi/visual-capture.py')
        console = load('esc_console', args.original_root / 'test/e2e/appliance/esxi/console-priv.py')
        pixel = load('esc_pixel', args.geometry_root / 'test/e2e/appliance/esxi/pixel-console.py')
        lab = console.b.module.Lab(args.scope)
        console.b.module.validate_scope(lab.c)
        console.b.private_directory(lab)
        fonts = os.environ['CULVERT_ESXI_CONSOLE_FONT']
        with console.b.module.locked(lab.run), visual.passive_lock(lab.run):
            visual.preflight(lab)
            visual.identity(lab.state)
            visual.no_identity_reset(lab)
            reviewed = references(lab.sec, visual, pixel, fonts)
            directory = lab.sec / ('reviewed-splash-esc-' + args.label)
            directory.mkdir(mode=0o700)
            durable(directory / 'begin.json', {'helper_sha256': digest(Path(__file__)),
                'original_controller': ORIGINAL, 'geometry_controller': GEOMETRY,
                'scope_sha256': digest(args.scope), 'geometry_scope_sha256': digest(args.geometry_scope),
                'reference_sha256': list(REFERENCES.values()), 'decoder_sha256': digest(Path(pixel.__file__)),
                'font_sha256': [digest(Path(p)) for p in fonts.split(os.pathsep)], 'wait_seconds': 45})
            observe(lab, directory, visual, pixel, fonts, console.Keyboard(lab), reviewed)
        print('Esc sent once on exact reviewed splash; private after-frame requires review.')
        return 0
    except Exception:
        if directory is not None:
            durable(directory / 'blocked.json', {'realtime_ns': time.time_ns(),
                'intent_exists': (directory / 'intent.json').exists(), 'no_automatic_retry': True})
            error_path = lab.sec / 'govc-error.json'
            if error_path.is_file() and not error_path.is_symlink() and error_path.stat().st_size <= 65536:
                with (directory / 'private-last-govc-error.json').open('xb') as output:
                    output.write(error_path.read_bytes())
        print('BLOCKED: retain private frames and intent; never retry ambiguous input.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
