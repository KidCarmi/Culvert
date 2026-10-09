#!/usr/bin/env python3
"""One Ctrl+C for the exact abandoned 91 sudo challenge; never enter credentials."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
NONCE = 'c406aedf244ce796f2dcc32926bce90bcdb4d36ecc784f1c'
UUID = '564d205b-b446-ee24-8c33-f4cf63c15efd'
REVISION = 'c637c1c677d6d1a36089c9e99b329f5e6e035d2a'
CAPTURE_SHA = '0746e15413f424356b02d4465e0705de3f8355f4b533daa346285b67fa281104'
FIELDS = {'scope', 'manifest', 'owned', 'pending_capture', 'lifecycle_receipt', 'lifecycle_out', 'lifecycle_err'}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / (name + '.py'))
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


console = load('console-priv')


def need(ok, message):
    if not ok: raise ValueError(message)


def raw(path):
    path = Path(path)
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 64*1024*1024, 'bounded regular evidence required')
    return path.read_bytes()


def sha(value): return hashlib.sha256(value).hexdigest()


def bound_external(manifest, path):
    path = Path(path).resolve()
    matches = [item for item in manifest.get('external_inputs', []) if Path(item['path']).resolve() == path]
    need(len(matches) == 1 and matches[0]['sha256'] == sha(raw(path)), 'external input not frozen')


def validate(lab, binding_path):
    freeze = load('controller-freeze')
    new = freeze.verify(Path(lab.c['controller_manifest']))
    bound_external(new, binding_path)
    binding = json.loads(raw(binding_path))
    need(set(binding) == {'original_root', 'files', 'cancel_binary', 'cancel_binary_sha256'}, 'binding fields refused')
    need(set(binding['files']) == FIELDS, 'original evidence set incomplete')
    evidence = {}
    for name, item in binding['files'].items():
        evidence[name] = raw(item['path'])
        need(sha(evidence[name]) == item['sha256'], 'original evidence changed: ' + name)
    old = json.loads(evidence['scope']); manifest = json.loads(evidence['manifest'])
    for name in ('visual-capture.lock', 'console-capture.lock', 'operation.lock', 'access-aware-qualify.lock', 'restore-qualification.lock'):
        need(not os.path.lexists(Path(old['run_dir']) / name), 'original run operation still active')
    need(manifest['revision'] == REVISION, 'original controller differs')
    root = Path(binding['original_root']).resolve()
    need(Path(binding['files']['manifest']['path']).resolve() == Path(old['controller_manifest']).resolve(), 'original manifest path differs')
    freeze.verify(Path(old['controller_manifest']), root)
    comparable = dict(lab.c)
    comparable['run_dir'] = old['run_dir']; comparable['controller_manifest'] = old['controller_manifest']
    need(comparable == old and lab.run.resolve() != Path(old['run_dir']).resolve(), 'only separate working run and controller may change')
    old_owned = json.loads(evidence['owned'])
    need(Path(binding['files']['owned']['path']).resolve() == Path(old['run_dir']).resolve() / 'owned.json', 'original ledger path differs')
    need(lab.state == old_owned and lab.state['uuid'] == UUID, 'exact owned ledger required')
    identities = load('candidate-identities')
    need(identities.scope_profile(lab.c)['source_sha'] == identities.E91, 'exact candidate91 required')
    receipt = json.loads(evidence['lifecycle_receipt'])
    need(receipt['exit_code'] == 1 and receipt['stdout_sha256'] == sha(evidence['lifecycle_out'])
         and receipt['stderr_sha256'] == sha(evidence['lifecycle_err']), 'failed lifecycle receipt differs')
    need(b'Authenticated console transport blocked' in evidence['lifecycle_err'], 'expected transport failure missing')
    old_sec = Path(old['run_dir']) / 'secrets'
    need(not (old_sec / ('transport-' + NONCE) / 'result').exists(), 'old transport has a result')
    need(sha(evidence['pending_capture']) == CAPTURE_SHA, 'known pending capture differs')
    text = evidence['pending_capture'].decode('utf-8')
    prompt = text.rstrip().splitlines()[-1].strip()
    need(re.fullmatch(r'LAB AUTH [A-F0-9]{16}:', prompt) and NONCE in text
         and console.sudo_prompt_ready(text, prompt), 'known nonce challenge not proven')
    binary = Path(binding['cancel_binary']).resolve()
    bound_external(new, binary)
    need(sha(raw(binary)) == binding['cancel_binary_sha256'], 'cancel binary differs')
    source = 'test/e2e/appliance/esxi/private-cancel.go'
    need(new['files'].get(source) == sha(raw(HERE / 'private-cancel.go')), 'cancel source not frozen')
    return binary, prompt


def save(path, value):
    with path.open('x', encoding='utf-8') as output:
        json.dump(value, output); output.flush(); os.fsync(output.fileno())


def cancel(lab, binding_path, dispatch=None):
    binary, prompt = validate(lab, binding_path)
    console.b.private_directory(lab)
    need(not (lab.run / 'visual-capture.lock').exists(), 'passive capture must finish first')
    directory = lab.sec / 'abandoned-transport-cancel'
    directory.mkdir()  # Exclusive one-shot, including ambiguous failures.
    observer = console.Console(lab)
    # Observe only. Never shell(), enter(), wait_shell() or generic keyboard send.
    deadline = time.monotonic() + 25
    while True:
        text = observer.screen(deadline)
        last = text.rstrip().splitlines()[-1].strip() if text.rstrip() else ''
        if last == prompt and console.sudo_prompt_ready(text, prompt): break
        need(time.monotonic() < deadline and last in (prompt + ' \ufffd', prompt + '\ufffd'),
             'fresh exact abandoned prompt unavailable')
        time.sleep(0.5)
    need(lab.vm(timeout=10)['runtime']['powerState'] == 'poweredOn', 'owned VM must be powered on')
    # Refresh after ownership observation; never act on a stale screen.
    text = observer.screen(time.monotonic()+15)
    need(text.rstrip().splitlines()[-1].strip() == prompt and console.sudo_prompt_ready(text,prompt), 'prompt changed')
    old = json.loads(raw(json.loads(raw(binding_path))['files']['scope']['path']))
    for name in ('visual-capture.lock', 'console-capture.lock', 'operation.lock', 'access-aware-qualify.lock', 'restore-qualification.lock'):
        need(not os.path.lexists(Path(old['run_dir']) / name), 'original run operation became active')
    intent = {'uuid': UUID, 'transport_nonce': NONCE, 'binding_sha256': sha(raw(binding_path)),
              'action': 'single-ctrl-c', 'time_ns': time.time_ns()}
    save(directory / 'intent.json', intent)
    payload = dict(reference=lab.state['ref']['value'], uuid=UUID, owner=lab.state['owner'])
    env = dict(lab._credential_env)
    env.update(GOVC_URL=lab.c['endpoint'], GOVC_PERSIST_SESSION='false',
               GOVC_INSECURE='true' if lab.c.get('tls_insecure') else 'false')
    operation = dispatch or subprocess.run
    result = operation([str(binary)], input=json.dumps(payload), env=env, capture_output=True, text=True, timeout=30)
    need(result.returncode == 0, 'cancellation ambiguous; no retry')
    deadline = time.monotonic()+60
    while time.monotonic() < deadline:
        text = observer.screen(deadline)
        if observer.shell_prompt(text):
            save(directory / 'complete.json', dict(intent, shell_verified=True, completed_ns=time.time_ns()))
            return
        time.sleep(0.5)
    raise ValueError('clean shell unverified after one cancellation; no retry')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--binding', type=Path, required=True)
    args = parser.parse_args()
    try:
        lab = console.b.module.Lab(args.scope)
        console.b.module.validate_scope(lab.c)
        with console.b.module.locked(lab.run): cancel(lab,args.binding)
        print('Abandoned transport cancelled once; clean shell verified. Original failure retained.')
        return 0
    except Exception:
        print('BLOCKED: cancellation unverified; preserve private evidence; no retry.',file=sys.stderr)
        return 90


if __name__ == '__main__': sys.exit(main())
