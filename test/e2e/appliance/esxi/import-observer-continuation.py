#!/usr/bin/env python3
"""One-shot continuation of the exact 7c import stopped before first power-on.

Prepare a new observer nonce, then power only after that observer arms. Never
import again, overwrite the original preflight, or retry an ambiguous power-on.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import sys

HERE = Path(__file__).resolve().parent
ORIGINAL = '76125c09ecd3e4858402e30f3639e1923b8c8316'
SOURCE = '7c7b29ee3be40af6a0809c73ad04d4337303263d'
FILES = ('scope', 'manifest', 'preflight', 'owned', 'import_receipt', 'import_out',
         'import_err', 'observer_out', 'observer_err')
STOP = 'visual observer not ready; imported VM remains powered off'


def need(ok, message):
    if not ok: raise ValueError(message)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def raw(path):
    need(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024,
         'bounded regular original evidence required')
    return path.read_bytes()


def sha(data): return hashlib.sha256(data).hexdigest()


def paths(root, oldscope):
    run = Path(oldscope['run_dir'])
    ops = root / '.tools/private-operations'
    return dict(scope=root / '.tools/scope-7c-source.json',
                manifest=Path(oldscope['controller_manifest']), preflight=run / 'evidence/preflight.json',
                owned=run / 'owned.json', import_receipt=ops / 'import.receipt.json',
                import_out=ops / 'import.out', import_err=ops / 'import.err',
                observer_out=ops / 'cold-capture.out', observer_err=ops / 'cold-capture.err')


def validate_binding(lab):
    """Read-only validation, also used by the passive observer after prepare."""
    binding = lab.c['visual_import_continuation']
    need(set(binding) == {'original_root', 'sha256'}, 'unexpected continuation fields')
    need(set(binding['sha256']) == set(FILES), 'all original evidence hashes required')
    root = Path(binding['original_root']).resolve()
    oldraw = raw(root / '.tools/scope-7c-source.json')
    need(sha(oldraw) == binding['sha256']['scope'], 'original scope changed')
    old = json.loads(oldraw)
    current = dict(lab.c); current.pop('visual_import_continuation')
    current['controller_manifest'] = old['controller_manifest']
    need(current == old and lab.c['controller_manifest'] != old['controller_manifest'],
         'only controller freeze and explicit continuation binding may change')
    profiles = module('import_candidate_profiles', HERE / 'candidate-identities.py')
    profile = profiles.scope_profile(lab.c)
    need(profile['source_sha'] == SOURCE and old['max_vms'] == 1 and old.get('credential_mode') == 'none',
         'exact default one-VM 7c scope required')
    locations = paths(root, old)
    directory = lab.sec / 'import-observer-continuation'
    evidence = {}
    for name, path in locations.items():
        # The import ledger is saved before rotating its rendezvous nonce. Its
        # immutable copy remains the original evidence after preparation.
        if name == 'owned' and directory.exists(): path = directory / 'original-owned.json'
        evidence[name] = raw(path)
        need(sha(evidence[name]) == binding['sha256'][name], 'original ' + name + ' evidence changed')
    freeze = json.loads(evidence['manifest'])
    need(freeze['revision'] == ORIGINAL, 'exact original controller required')
    module('import_freeze', HERE / 'controller-freeze.py').verify(locations['manifest'], root)
    preflight = json.loads(evidence['preflight'])
    need(preflight['harness_sha'] == ORIGINAL and preflight['harness_dirty'] is False
         and preflight['controller_freeze'] == freeze and preflight['expected_source'] == SOURCE
         and preflight['expected_image'] == profile['image_id']
         and preflight['artifact']['ova_sha256'] == profile['ova_sha256'], 'original preflight differs')
    receipt = json.loads(evidence['import_receipt'])
    need(receipt['exit_code'] == 3 and receipt['stdout_sha256'] == sha(evidence['import_out'])
         and receipt['stderr_sha256'] == sha(evidence['import_err']), 'import did not stop with bound evidence')
    need(evidence['import_err'] == b'' and evidence['import_out'].decode().splitlines()[-1] == 'BLOCKED: up: ' + STOP,
         'import did not stop at the reviewed observer boundary')
    need(evidence['observer_out'] == b'' and evidence['observer_err'].decode().strip() ==
         'BLOCKED: private visual capture stopped; preserve evidence and reconcile ownership.',
         'original observer failure differs')
    owned = json.loads(evidence['owned'])
    visual = module('import_visual', HERE / 'visual-capture.py')
    need(owned['phase'] == 'imported' and owned.get('visual_capture_nonce'), 'original imported ledger required')
    pinned = visual.identity(owned)
    need(visual.identity(lab.state) == pinned, 'owned VM identity changed')
    need(owned['endpoint'] == old['endpoint'], 'original endpoint differs')
    return owned


def untouched(lab):
    for pattern in ('bootstrap*', 'access-bootstrap*', 'operator-*', 'known_hosts', 'transport*',
                    'p1-regressions*', 'signed-update*', 'production-*'):
        need(not list(lab.sec.glob(pattern)), 'guest access or mutation has already started')


def save(path, value):
    with path.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(value, output, sort_keys=True); output.write('\n')


def prepare(lab):
    old = validate_binding(lab)
    untouched(lab)
    need(lab.state == old and lab.vm(timeout=15)['runtime']['powerState'] == 'poweredOff',
         'exact imported and powered-off VM required')
    need(not (lab.sec / ('visual-' + lab.c['visual_capture_label'])).exists(), 'original visual sequence already exists')
    directory = lab.sec / 'import-observer-continuation'
    directory.mkdir(mode=0o700)
    with (directory / 'original-owned.json').open('xb') as output:
        output.write(raw(lab.state_file))
    nonce = secrets.token_hex(16)
    save(directory / 'prepared.json', {'schema': 1, 'scope_sha256': sha(raw(lab.scope_path)),
         'original_sha256': lab.c['visual_import_continuation']['sha256'],
         'owner_uuid': old['uuid'], 'new_nonce': nonce, 'old_nonce': old['visual_capture_nonce']})
    lab.state['visual_capture_nonce'] = nonce
    lab.save()


def power_on(lab, adapter):
    old = validate_binding(lab)
    untouched(lab)
    directory = lab.sec / 'import-observer-continuation'
    prepared = json.loads(raw(directory / 'prepared.json'))
    need(prepared['scope_sha256'] == sha(raw(lab.scope_path)) and prepared['owner_uuid'] == lab.state['uuid']
         and prepared['original_sha256'] == lab.c['visual_import_continuation']['sha256']
         and prepared['old_nonce'] == old['visual_capture_nonce']
         and prepared['new_nonce'] == lab.state['visual_capture_nonce']
         and prepared['new_nonce'] != prepared['old_nonce'], 'new observer nonce binding differs')
    need(lab.state['phase'] == 'imported' and lab.vm(timeout=15)['runtime']['powerState'] == 'poweredOff',
         'first power-on only; no retry')
    need(not (directory / 'power-intent.json').exists(), 'power-on already attempted; no retry')
    adapter.wait_visual_capture(lab)
    need(lab.vm(timeout=15)['runtime']['powerState'] == 'poweredOff', 'power state changed before dispatch')
    adapter.wait_visual_capture(lab)  # Refresh the five-second arm after the API observation.
    save(directory / 'power-intent.json', prepared)
    lab.gov('vm.power', '-on', lab.state['path'], json_output=False)
    lab.state['phase'] = 'powered-on'; lab.save()
    save(directory / 'power-complete.json', {'owner_uuid': lab.state['uuid'], 'scope_sha256': prepared['scope_sha256']})
    lab.record('observer-continuation-power-on', 'pass', 'Original observer failure retained; new frozen observer armed before first power-on.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('prepare', 'power-on'))
    parser.add_argument('--scope', type=Path, required=True)
    args = parser.parse_args()
    try:
        adapter = module('import_adapter', HERE / 'esxi-lab.py')
        lab = adapter.Lab(args.scope)
        adapter.validate_scope(lab.c)
        with adapter.locked(lab.run):
            if args.action == 'prepare': prepare(lab)
            else: power_on(lab, adapter)
        print('Imported-off observer continuation ' + args.action + ' complete.')
        return 0
    except Exception:
        print('BLOCKED: import observer continuation stopped; preserve all evidence; no automatic retry.', file=sys.stderr)
        return 90


if __name__ == '__main__': sys.exit(main())
