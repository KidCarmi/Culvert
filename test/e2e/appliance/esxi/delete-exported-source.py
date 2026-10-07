#!/usr/bin/env python3
"""Delete only the exported, P1-qualified source VM and prove its disk folder gone.

No guest operations. This is an explicit one-shot destructive lab stage, never
an automatic retry/cleanup fallback. Private escrow remains outside the run.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import sys


HERE = Path(__file__).resolve().parent
SOURCE = 'b579ca28c9d936e9141292ce5ec564a26feeae86'
OVA = '1a713a9bedc4ee50ac4212c12048924e03abe6b8f04cb82d4d0ef95e33ef4775'
P1_STAGES = ('network-before', 'network-after', 'identity-before', 'identity-reset',
             'identity-power-on', 'identity-bootstrap', 'identity-after')


def require(value, message):
    if not value:
        raise ValueError(message)


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


campaigns = module('delete_p1_campaigns', HERE / 'p1-campaign.py')


def reference(value):
    require(isinstance(value, dict) and value.get('type') == 'Datastore'
            and isinstance(value.get('value'), str) and value['value'], 'datastore reference missing')
    return {'type': value['type'], 'value': value['value']}


def datastore_path(value, datastore):
    require(isinstance(value, str), 'datastore file path missing')
    match = re.fullmatch(r'\[([^\[\]\r\n]+)\] ([^\r\n\\]+)', value)
    require(match and match[1] == datastore, 'disk path is outside authorized datastore')
    components = match[2].split('/')
    require(all(component not in ('', '.', '..') and not any(ord(c) < 32 for c in component)
                for component in components), 'unsafe datastore path components')
    return components


def disk_plan(vm, owned, ds):
    require(ds.get('name') and reference(ds['self']) == reference(owned['ds_ref']), 'authorized datastore identity drift')
    name = ds['name']
    require(vm['config']['uuid'] == owned['uuid'] and vm['name'] == owned['name'], 'VM identity changed')
    config = datastore_path(vm['config']['files']['vmPathName'], name)
    require(len(config) == 2 and config[0] == owned['name'] and config[1].endswith('.vmx'), 'VM configuration is not in its own folder')
    devices = vm['config']['hardware']['device']
    require(isinstance(devices, list) and devices, 'hardware inventory missing')
    paths = []
    for device in devices:
        require(isinstance(device, dict), 'ambiguous hardware device')
        require(device.get('sharedBus', 'noSharing') == 'noSharing', 'shared disk controller refused')
        # govc vm.info uses encoding/json, without VMOMI _typeName markers.
        # capacityInKB is a required, non-omitempty VirtualDisk field.
        if 'capacityInKB' not in device:
            require('capacityInBytes' not in device and device.get('_typeName') != 'VirtualDisk'
                    and 'diskMode' not in device.get('backing', {}), 'unknown disk type')
            continue
        require(device.get('_typeName', 'VirtualDisk') == 'VirtualDisk'
                and type(device['capacityInKB']) is int and device['capacityInKB'] > 0, 'unknown disk type')
        backing = device.get('backing', {})
        # These provisioning fields identify FlatVer2 in the generated types.
        # Refuse missing type evidence instead of guessing that an RDM is local.
        require(isinstance(backing, dict)
                and backing.get('_typeName', 'VirtualDiskFlatVer2BackingInfo') == 'VirtualDiskFlatVer2BackingInfo'
                and any(type(backing.get(k)) is bool for k in ('thinProvisioned', 'eagerlyScrub'))
                and set(backing) <= {'_typeName', 'fileName', 'datastore', 'backingObjectId', 'diskMode',
                    'split', 'writeThrough', 'thinProvisioned', 'eagerlyScrub', 'uuid', 'contentId', 'changeId',
                    'parent', 'deltaDiskFormat', 'digestEnabled', 'deltaGrainSize', 'deltaDiskFormatVariant',
                    'sharing', 'keyId'}
                and backing.get('diskMode') == 'persistent' and not backing.get('parent')
                and backing.get('sharing', 'sharingNone') == 'sharingNone'
                and backing.get('split') is not True and device.get('nativeUnmanagedLinkedClone') is not True,
                'shared, linked, split or unsupported disk backing refused')
        require(reference(backing.get('datastore')) == reference(owned['ds_ref']), 'disk datastore differs')
        path = backing.get('fileName')
        parts = datastore_path(path, name)
        require(len(parts) == 2 and parts[0] == owned['name'] and parts[1].endswith('.vmdk'),
                'external disk path refused')
        paths.append(path)
    require(paths and len(paths) == len(set(paths)), 'missing or duplicate disk backing')
    return {'datastore': name, 'folder': owned['name'], 'source_disk_paths': sorted(paths)}


def root_listing(listing, datastore, ds_ref):
    require(isinstance(listing, list) and len(listing) == 1, 'datastore root listing missing or ambiguous')
    row = listing[0]
    require(isinstance(row, dict) and row.get('folderPath', '').strip() in ('[' + datastore + ']', '[' + datastore + '] /'),
            'datastore listing is not the expected root')
    if 'datastore' in row:
        require(reference(row['datastore']) == reference(ds_ref), 'listing datastore changed')
    require(isinstance(row.get('file'), list), 'explicit datastore file inventory missing')
    entries = {}
    for entry in row['file']:
        require(isinstance(entry, dict) and isinstance(entry.get('path'), str), 'unknown datastore root entry')
        path = entry['path']
        require(path and '\\' not in path and not any(ord(c) < 32 for c in path), 'invalid root entry path')
        basename = path[:-1] if path.endswith('/') else path
        require('/' not in basename and basename not in ('', '.', '..') and basename not in entries,
                'ambiguous datastore entry')
        # cli/datastore/ls.go appends '/' only for FolderFileInfo with -p.
        # Its standard encoding/json MarshalJSON omits dynamic type names.
        entries[basename] = 'FolderFileInfo' if path.endswith('/') else 'FileInfo'
    return entries


def validate_deletion(before, after, plan, ds_ref):
    old = root_listing(before, plan['datastore'], ds_ref)
    new = root_listing(after, plan['datastore'], ds_ref)
    require(old.get(plan['folder']) == 'FolderFileInfo', 'owned folder was not observed before deletion')
    require(plan['folder'] not in new, 'owned datastore folder still exists')


def atomic_new(path, value):
    """Publish complete bytes exclusively; a partial receipt can never look ready."""
    raw = (json.dumps(value, indent=2) + '\n').encode()
    staged = path.parent / ('.' + path.name + '.' + secrets.token_hex(12) + '.pending')
    try:
        with staged.open('xb') as out:
            out.write(raw); out.flush(); os.fsync(out.fileno())
        os.link(staged, path)  # Same-directory atomic create, refuses existing target.
    finally:
        if staged.exists():
            staged.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--escrow', type=Path, required=True)
    parser.add_argument('--campaign', choices=tuple(campaigns.NAMES), default='initial')
    args = parser.parse_args()
    fresh = module('delete_fresh_recovery', HERE / 'fresh-recovery.py')
    adapter = fresh.console.b.module
    lab = adapter.Lab(args.scope)
    started = False
    try:
        adapter.validate_scope(lab.c)
        profile = module('delete_candidate_identities', HERE / 'candidate-identities.py').scope_profile(lab.c)
        require(lab.c['max_vms'] == 1, 'exact one-VM scope required')
        campaigns.SOURCE = profile['source_sha']
        escrow = fresh.private_escrow(args.escrow, lab.run)
        require(not (escrow / 'source-deletion-receipt.json').exists()
                and not (escrow / 'source-deletion-attempt.json').exists(), 'previous deletion attempt exists; no retry')
        fresh.verify_export(escrow)
        exported = fresh.read_json(escrow / 'source-owned.json')
        require(all(exported.get(field) == lab.state.get(field) for field in ('uuid', 'path', 'endpoint', 'owner', 'ref', 'ds_ref'))
                and exported.get('uuid'), 'export belongs to another source VM')
        rows = []
        initial = campaigns.initial_failure(lab.sec, lab.state['uuid'], args.campaign)
        for stage in P1_STAGES:
            record = campaigns.effective_stage(lab.sec, args.campaign, stage, lab.state['uuid'])
            require(record.get('status') == 'pass' and record.get('uuid') == lab.state['uuid'], 'P1 qualification incomplete')
            require(record.get('campaign', 'initial') == args.campaign, 'P1 campaign mismatch')
            rows.append({'check': 'p1-' + stage, 'result': 'pass', 'continuation': record.get('continuation')})
        verdicts = {'schema': 1, 'source': profile['source_sha'], 'ova_sha256': profile['ova_sha256'], 'campaign': args.campaign,
                    'results': rows, 'initial_failure': initial}
        # These survive lab.down's private run cleanup; raw credentials do not.
        atomic_new(escrow / 'source-p1-verdicts.json', verdicts)
        atomic_new(lab.ev / 'source-p1-verdicts.json', verdicts)
        with adapter.locked(lab.run):
            vm = lab.vm(timeout=30)
            dss = lab.gov('datastore.info', lab.c['datastore'], timeout=30).get('datastores')
            require(isinstance(dss, list) and len(dss) == 1, 'authorized datastore ambiguous')
            ds = {'name': dss[0]['name'], 'self': dss[0]['self']}
            plan = disk_plan(vm, lab.state, ds)
            before = lab.gov('datastore.ls', '-l', '-a', '-p', '-H=false', '-ds', lab.c['datastore'], timeout=60)
            require(root_listing(before, plan['datastore'], lab.state['ds_ref']).get(plan['folder']) == 'FolderFileInfo',
                    'owned folder absent before deletion')
            atomic_new(escrow / 'source-deletion-before.json', {'plan': plan, 'root_listing': before})
            atomic_new(escrow / 'source-deletion-attempt.json', {'schema': 1, 'status': 'started', 'source_uuid': lab.state['uuid']})
            started = True
            original = dict(lab.state)
            require(disk_plan(lab.vm(timeout=30), lab.state, ds) == plan, 'disk backing changed before deletion')
            lab.down()  # Independently rechecks owner/UUID, destroys VM, confirms absence, cleans private run.
            absent = lab.gov('vm.info', original['path'], timeout=30)
            require(isinstance(absent, dict) and 'virtualMachines' in absent
                    and not absent['virtualMachines'], 'source VM absence not established')
            after = lab.gov('datastore.ls', '-l', '-a', '-p', '-H=false', '-ds', lab.c['datastore'], timeout=60)
            validate_deletion(before, after, plan, original['ds_ref'])
            require(lab.state.get('deleted') is True and lab.state.get('phase') == 'deleted', 'deletion ledger incomplete')
            atomic_new(escrow / 'source-deletion-after.json', {'root_listing': after})
            atomic_new(escrow / 'source-deleted-owned.json', lab.state)
            receipt = {'schema': 1, 'source_uuid': original['uuid'], 'source_path': original['path'],
                       'endpoint': lab.c['endpoint'], 'source_disks_deleted': True,
                       'source_disk_paths': plan['source_disk_paths'], 'one_vm_limit': 1}
            atomic_new(escrow / 'source-deletion-receipt.json', receipt)
            adapter.atomic_json(escrow / 'source-deletion-attempt.json', {'schema': 1, 'status': 'pass', 'source_uuid': original['uuid']})
        print('PASS: exported source VM absent and its previously observed datastore disk folder removed.')
        return 0
    except Exception:
        if started:
            adapter.atomic_json(escrow / 'source-deletion-attempt.json', {'schema': 1, 'status': 'blocked', 'source_uuid': lab.state.get('uuid')})
        print('BLOCKED: source deletion not fully proven; preserve escrow and inventory evidence; no retry.', file=sys.stderr)
        return 90


if __name__ == '__main__':
    sys.exit(main())
