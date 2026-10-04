"""Synthetic deletion evidence only; never invoke ESXi or delete a VM."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location('delete_exported_source', Path(__file__).with_name('delete-exported-source.py'))
deletion = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deletion)


DS = {'type': 'Datastore', 'value': 'datastore-1'}
OWNED = {'name': 'culvert-esxi-synthetic', 'uuid': 'synthetic-uuid', 'ds_ref': DS}


def vm():
    return {'name': OWNED['name'], 'config': {'uuid': OWNED['uuid'],
            'files': {'vmPathName': '[DataStore2] culvert-esxi-synthetic/culvert-esxi-synthetic.vmx'},
            'hardware': {'device': [{'capacityInKB': 40 * 1024 * 1024,
                                    'backing': {'thinProvisioned': True, 'datastore': DS,
                                                'fileName': '[DataStore2] culvert-esxi-synthetic/disk.vmdk',
                                                'diskMode': 'persistent', 'sharing': 'sharingNone'}}]}}}


def listing(present):
    entries = [{'path': 'another-folder/'}]
    if present:
        entries.append({'path': 'culvert-esxi-synthetic/'})
    return [{'folderPath': '[DataStore2] ', 'datastore': DS, 'file': entries}]


class DeletionEvidenceTests(unittest.TestCase):
    def test_observed_owned_folder_must_disappear(self):
        plan = deletion.disk_plan(vm(), OWNED, {'name': 'DataStore2', 'self': DS})
        deletion.validate_deletion(listing(True), listing(False), plan, DS)
        for before, after in [(listing(False), listing(False)), (listing(True), listing(True)),
                              ([], listing(False)), (listing(True), []), (listing(True), {}),
                              (listing(True), [{'file': []}]),
                              (listing(True), [{'folderPath': '[DataStore2] '}]),
                              (listing(True), [{'folderPath': '[wrong] ', 'file': []}])]:
            with self.subTest(before=before, after=after):
                with self.assertRaises(ValueError):
                    deletion.validate_deletion(before, after, plan, DS)

    def test_external_shared_linked_and_ambiguous_disks_refused(self):
        for field, value in [('fileName', '[DataStore2] other/disk.vmdk'),
                             ('fileName', '[external] culvert-esxi-synthetic/disk.vmdk'),
                             ('fileName', '[DataStore2] culvert-esxi-synthetic/../disk.vmdk'),
                             ('parent', {'fileName': '[DataStore2] parent/base.vmdk'}),
                             ('sharing', 'sharingMultiWriter'), ('diskMode', 'independent_persistent'),
                             ('deviceName', '/vmfs/devices/disks/raw'), ('thinProvisioned', None),
                             ('_typeName', 'VirtualDiskRawDiskMappingVer1BackingInfo')]:
            bad = vm()
            bad['config']['hardware']['device'][0]['backing'][field] = value
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    deletion.disk_plan(bad, OWNED, {'name': 'DataStore2', 'self': DS})
        for devices in ([], [{'_typeName': 'UnknownDisk', 'capacityInKB': 42}],
                        [vm()['config']['hardware']['device'][0]] * 2):
            bad = vm()
            bad['config']['hardware']['device'] = devices
            with self.assertRaises(ValueError):
                deletion.disk_plan(bad, OWNED, {'name': 'DataStore2', 'self': DS})

    def test_duplicate_or_unknown_root_entries_refused(self):
        bad = listing(True)
        bad[0]['file'].append(copy.deepcopy(bad[0]['file'][0]))
        with self.assertRaises(ValueError):
            deletion.root_listing(bad, 'DataStore2', DS)
        bad = listing(True)
        bad[0]['file'][0].pop('path')
        with self.assertRaises(ValueError):
            deletion.root_listing(bad, 'DataStore2', DS)
        bad = listing(True)
        bad[0]['file'][1]['path'] = 'culvert-esxi-synthetic'
        plan = deletion.disk_plan(vm(), OWNED, {'name': 'DataStore2', 'self': DS})
        with self.assertRaises(ValueError):
            deletion.validate_deletion(bad, listing(False), plan, DS)

    def test_receipt_is_exclusive_and_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'receipt.json'
            deletion.atomic_new(target, {'source_disks_deleted': True})
            self.assertEqual(json.loads(target.read_text()), {'source_disks_deleted': True})
            with self.assertRaises(FileExistsError):
                deletion.atomic_new(target, {'source_disks_deleted': False})
            self.assertEqual(json.loads(target.read_text()), {'source_disks_deleted': True})
            self.assertEqual(list(Path(directory).iterdir()), [target])


if __name__ == '__main__':
    unittest.main()
