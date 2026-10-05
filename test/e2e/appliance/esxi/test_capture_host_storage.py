"""Offline storage attribution/counter tests. No ESXi or VM calls."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('host_storage', Path(__file__).with_name('capture-host-storage.py'))
C = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(C)
HOST = {'type': 'HostSystem', 'value': 'host-synthetic'}
DS = {'type': 'Datastore', 'value': 'datastore-synthetic'}
STORAGE = {'type': 'HostStorageSystem', 'value': 'storage-synthetic'}
DEVICE = 'naa.0123456789abcdef'
TIMES = ['2026-10-05T01:00:00Z', '2026-10-05T01:00:20Z', '2026-10-05T01:00:40Z']


def fixtures():
    ds = {'datastores': [{'self': DS, 'vm': ['OTHER-VM-DO-NOT-EXPORT'],
                         'host': [{'key': HOST, 'mountInfo': {'mounted': True, 'accessible': True}}],
                         'info': {'vmfs': {'type': 'VMFS', 'extent': [{'diskName': DEVICE, 'partition': 1}]}}}]}
    host = {'hostSystems': [{'self': HOST, 'configManager': {'storageSystem': STORAGE},
                             'vm': ['OTHER-VM-DO-NOT-EXPORT']}]}
    storage = {'self': STORAGE, 'storageDeviceInfo': {'scsiLun': [
        {'canonicalName': DEVICE, 'deviceType': 'disk'},
        {'canonicalName': 'naa.other-unapproved', 'deviceType': 'disk'}]}}
    return ds, host, storage


def metadata():
    result = {}
    for name, unit in C.METRICS.items():
        group, key, rollup = name.split('.')
        result[name] = {'counter': {'groupInfo': {'key': group}, 'nameInfo': {'key': key},
                                  'rollupType': rollup, 'unitInfo': {'key': unit},
                                  'statsType': 'absolute' if unit == 'millisecond' else 'rate'}}
    return result


def data(values=None):
    return {'sample': [{'entity': HOST, 'sampleInfo': [{'timestamp': x, 'interval': 20} for x in TIMES],
                        'value': [{'name': name, 'unit': unit, 'instance': DEVICE,
                                   'value': values if values is not None else [3, 7, 5]}
                                  for name, unit in C.METRICS.items()]}]}


class StorageTests(unittest.TestCase):
    def test_binds_only_approved_extents_and_excludes_other_inventory(self):
        binding = C.bind_devices(*fixtures(), {'host_ref': HOST, 'ds_ref': DS})
        self.assertEqual(binding['devices'], [{'canonical_name': DEVICE, 'partitions': [1]}])
        self.assertNotIn('OTHER-VM', json.dumps(binding))
        self.assertNotIn('other-unapproved', json.dumps(binding))

    def test_host_datastore_storage_and_mount_mismatch_fail_closed(self):
        for index in range(5):
            ds, host, storage = fixtures()
            if index == 0:
                ds['datastores'][0]['self'] = {'value': 'other'}
            elif index == 1:
                host['hostSystems'][0]['self'] = {'value': 'other'}
            elif index == 2:
                storage['self'] = {'value': 'other'}
            elif index == 3:
                ds['datastores'][0]['host'][0]['mountInfo']['mounted'] = False
            else:
                ds['datastores'][0]['info']['vmfs']['type'] = 'NFS'
            with self.subTest(index=index), self.assertRaises(ValueError):
                C.bind_devices(ds, host, storage, {'host_ref': HOST, 'ds_ref': DS})

    def test_duplicate_or_unmatched_device_and_unsafe_instance_rejected(self):
        for kind in ('duplicate', 'missing', 'option', 'duplicate_extent'):
            ds, host, storage = fixtures()
            if kind == 'duplicate':
                storage['storageDeviceInfo']['scsiLun'].append({'canonicalName': DEVICE, 'deviceType': 'disk'})
            elif kind == 'missing':
                storage['storageDeviceInfo']['scsiLun'] = []
            elif kind == 'option':
                ds['datastores'][0]['info']['vmfs']['extent'][0]['diskName'] = '-instance=*'
            else:
                ds['datastores'][0]['info']['vmfs']['extent'] *= 2
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.bind_devices(ds, host, storage, {'host_ref': HOST, 'ds_ref': DS})

    def test_counter_unit_and_rate_metadata_checked(self):
        self.assertEqual(set(C.supported_metrics(metadata())), set(C.METRICS))
        altered = metadata()
        altered['disk.read.average']['counter']['unitInfo']['key'] = 'byte'
        with self.assertRaises(ValueError):
            C.supported_metrics(altered)
        altered = metadata()
        altered['disk.numberReadAveraged.average']['counter']['statsType'] = 'absolute'
        with self.assertRaises(ValueError):
            C.supported_metrics(altered)

    def test_window_null_missing_and_public_device_hash(self):
        result = C.summarize(data([3, -1, 9]), HOST, DEVICE, list(C.METRICS),
                             C.timestamp(TIMES[1]), C.timestamp(TIMES[2]), 3)
        self.assertNotIn(DEVICE, json.dumps(result))
        self.assertEqual(len(result['device_sha256']), 64)
        self.assertEqual(len(result['sample_times']), 2)
        for row in result['metrics']:
            self.assertEqual(row['values'], [None, 9])
            self.assertEqual(row['valid_samples'], 1)
            self.assertEqual(row['missing_samples'], 1)
            self.assertEqual(row['sample_mean'], 9)

    def test_wrong_host_device_interval_duplicates_and_invalid_values_rejected(self):
        for kind in ('host', 'device', 'interval', 'duplicate', 'nan', 'short', 'extra', 'count'):
            value = data()
            sample = value['sample'][0]
            if kind == 'host':
                sample['entity'] = DS
            elif kind == 'device':
                sample['value'][0]['instance'] = 'naa.other'
            elif kind == 'interval':
                sample['sampleInfo'][0]['interval'] = 300
            elif kind == 'duplicate':
                sample['sampleInfo'][1] = sample['sampleInfo'][0]
            elif kind == 'nan':
                sample['value'][0]['value'][0] = float('nan')
            elif kind == 'short':
                sample['value'][0]['value'] = [1]
            elif kind == 'extra':
                sample['value'][0]['name'] = 'unexpected'
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                C.summarize(value, HOST, DEVICE, list(C.METRICS), None, None, 2 if kind == 'count' else 3)

    def test_missing_metric_and_empty_window_explicit(self):
        value = data()
        value['sample'][0]['value'].pop()
        t = C.timestamp('2026-10-06T00:00:00Z')
        result = C.summarize(value, HOST, DEVICE, list(C.METRICS), t, t, 3)
        self.assertTrue(result['empty_selected_window'])
        self.assertEqual(len(result['unavailable_metrics']), 1)
        self.assertFalse(result['requested_window_covered'])

    def test_missing_timestamp_slots_and_partial_requested_window_explicit(self):
        value = data()
        value['sample'][0]['sampleInfo'][2]['timestamp'] = '2026-10-05T01:01:00Z'
        result = C.summarize(value, HOST, DEVICE, list(C.METRICS),
                             C.timestamp('2026-10-05T00:59:00Z'), C.timestamp(TIMES[2]), 3)
        self.assertEqual(result['timestamp_gaps'][0]['missing_slots'], 1)
        self.assertFalse(result['requested_window_covered'])

    def fake_lab(self):
        lab = mock.Mock()
        lab.c = {'host': '/approved-host', 'datastore': '/approved-datastore'}
        lab.state = {'host_ref': HOST, 'ds_ref': DS}
        ds, host, storage = fixtures()
        def gov(*args, **kwargs):
            if args[0] == 'datastore.info': return copy.deepcopy(ds)
            if args[0] == 'host.info': return copy.deepcopy(host)
            if args[0] == 'host.storage.info': return copy.deepcopy(storage)
            if args[0] == 'metric.info': return {args[-1]: metadata()[args[-1]]}
            if args[0] == 'metric.sample': return data()
            self.fail('unexpected command')
        lab.gov.side_effect = gov
        return lab

    def test_capture_readonly_ownership_twice_and_realtime_instance_bound(self):
        lab = self.fake_lab()
        raw, public = C.capture(lab, 3)
        self.assertTrue(public['complete'])
        self.assertEqual(lab.vm.call_count, 2)
        sample = next(x.args for x in lab.gov.call_args_list if x.args[0] == 'metric.sample')
        self.assertIn('-i=real', sample)
        self.assertIn('-n=3', sample)
        self.assertEqual(sample[sample.index('-instance') + 1], DEVICE)
        self.assertNotIn('OTHER-VM', json.dumps(raw))
        self.assertNotIn(DEVICE, json.dumps(public))

    def test_metadata_error_is_not_hidden_by_successful_other_metrics(self):
        lab = self.fake_lab()
        original = lab.gov.side_effect
        unavailable = next(iter(C.METRICS))
        def call(*args, **kwargs):
            if args[0] == 'metric.info' and args[-1] == unavailable:
                raise RuntimeError('private-canary')
            result = original(*args, **kwargs)
            if args[0] == 'metric.sample':
                result['sample'][0]['value'] = [x for x in result['sample'][0]['value'] if x['name'] != unavailable]
            return result
        lab.gov.side_effect = call
        raw, public = C.capture(lab, 3)
        self.assertFalse(public['complete'])
        self.assertIn(unavailable, public['metadata_unavailable'])
        self.assertNotIn('private-canary', json.dumps(raw) + json.dumps(public))

    def test_changed_extent_after_sampling_refuses_attribution(self):
        lab = self.fake_lab()
        original = lab.gov.side_effect
        calls = 0
        def call(*args, **kwargs):
            nonlocal calls
            value = original(*args, **kwargs)
            if args[0] == 'datastore.info':
                calls += 1
                if calls == 2:
                    value['datastores'][0]['info']['vmfs']['extent'][0]['partition'] = 2
            return value
        lab.gov.side_effect = call
        with self.assertRaises(ValueError): C.capture(lab, 3)


if __name__ == '__main__':
    unittest.main()
