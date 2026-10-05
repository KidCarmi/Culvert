#!/usr/bin/env python3
"""Read-only host device metrics bound to the owned VM's approved VMFS datastore.

Raw evidence stays in SEC. Public output contains device SHA256 identities only.
Device counters include other workloads sharing the backing device; they cannot
attribute contention to a VM or prove storage causation. No workload is stopped.
"""
import argparse
import datetime
import hashlib
import json
import math
from pathlib import Path
import re
import sys

from timing_capture import LIMIT, destinations, load_lab, utc, write_summary

METRICS = {'disk.' + name + '.average': unit for names, unit in (
    (('deviceReadLatency', 'kernelReadLatency', 'queueReadLatency',
      'deviceWriteLatency', 'kernelWriteLatency', 'queueWriteLatency'), 'millisecond'),
    (('read', 'write'), 'kiloBytesPerSecond'),
    (('numberReadAveraged', 'numberWriteAveraged'), 'number')) for name in names}


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('invalid timestamp')
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset() != datetime.timedelta(0):
        raise ValueError('UTC timestamp required')
    return result


def bind_devices(datastore, host, storage, state):
    stores, hosts = datastore.get('datastores'), host.get('hostSystems')
    if not isinstance(stores, list) or len(stores) != 1 or not isinstance(hosts, list) or len(hosts) != 1:
        raise ValueError('one approved host and datastore required')
    ds, hs = stores[0], hosts[0]
    if ds.get('self') != state['ds_ref'] or hs.get('self') != state['host_ref']:
        raise ValueError('approved inventory reference mismatch')
    if storage.get('self') != hs.get('configManager', {}).get('storageSystem') or not storage.get('self'):
        raise ValueError('storage system not bound to approved host')
    mounts = [x for x in ds.get('host', []) if x.get('key') == state['host_ref']]
    if (len(mounts) != 1 or mounts[0].get('mountInfo', {}).get('mounted') is not True
            or mounts[0].get('mountInfo', {}).get('accessible') is not True):
        raise ValueError('approved datastore not mounted and accessible')
    vmfs = ds.get('info', {}).get('vmfs', {})
    extents = vmfs.get('extent')
    if vmfs.get('type') != 'VMFS' or not isinstance(extents, list) or not 1 <= len(extents) <= 8:
        raise ValueError('bounded VMFS extents required')
    devices, seen_extents = {}, set()
    luns = storage.get('storageDeviceInfo', {}).get('scsiLun', [])
    if not isinstance(luns, list) or len(luns) > 2048:
        raise ValueError('device inventory bound')
    for extent in extents:
        name, partition = extent.get('diskName'), extent.get('partition')
        if (not isinstance(name, str) or not re.fullmatch(r'(?:naa|eui|t10|mpx|nvme)\.[A-Za-z0-9_.:-]{1,240}', name)
                or type(partition) is not int or not 1 <= partition <= 128
                or (name, partition) in seen_extents):
            raise ValueError('invalid or duplicate extent identity')
        seen_extents.add((name, partition))
        matches = [x for x in luns if x.get('canonicalName') == name]
        if len(matches) != 1 or matches[0].get('deviceType') != 'disk':
            raise ValueError('extent lacks unique canonical host disk')
        devices.setdefault(name, []).append(partition)
    # Only the approved binding is retained; other datastore VM inventory and
    # host device names are deliberately excluded even from our raw projection.
    return {'datastore_ref': ds['self'], 'host_ref': hs['self'], 'storage_ref': storage['self'],
            'devices': [{'canonical_name': name, 'partitions': sorted(parts)}
                        for name, parts in sorted(devices.items())]}


def supported_metrics(metadata):
    supported = []
    for name, expected_unit in METRICS.items():
        if name not in metadata:
            continue
        counter = metadata[name].get('counter', {})
        actual = '.'.join((counter.get('groupInfo', {}).get('key', ''),
                           counter.get('nameInfo', {}).get('key', ''), counter.get('rollupType', '')))
        if actual != name or counter.get('unitInfo', {}).get('key') != expected_unit:
            raise ValueError('counter metadata identity or unit mismatch')
        expected_type = 'rate' if expected_unit in ('number', 'kiloBytesPerSecond') else 'absolute'
        if counter.get('statsType') != expected_type:
            raise ValueError('counter aggregation semantics mismatch')
        supported.append(name)
    return supported


def summarize(data, expected_ref, device, names, start, end, requested_samples):
    samples = data.get('sample')
    if not isinstance(samples, list) or len(samples) != 1 or samples[0].get('entity') != expected_ref:
        raise ValueError('metrics not bound to approved host')
    info, series = samples[0].get('sampleInfo'), samples[0].get('value')
    if (not isinstance(info, list) or not 1 <= len(info) <= requested_samples <= 180
            or not isinstance(series, list) or len(series) > len(METRICS)):
        raise ValueError('metric sample bound')
    if any(type(x.get('interval')) is not int or x['interval'] != 20 for x in info):
        raise ValueError('realtime 20-second interval required')
    times = [timestamp(x['timestamp']) for x in info]
    if times != sorted(set(times)):
        raise ValueError('sample times must be unique and ordered')
    gaps = []
    for previous, current in zip(times, times[1:]):
        elapsed = (current - previous).total_seconds()
        if elapsed % 20:
            raise ValueError('sample timestamps not aligned to realtime interval')
        if elapsed > 20:
            gaps.append({'after': previous.isoformat(), 'before': current.isoformat(),
                         'missing_slots': int(elapsed / 20) - 1})
    selected = [i for i, t in enumerate(times) if start is None or start <= t <= end]
    metrics, seen = [], set()
    for item in series:
        name = item.get('name')
        if (name not in names or item.get('instance') != device or name in seen
                or item.get('unit') != METRICS[name]):
            raise ValueError('unexpected metric or device instance')
        seen.add(name)
        values = item.get('value')
        if not isinstance(values, list) or len(values) != len(times):
            raise ValueError('metric sample length')
        if any(type(v) not in (int, float) or not math.isfinite(v) or (v < 0 and v != -1) for v in values):
            raise ValueError('invalid counter value')
        valid = [(times[i], values[i]) for i in selected if values[i] >= 0]
        row = {'metric': name, 'unit': METRICS[name], 'selected_samples': len(selected),
               'valid_samples': len(valid), 'missing_samples': len(selected) - len(valid),
               'values': [values[i] if values[i] >= 0 else None for i in selected]}
        if valid:
            peak = max(valid, key=lambda x: x[1])
            row.update(sample_mean=round(sum(x[1] for x in valid) / len(valid), 4),
                       maximum_sample=peak[1], maximum_at=peak[0].isoformat())
        metrics.append(row)
    return {'device_sha256': hashlib.sha256(device.encode('ascii')).hexdigest(),
            'metrics': metrics, 'unavailable_metrics': sorted(set(METRICS) - seen),
            'returned_start': times[0].isoformat(), 'returned_end': times[-1].isoformat(),
            'selected_start': times[selected[0]].isoformat() if selected else None,
            'selected_end': times[selected[-1]].isoformat() if selected else None,
            'sample_times': [times[i].isoformat() for i in selected],
            'timestamp_gaps': gaps,
            'requested_window_covered': start is None or (times[0] <= start and times[-1] >= end),
            'empty_selected_window': not selected, 'interval_seconds': 20}


def capture(lab, samples, start=None, end=None):
    if type(samples) is not int or not 1 <= samples <= 180 or (start is None) != (end is None) or (start and start > end):
        raise ValueError('invalid sample request')
    lab.vm(timeout=20)
    def binding():
        return bind_devices(lab.gov('datastore.info', lab.c['datastore'], timeout=30),
                            lab.gov('host.info', lab.c['host'], timeout=30),
                            lab.gov('host.storage.info', '-host', lab.c['host'], timeout=30), lab.state)
    before = binding()
    raw = {'binding': before, 'metadata': {}, 'metadata_query_errors': [], 'samples': [], 'sample_query_errors': []}
    # A missing counter must not suppress supported counters. One bounded query
    # per name retains absence explicitly without exposing exception messages.
    for name in METRICS:
        try:
            value = lab.gov('metric.info', '-', name, timeout=15)
            if not isinstance(value, dict) or set(value) - {name}:
                raise ValueError('unexpected counter metadata')
            raw['metadata'].update(value)
        except Exception:
            raw['metadata_query_errors'].append(name)
    names = supported_metrics(raw['metadata'])
    summaries = []
    for device in before['devices']:
        name = device['canonical_name']
        try:
            if not names:
                raise ValueError('no supported counters')
            data = lab.gov('metric.sample', '-i=real', f'-n={samples}', '-t',
                           '-instance', name, lab.c['host'], *names, timeout=60)
            raw['samples'].append(data)
            summaries.append(summarize(data, lab.state['host_ref'], name, names, start, end, samples))
        except Exception:
            raw['sample_query_errors'].append(name)
            summaries.append({'device_sha256': hashlib.sha256(name.encode('ascii')).hexdigest(),
                              'result': 'unavailable_or_invalid_samples', 'unavailable_metrics': list(METRICS)})
    lab.vm(timeout=20)
    if binding() != before:
        raise ValueError('datastore extent binding changed during capture')
    return raw, {'devices': summaries, 'metadata_unavailable': sorted(set(METRICS) - set(names)),
                 'query_errors': {'metadata_count': len(raw['metadata_query_errors']),
                                  'device_count': len(raw['sample_query_errors'])},
                 'window_start': start.isoformat() if start else None,
                 'window_end': end.isoformat() if end else None,
                 'requested_samples': samples, 'required_interval_seconds': 20,
                 'complete': not raw['metadata_query_errors'] and not raw['sample_query_errors'] and
                             all(not d.get('empty_selected_window', True) and not d.get('unavailable_metrics') and
                                 d.get('requested_window_covered', False) and not d.get('timestamp_gaps') and
                                 all(m['missing_samples'] == 0 for m in d['metrics']) for d in summaries),
                 'note': 'Shared physical backing-device counters, not per-VM attribution or proof of cause. '
                         'Means/maxima summarize 20-second samples; missing values are null, never zero.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--samples', type=int, choices=range(1, 181), default=120)
    parser.add_argument('--start')
    parser.add_argument('--end')
    args = parser.parse_args(argv)
    start, end = timestamp(args.start) if args.start else None, timestamp(args.end) if args.end else None
    if (start is None) != (end is None) or (start and start > end):
        raise ValueError('invalid time window')
    lab = load_lab(args.scope)
    raw_path, _, summary_path = destinations(lab, args.label, 'host-storage')
    started = utc()
    raw, summary = capture(lab, args.samples, start, end)
    encoded = json.dumps(raw, separators=(',', ':')).encode('utf-8')
    if len(encoded) > LIMIT:
        raise ValueError('private raw result exceeds bound')
    with raw_path.open('xb') as stream:
        stream.write(encoded)
    report = dict(summary, schema_version=1, started_at=started, finished_at=utc(),
                  raw_sha256=hashlib.sha256(encoded).hexdigest())
    write_summary(summary_path, report)
    print('Approved datastore device metrics recorded; raw evidence remains private.')
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Host storage capture blocked; no private details exported.', file=sys.stderr)
        sys.exit(90)
