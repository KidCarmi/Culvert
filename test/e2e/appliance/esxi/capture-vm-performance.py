#!/usr/bin/env python3
"""Read-only performance snapshot for exactly the scoped, owned ESXi VM.

Run with distinct --label before-reboot/during-reboot/after-reboot labels.
--start and --end optionally restrict UTC sample timestamps (both required).
Without them the summary describes ALL returned samples, not just this boot.
No host counters, other VMs, configuration writes or power actions are queried.
"""
import argparse
import datetime
import json
import math
from pathlib import Path
import sys

from timing_capture import LIMIT, destinations, load_lab, utc, write_summary

METRICS = {
    'cpu.ready.summation': 'millisecond',
    'cpu.costop.summation': 'millisecond',
    'cpu.maxlimited.summation': 'millisecond',
    'mem.swapinRate.average': 'kiloBytesPerSecond',
    'mem.vmmemctl.average': 'kiloBytes',
    'virtualDisk.totalReadLatency.average': 'millisecond',
    'virtualDisk.totalWriteLatency.average': 'millisecond',
    'virtualDisk.read.average': 'kiloBytesPerSecond',
    'virtualDisk.write.average': 'kiloBytesPerSecond',
    'virtualDisk.numberReadAveraged.average': 'number',
    'virtualDisk.numberWriteAveraged.average': 'number',
}


def timestamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('invalid timestamp')
    parsed = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError('UTC timestamp required')
    return parsed


def summarize(data, expected_ref, start=None, end=None, required_interval=None):
    if (start is None) != (end is None) or (start and start > end):
        raise ValueError('invalid sample window')
    samples = data.get('sample')
    if not isinstance(samples, list) or len(samples) != 1 or samples[0].get('entity') != expected_ref:
        raise ValueError('performance response not bound to owned VM')
    sample = samples[0]
    info, series = sample.get('sampleInfo'), sample.get('value')
    if not isinstance(info, list) or not 1 <= len(info) <= 180 or not isinstance(series, list) or len(series) > 128:
        raise ValueError('sample count bound')
    times = [timestamp(item['timestamp']) for item in info]
    if len(set(times)) != len(times):
        raise ValueError('duplicate sample timestamps')
    intervals = set()
    for item in info:
        interval = item.get('interval')
        if type(interval) is not int or not 1 <= interval <= 86400:
            raise ValueError('invalid sampling interval')
        intervals.add(interval)
    if required_interval is not None and intervals != {required_interval}:
        raise ValueError('required realtime sample interval unavailable')
    selected = [i for i, time in enumerate(times) if start is None or start <= time <= end]
    result = []
    seen = set()
    for metric in series:
        name, instance = metric.get('name'), metric.get('instance', '')
        if name not in METRICS:
            continue
        # This appliance has one disk; retain total CPU and explicit CPU0/1.
        if instance not in ('', '0', '1', 'scsi0:0'):
            continue
        if metric.get('unit') != METRICS[name] or (name, instance) in seen:
            raise ValueError('metric unit or identity mismatch')
        seen.add((name, instance))
        values = metric.get('value')
        if not isinstance(values, list) or len(values) != len(info):
            raise ValueError('metric sample length mismatch')
        if any(type(value) not in (int, float) or not math.isfinite(value) or value < -1 for value in values):
            raise ValueError('invalid metric sample')
        valid = [(times[i], values[i]) for i in selected if values[i] >= 0]
        row = {'metric': name, 'unit': METRICS[name], 'instance': instance,
               'selected_samples': len(selected), 'valid_samples': len(valid),
               'missing_samples': len(selected) - len(valid)}
        if valid:
            peak = max(valid, key=lambda pair: pair[1])
            row.update(sample_mean=round(sum(value for _, value in valid) / len(valid), 4),
                       maximum_sample=peak[1], maximum_at=peak[0].isoformat())
        result.append(row)
    return {'metrics': result, 'unavailable_metrics': sorted(set(METRICS) - {row['metric'] for row in result}),
            'intervals_seconds': sorted(intervals),
            'returned_start': min(times).isoformat(), 'returned_end': max(times).isoformat(),
            'window_start': start.isoformat() if start else None,
            'window_end': end.isoformat() if end else None,
            'note': 'Means and maxima of available samples; missing samples excluded. '
                    'Not per-I/O percentiles, guest readiness timestamps or causal proof.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--samples', type=int, choices=range(1, 181), default=120)
    parser.add_argument('--start')
    parser.add_argument('--end')
    parser.add_argument('--require-realtime', action='store_true', help='Refuse a fallback interval other than 20 seconds')
    args = parser.parse_args(argv)
    start = timestamp(args.start) if args.start else None
    end = timestamp(args.end) if args.end else None
    if (start is None) != (end is None) or (start and start > end):
        raise ValueError('invalid sample window')
    lab = load_lab(args.scope)
    raw, _stderr, summary = destinations(lab, args.label, 'vm-performance')
    vm = lab.vm(timeout=20)
    report = {'schema_version': 1, 'started_at': utc()}
    data = lab.gov('metric.sample', '-i=real', f'-n={args.samples}', '-t', lab.state['path'], *METRICS, timeout=60)
    encoded = json.dumps(data).encode('utf-8')
    if len(encoded) > LIMIT:
        raise ValueError('raw performance bound')
    with raw.open('xb') as stream:
        stream.write(encoded)
    # Recheck ownership/placement following the query, before attributing it.
    lab.vm(timeout=20)
    try:
        report.update(summarize(data, vm['self'], start, end, 20 if args.require_realtime else None), complete=True)
    except (ValueError, TypeError, KeyError):
        report.update(complete=False, diagnosis='invalid_or_unattributable_metric_response')
    report['finished_at'] = utc()
    write_summary(summary, report)
    print('Owned-VM performance capture recorded; raw evidence remains private.')
    return 0 if report['complete'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Performance capture blocked; no raw details exported.', file=sys.stderr)
        sys.exit(90)
