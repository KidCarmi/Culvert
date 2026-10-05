#!/usr/bin/env python3
"""Capture guest timing through an existing authenticated console session.

Preload helpers before freeze; no login retry, power operation or product change.
Example: --scope S --bind CONTROLLER_LAN_IP --label after-reboot
Raw stdout/stderr remain under the ACL-checked run secrets directory.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import sys

from timing_capture import HERE, LIMIT, capture, destinations, load_lab, utc, write_summary


def summarize(raw):
    if len(raw) > LIMIT:
        raise ValueError('oversized observation')
    lines = raw.splitlines()
    if not 2 <= len(lines) <= 64:
        raise ValueError('invalid observation count')
    rows = [json.loads(line) for line in lines]
    if (not all(isinstance(row, dict) for row in rows)
            or rows[0].get('event') != 'guest_timing_started'
            or rows[-1].get('event') != 'guest_timing_finished'):
        raise ValueError('incomplete observation')
    timings, failures = [], 0
    for row in rows:
        result = row.get('result')
        if result not in (None, 'ok'):
            failures += 1
        if row.get('event') != 'backup_timing':
            continue
        if row.get('probe') not in ('agent_backups', 'compose_backups'):
            raise ValueError('unknown timing probe')
        seconds = row.get('elapsed_seconds')
        if type(seconds) not in (int, float) or not 0 <= seconds <= 180:
            raise ValueError('invalid duration')
        item = {'probe': row['probe'], 'elapsed_seconds': seconds,
                'result': result if result in ('ok', 'timeout', 'oversize', 'command_failed',
                    'spawn_failed', 'invalid_response') else 'unknown',
                'listing_succeeded': row.get('listing_succeeded') is True}
        if type(row.get('http_status')) is int and 100 <= row['http_status'] <= 599:
            item['http_status'] = row['http_status']
        if type(row.get('entry_count')) is int and 0 <= row['entry_count'] <= 100000:
            item['entry_count'] = row['entry_count']
        timings.append(item)
    return {'complete': True, 'observation_error_count': failures, 'backup_timings': timings}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scope', type=Path, required=True)
    parser.add_argument('--bind', required=True)
    parser.add_argument('--label', required=True)
    parser.add_argument('--samples', type=int, choices=range(1, 4), default=2)
    parser.add_argument('--timeout', type=int, choices=range(5, 31), default=25)
    args = parser.parse_args(argv)
    ipaddress.IPv4Address(args.bind)
    lab = load_lab(args.scope)
    lab.vm(timeout=20)
    raw, stderr, summary = destinations(lab, args.label, 'guest-timing')
    source = (HERE / 'timing-diagnostic-guest.py').read_bytes()
    if len(source) > 64 * 1024:
        raise ValueError('guest source bound')
    script = (f"python3 - --samples {args.samples} --timeout {args.timeout} <<'CULVERT_GUEST_TIMING'\n".encode()
              + source + b'\nCULVERT_GUEST_TIMING\n')
    report = {'schema_version': 1, 'started_at': utc(),
              'guest_source_sha256': hashlib.sha256(source).hexdigest()}
    report['transport'] = capture([sys.executable, str(HERE / 'console-priv.py'), '--scope',
        str(args.scope), '--bind', args.bind, '--timeout', '300'], script, raw, stderr, 420)
    report['finished_at'] = utc()
    try:
        report.update(summarize(raw.read_bytes()))
        if len(report['backup_timings']) != 2 * args.samples:
            report.update(complete=False, diagnosis='missing_backup_timing_samples')
    except (ValueError, UnicodeError):
        report.update(complete=False, diagnosis='invalid_or_incomplete_private_observation')
    write_summary(summary, report)
    print('Guest timing capture recorded; raw evidence remains private.')
    return 0 if report['complete'] and report['transport']['exit_code'] == 0 else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        print('Guest timing capture blocked; no raw details exported.', file=sys.stderr)
        sys.exit(90)
