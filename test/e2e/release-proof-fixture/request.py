#!/usr/bin/env python3
"""Attach independently signed test evidence to one small agent request on stdin."""
import argparse
import json
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proofs', required=True)
    parser.add_argument('--prior')
    args = parser.parse_args()
    with open(args.proofs, encoding='utf-8') as source:
        proofs = json.load(source)
    raw = sys.stdin.read(16385)
    if len(raw) > 16384:
        raise ValueError('fixture request is oversized')
    request = json.loads(raw)
    request['release_proof'] = proofs[request['image_ref']]
    request.pop('prior_release_proof', None)
    if args.prior:
        request['prior_release_proof'] = proofs[args.prior]
    print(json.dumps(request, separators=(',', ':')))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError):
        sys.exit('Cannot construct signed fixture request; no payload reported.')
