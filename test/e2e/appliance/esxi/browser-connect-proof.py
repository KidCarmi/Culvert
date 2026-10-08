"""Extract bounded, credential-free CONNECT evidence from Chromium NetLog.

This proves the browser's tunnel exchange only. Pair it with browser response
and appliance identity/policy activity evidence; a CONNECT 200 alone is not
an origin response, authenticated identity, or TLS verification result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re

SEND = 'HTTP_TRANSACTION_SEND_TUNNEL_HEADERS'
RECEIVE = 'HTTP_TRANSACTION_READ_TUNNEL_RESPONSE_HEADERS'


def extract(document, authority, expected_status):
    if not re.fullmatch(r'[a-z0-9.-]+:[0-9]{1,5}', authority):
        raise ValueError('invalid expected authority')
    names = {v: k for k, v in document['constants']['logEventTypes'].items()}
    pending, rows = {}, []
    for event in document['events']:
        kind = names.get(event.get('type'), event.get('type'))
        source = event.get('source', {})
        key = (source.get('type'), source.get('id'))
        params = event.get('params', {})
        if kind == SEND:
            line = params.get('line', '').strip()
            if line != 'CONNECT ' + authority + ' HTTP/1.1':
                continue
            headers = params.get('headers', [])
            if not isinstance(headers, list):
                raise ValueError('unrecognized request headers')
            presented = any(str(h).lower().startswith(('proxy-authorization:', 'cookie:')) for h in headers)
            row = {'source_type': key[0], 'source_id': key[1], 'authority': authority,
                   'send_tick': event.get('time'), 'status': None,
                   'presented_cookie_or_proxy_credential': presented}
            rows.append(row)
            pending[key] = row
        elif kind == RECEIVE and key in pending:
            row = pending.pop(key)
            headers = params.get('headers', [])
            line = headers[0] if isinstance(headers, list) and headers else ''
            match = re.fullmatch(r'HTTP/1\.[01] ([0-9]{3})(?: .*?)?', line.strip())
            if match:
                row['status'] = int(match[1])
            row['receive_tick'] = event.get('time')
    return {'schema': 1, 'scope': 'browser CONNECT exchange only; requires origin and appliance activity evidence',
            'expected_status': expected_status, 'exchanges': rows,
            'pass': bool(rows) and all(r['status'] == expected_status and
                                      not r['presented_cookie_or_proxy_credential'] for r in rows)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('netlog', type=Path)
    parser.add_argument('--authority', default='example.com:443')
    parser.add_argument('--expected-status', type=int, choices=(200, 403, 407), required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    raw = args.netlog.read_bytes()
    proof = extract(json.loads(raw), args.authority, args.expected_status)
    proof['private_netlog_sha256'] = hashlib.sha256(raw).hexdigest()
    with args.out.open('x', encoding='utf-8', newline='\n') as output:
        json.dump(proof, output, indent=2)
        output.write('\n')
    return 0 if proof['pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
