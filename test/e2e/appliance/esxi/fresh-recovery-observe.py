"""Supported API/traffic oracles for the owned fresh-recovery fixture.

Called by fresh-recovery.py; no credentials on argv and no infrastructure
mutation. Historical logs use a separately encrypted supported export.
"""
import hashlib
import http.client
import http.cookiejar
import ipaddress
import json
import re
import ssl
import time
import urllib.request

HOSTS = ('pokerstars.com', 'bet365.com', 'pornhub.com', 'thepiratebay.org', '888casino.com')
MAX_RESPONSE = 4 * 1024 * 1024
LOG_LIMIT = {'result': 'blocked', 'reason': 'Supported Tier-1/Tier-2 backup excludes Tier-3 historical logs; retaining the log passphrase alone cannot recover them.'}


def require(value):
    if not value:
        raise ValueError('Fresh recovery behavioral oracle failed; inspect private evidence.')


class Client:
    def __init__(self, guest):
        require(ipaddress.ip_address(guest).version == 4)
        self.guest = guest
        self.origin = 'https://' + guest + ':9090'
        # Matches the explicitly accepted self-signed lab UI TLS policy. The
        # privileged binary transfer separately requires a pinned public key.
        context = ssl._create_unverified_context()
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, request, fp, code, msg, headers, newurl):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def raw(self, path, payload=None):
        request = urllib.request.Request(self.origin + path,
            data=None if payload is None else json.dumps(payload).encode(),
            headers={'Origin': self.origin, 'Content-Type': 'application/json'})
        with self.opener.open(request, timeout=30) as response:
            require(response.status == 200 and response.url == self.origin + path)
            data = response.read(MAX_RESPONSE + 1)
            require(len(data) <= MAX_RESPONSE)
            return data

    def api(self, path, payload=None):
        return json.loads(self.raw(path, payload))

    def traffic(self, host):
        connection = http.client.HTTPConnection(self.guest, 8080, timeout=30)
        try:
            connection.request('GET', 'http://' + host + '/', headers={'Host': host})
            response = connection.getresponse()
            return response.status  # Never follows redirects outside the proxy.
        finally:
            connection.close()

    def health(self):
        connection = http.client.HTTPConnection(self.guest, 8080, timeout=10)
        try:
            connection.request('GET', '/health')
            response = connection.getresponse()
            require(response.status == 200)
            data = response.read(MAX_RESPONSE + 1)
            require(len(data) <= MAX_RESPONSE)
            return json.loads(data)
        finally:
            connection.close()



def domain_allowlist_comparison(expected, response):
    """Read-only config equality; feed data itself is not a recovery oracle."""
    actual = response.get('domains') if isinstance(response, dict) else None
    valid = (isinstance(actual, list) and len(actual) <= 4096
             and all(isinstance(x, str) and 0 < len(x) <= 1024 for x in actual)
             and len(set(actual)) == len(actual))
    expected_valid = (isinstance(expected, list) and len(expected) <= 4096
                      and all(isinstance(x, str) and 0 < len(x) <= 1024 for x in expected)
                      and len(set(expected)) == len(expected))
    return {'schema': 1, 'result': 'pass' if valid and expected_valid and sorted(actual) == sorted(expected) else 'fail',
            'expected': expected, 'actual': actual, 'actual_valid': valid,
            'mutation_performed': False}


def read_domain_allowlist(guest, admin, password):
    client = Client(guest)
    client.api('/api/auth/login', {'user': admin, 'pass': password})
    return client.api('/api/security-scan/feeds/domain-allowlist')


def capture_domain_allowlist(guest, admin, password, record=None):
    response = read_domain_allowlist(guest, admin, password)
    actual = response.get('domains') if isinstance(response, dict) else None
    checked = domain_allowlist_comparison(actual, response)
    checked['source_canary_present'] = isinstance(actual, list) and 'example.com' in actual
    if not checked['source_canary_present']:
        checked['result'] = 'blocked'
        checked['reason'] = 'Intended source canary absent; custom-setting recovery not exercised.'
    if record is not None:
        record(checked)
    require(checked['result'] == 'pass' and checked['source_canary_present'])
    return sorted(actual)


def normalized_rules(policy):
    require(policy.get('draft') is False and policy.get('persisted') is True and policy.get('rules'))
    return [{k: v for k, v in rule.items() if k not in ('hitCount', 'lastHit')} for rule in policy['rules']]


def validate_history(markers, tag, expected_count=12):
    require(re.fullmatch(r'freshhist[a-f0-9]{16}', tag))
    require(markers.get('history') is True and markers.get('total') == expected_count)
    rows = markers.get('rows')
    require(isinstance(rows, list) and len(rows) == expected_count)
    expected = {tag + '-' + str(n) + '.invalid' for n in range(1, expected_count + 1)}
    require(all(isinstance(row, list) and len(row) == 4 and type(row[0]) is int and row[0] > 0
                and row[2:] == ['POLICY_DEFAULT_DENY', 'GET'] for row in rows))
    require({row[1] for row in rows} == expected)


def observe_history(guest, admin, password, baseline):
    validate_history(baseline['markers'], baseline['tag'])
    client = Client(guest)
    client.api('/api/auth/login', {'user': admin, 'pass': password})
    retention = client.api('/api/logs/retention')
    require(retention.get('enabled') is True and retention.get('encrypted') is True)
    data = client.api('/api/logs?source=store&filter=' + baseline['tag'] + '&limit=500')
    markers = {'history': data.get('history'), 'total': data.get('total'),
               'rows': sorted([[e.get(k) for k in ('ts', 'host', 'status', 'method')]
                               for e in data.get('logs') or []])}
    validate_history(markers, baseline['tag'])
    require(markers == baseline['markers'])
    require(client.traffic('example.com') == 200 and client.traffic('example.org') == 403)
    return {'schema': 1, 'result': 'pass', 'records': 12, 'identical': True,
            'archive_sha256': baseline['archive_sha256'], 'traffic': {'allow': 200, 'block': 403}}


def observe(guest, admin, password, baseline=None):
    client = Client(guest)
    deadline = time.monotonic() + 300
    while True:
        try:
            require(client.health().get('ssl_inspection') == 'ready')
            break
        except Exception:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)
    client.api('/api/auth/login', {'user': admin, 'pass': password})
    allowlist = None
    if baseline is not None and 'threat_domain_allowlist' in baseline:
        checked = domain_allowlist_comparison(baseline['threat_domain_allowlist'], client.api('/api/security-scan/feeds/domain-allowlist'))
        require(checked['result'] == 'pass')
        allowlist = sorted(checked['actual'])
    cert = ssl.PEM_cert_to_DER_cert(client.raw('/api/ca-cert').decode('ascii'))
    policy = normalized_rules(client.api('/api/policy'))
    require(any(r.get('name') == 'lab-allow-example' and r.get('enabled') is not False for r in policy))
    require(client.api('/api/default-action').get('defaultAction') == 'deny')
    require(client.traffic('example.com') == 200 and client.traffic('example.org') == 403)
    agent = client.api('/api/maintenance-agent')
    require(agent.get('available') is True and agent.get('compose_stack_up') is True)
    require(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?', agent.get('agent_version', '')))
    deadline = time.monotonic() + 1500
    while True:
        feed = client.api('/api/urlcat/feed-status').get('ut1', {})
        if feed.get('lastSync') and int(feed.get('entries', 0)) > 0:
            break
        require(time.monotonic() < deadline)
        time.sleep(20)
    categories = {}
    for host in HOSTS:
        lookup = client.api('/api/urlcat/lookup?host=' + host)
        categories[host] = {k: lookup.get(k) or '' for k in ('category', 'tier', 'matchedBy')}
    require(any(v['tier'] == 'community' and v['category'] for v in categories.values()))
    result = {'schema': 1, 'ca_sha256': hashlib.sha256(cert).hexdigest(), 'rules': policy,
              'categories': categories, 'admin_login': 'pass', 'ca_decryption': 'pass',
              'traffic': {'example.com': 200, 'example.org': 403}, 'agent': 'pass', 'agent_version': agent['agent_version'],
              'historical_encrypted_log_recovery': LOG_LIMIT}
    if allowlist is not None:
        result['threat_domain_allowlist'] = allowlist
    if baseline is not None:
        require(result['ca_sha256'] == baseline['ca_sha256'])
        require(result['rules'] == baseline['rules'])
        require(result['categories'] == baseline['categories'])
        require(result['agent_version'] == baseline['agent_version'])
    return result
