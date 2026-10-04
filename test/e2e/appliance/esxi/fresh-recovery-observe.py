"""Supported API/traffic oracles for the owned fresh-recovery fixture.

Called by fresh-recovery.py; no credentials on argv and no infrastructure
mutation. Historical logs are intentionally excluded by the backup format.
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


def normalized_rules(policy):
    require(policy.get('draft') is False and policy.get('persisted') is True and policy.get('rules'))
    return [{k: v for k, v in rule.items() if k not in ('hitCount', 'lastHit')} for rule in policy['rules']]


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
    if baseline is not None:
        require(result['ca_sha256'] == baseline['ca_sha256'])
        require(result['rules'] == baseline['rules'])
        require(result['categories'] == baseline['categories'])
        require(result['agent_version'] == baseline['agent_version'])
    return result
