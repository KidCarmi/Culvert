#!/usr/bin/env python3
"""Exercise the actual Gitleaks policy with synthetic, non-secret canaries."""
import argparse
import json
from pathlib import Path
import re
import secrets
import subprocess
import tempfile


def scan(executable, config, root):
    result = subprocess.run(
        [executable, 'dir', '.', '--config', str(config), '--redact=100',
         '--report-format', 'json', '--report-path', '-', '--no-banner',
         '--no-color', '--timeout', '30'], cwd=root, capture_output=True, timeout=40)
    if result.returncode not in (0, 1):
        raise RuntimeError('scanner failed')
    return json.loads(result.stdout)


# A canary must always be a FINDING when nothing suppresses it. gitleaks'
# generic-api-key rule drops any value containing one of its stopwords, so a
# token_urlsafe canary occasionally spelled one (measured: ~3% of runs failed
# "different value in allowed path was suppressed" with no suppression at
# all). This alphabet has no vowels and no m/p/x/0, so it cannot contain any
# v8.30.0 stopword (the vowel-free ones are md5, vpn, html, http, mqtt, smtp,
# xmpp, 000000, xxxxxx), while keeping ~5.4 bits of entropy per character.
CANARY_ALPHABET = 'BCDFGHJKLNQRSTVWZbcdfghjklnqrstvwz123456789'


def make_canary(length=40):
    return ''.join(secrets.choice(CANARY_ALPHABET) for _ in range(length))


def check(executable):
    repo = Path(__file__).resolve().parents[2]
    config = repo / '.gitleaks.toml'
    historical = repo / '.gitleaksignore'
    if historical.exists():
        for line in historical.read_text(encoding='utf-8').splitlines():
            if line and not line.startswith('#') and not re.fullmatch(
                    r'[0-9a-f]{40}:[A-Za-z0-9_./-]+:[a-z0-9-]+:[1-9][0-9]*', line):
                raise RuntimeError('historical exception must be an exact finding fingerprint')
    fixture_path = 'cmd/culvert-console/bootstrap_view_linux_test.go'
    source = (repo / fixture_path).read_text(encoding='utf-8')
    match = re.search(r'const viewFixtureCredential = "([A-Za-z0-9]+)"', source)
    if not match:
        raise RuntimeError('fixture source changed; review required')
    known = match.group(1)
    canary = make_canary()  # Generated here, never an operational key.
    with tempfile.TemporaryDirectory(prefix='culvert-gitleaks-policy-') as temp:
        root = Path(temp)
        target = root / fixture_path
        target.parent.mkdir(parents=True)
        target.write_text('initial_password = "' + known + '"\n', encoding='utf-8')
        if scan(executable, config, root):
            raise RuntimeError('known fixture exception no longer matches')
        target.write_text('initial_password = "' + canary + '"\n', encoding='utf-8')
        found = scan(executable, config, root)
        if not any(r['RuleID'] == 'generic-api-key' for r in found):
            raise RuntimeError('different value in allowed path was suppressed')
        target.unlink()
        (root / 'unrelated.conf').write_text('initial_password = "' + known + '"\n', encoding='utf-8')
        if not scan(executable, config, root):
            raise RuntimeError('known value in unrelated path was suppressed')
        (root / 'unrelated.conf').unlink()
        vendor = root / 'third_party/crewjam-saml/new_fixture.go'
        vendor.parent.mkdir(parents=True)
        vendor.write_bytes((repo / 'third_party/crewjam-saml/xmlenc/fuzz.go').read_bytes())
        if not any(r['RuleID'] == 'private-key' for r in scan(executable, config, root)):
            raise RuntimeError('unreviewed vendor path was suppressed')
        vendor.unlink()
        provenance = vendor.parent / 'CULVERT-PROVENANCE.json'
        provenance.write_text(json.dumps({'api_key': secrets.token_hex(32)}), encoding='utf-8')
        if not scan(executable, config, root):
            raise RuntimeError('arbitrary hex token in provenance was suppressed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gitleaks', required=True)
    args = parser.parse_args()
    try:
        check(str(Path(args.gitleaks).resolve()))
    except Exception:
        print('Gitleaks policy regression failed; no canary or finding content reported.')
        return 1
    print('Gitleaks policy: five canary checks passed; no finding content reported.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
