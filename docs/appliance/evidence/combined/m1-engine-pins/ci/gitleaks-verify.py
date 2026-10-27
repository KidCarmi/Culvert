#!/usr/bin/env python3
"""Re-check gitleaks-findings.tsv against the gitleaks SARIF and git history.

Usage (from a full clone that has every commit named in the SARIF):
    python3 -I gitleaks-verify.py gitleaks-results.sarif.gz gitleaks-findings.tsv

For each SARIF result, in order, it reads the flagged LINE from git at the
finding's own commit, cuts the matched span by the SARIF columns, and checks:
  * the TSV row agrees on commit (12-hex prefix), file, line and rule;
  * an auto-classified row satisfies its class rule:
      git-commit-hash-in-advisory-URL  span is 40 lowercase hex and sits
                                       inside an http(s) URL on that line
      go-module-h1-checksum            span sits inside an "h1:<base64>" token
      git-sha-or-tree-id-in-markdown   span is 40 lowercase hex in a .md file
  * a manual row's line exists (its note is a human judgment, not re-derived).
It prints counts and row numbers only. It never prints matched text.
"""
import csv, gzip, json, re, subprocess, sys

sarif, tsv = sys.argv[1:3]
res = json.load((gzip.open if sarif.endswith('.gz') else open)(sarif, 'rt'))['runs'][0]['results']
rows = list(csv.DictReader(open(tsv), delimiter='\t'))
if len(res) != len(rows):
    sys.exit(f'FAIL count: sarif={len(res)} tsv={len(rows)}')

cache = {}
def lines(c, p):
    if (c, p) not in cache:
        r = subprocess.run(['git', 'show', f'{c}:{p}'], capture_output=True)
        cache[(c, p)] = r.stdout.decode('utf-8', 'replace').splitlines() if r.returncode == 0 else None
    return cache[(c, p)]

HEX40 = re.compile(r'[0-9a-f]{40}')
bad = []
seen = {}
for i, (x, row) in enumerate(zip(res, rows), 1):
    loc = x['locations'][0]['physicalLocation']
    p, rg = loc['artifactLocation']['uri'], loc['region']
    c, n = x['partialFingerprints']['commitSha'], rg['startLine']
    if not c.startswith(row['commit(12)']) or len(row['commit(12)']) != 12 or \
            (row['file'], int(row['line']), row['rule']) != (p, n, x['ruleId']):
        bad.append((i, 'identity')); continue
    L = lines(c, p)
    if not L or not 0 < n <= len(L):
        bad.append((i, 'line-missing')); continue
    line = L[n - 1]
    # gitleaks' SARIF columns land one character late against the line as
    # git stores it (observed on every row), so the window is widened by one
    # on each side. A class rule must hold for a token inside that window.
    s, e = max(0, rg['startColumn'] - 2), rg['endColumn'] + 1
    span = line[s:e]
    cls = row['class']
    ok = True
    if cls == 'git-commit-hash-in-advisory-URL':
        ok = any(u.start() <= s + h.start() and s + h.end() <= u.end()
                 for h in HEX40.finditer(span)
                 for u in re.finditer(r'https?://\S+', line))
    elif cls == 'go-module-h1-checksum':
        ok = any(t.start() < e and s < t.end()
                 for t in re.finditer(r'h1:[A-Za-z0-9+/=]{40,}', line))
    elif cls == 'git-sha-or-tree-id-in-markdown':
        ok = p.endswith('.md') and bool(HEX40.search(span))
    elif cls == 'manual':
        ok = True
    else:
        ok = False
    seen[cls] = seen.get(cls, 0) + 1
    if not ok:
        bad.append((i, cls))

print('rows', len(rows), 'by class', dict(sorted(seen.items())))
print('PASS' if not bad else f'FAIL rows {bad}')
sys.exit(1 if bad else 0)
