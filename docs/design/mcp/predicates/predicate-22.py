#!/usr/bin/env python3
"""Predicate 22 — no LIVE normative document may state MCP-EVENT-002's commit-ordering
precondition in terms that name only the Gateway's side effect. Any sentence asserting
"durably committed BEFORE ..." must name each class's own irreversible action, using the
vocabulary DERIVED from MCP-EVENT-002's class table (amendment 20), not a fixed list.

The remediation ledger is EXCLUDED: it records the historical wording verbatim by design.
"""
import re, sys, pathlib

D = pathlib.Path('docs/design/mcp')
LEDGER = 'PR1-READINESS-REMEDIATION.md'
FILES = [p for p in D.glob('*.md') if p.name != LEDGER] + \
        [pathlib.Path('docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md')]

# vocabulary derived from MCP-EVENT-002's own class table
req = (D / 'SECURITY-REQUIREMENTS.md').read_text()
row = next(l for l in req.splitlines() if l.startswith('| MCP-EVENT-002'))
CLASS_ACTS = {
    'upstream call':   'before the upstream call' in row,
    'sign/push/apply': 'signed, pushed or applied' in row,
    'materialization': 'materialization' in row,
    'state change':    'state change' in row,
}
NARROW = re.compile(r'committed\s+BEFORE\s+credential use', re.I)


def run(texts):
    bad = []
    for name, t in texts.items():
        for i, line in enumerate(t.splitlines(), 1):
            if NARROW.search(line):
                bad.append(f'{name}:{i}: narrow phrasing — names only credential use / upstream call')
    return bad


if __name__ == '__main__':
    assert all(CLASS_ACTS.values()), f'authority vocabulary incomplete: {CLASS_ACTS}'
    print('vocabulary derived from MCP-EVENT-002:', CLASS_ACTS)
    texts = {p.name: p.read_text() for p in FILES}

    print('\n=== seeded known-positives (each MUST fire) ===')
    ok = True
    for target in ['EVENT-MODEL.md', '0024-mcp-agent-security-gateway-trust-boundary.md',
                   'RECOMMENDED-ARCHITECTURE.md']:
        seeded = dict(texts)
        seeded[target] = seeded[target] + \
            "\nthe decision event MUST be durably committed BEFORE credential use and before the upstream call.\n"
        base = set(run(texts))
        new = [x for x in run(seeded) if x not in base]
        fired = any(x.startswith(target) for x in new)
        print(f'  {"FIRES" if fired else "MISSED"}: seed into {target}' + (f' -> {new[0]}' if new else ' -> (none)'))
        ok &= fired

    print('\n=== residual on LIVE documents (ledger excluded) ===')
    v = run(texts)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')

    led = (D / LEDGER).read_text()
    print(f'\n(ledger retains {len(NARROW.findall(led))} historical occurrence(s) by design)')
    sys.exit(0 if ok and not v else 1)
