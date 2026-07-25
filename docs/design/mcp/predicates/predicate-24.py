#!/usr/bin/env python3
"""Predicate 24 — every per-class absence enumeration in the package must carry,
for each critical class, the SAME set of action-keys that EVENT-MODEL §4a's
per-class table (the authority) requires for that class.

The defect this catches: a class's clause asserting only the action the class is
NAMED after, when its flow performs a second irreversible action too (an approved
Management mutation publishes a signed snapshot; the Gateway commit gate precedes
both broker materialization and the upstream call).  Such a clause reads complete
and passes a handler that skips the eponymous action and performs the other.

The required sets are PARSED FROM §4a on every run, never hand-written, so the
predicate tracks the authority when the authority changes (amendment 20).
"""
import re
import sys
import pathlib

EM = pathlib.Path('docs/design/mcp/EVENT-MODEL.md')
SITES = [
    'docs/design/mcp/SECURITY-REQUIREMENTS.md',
    'docs/design/mcp/CI-GATES.md',
    'docs/design/mcp/IMPLEMENTATION-SLICES.md',
    'docs/design/mcp/TEST-TRACEABILITY-MATRIX.md',
]

# action-keys, detected the same way in the authority and at every site
KEYS = {
    'call': r'upstream call',
    'materialize': r'materializ|minted|mint\b|rotated|revoked',
    'revision': r'revision',
    'signed': r'signed',
    'pushed': r'push',
    'epoch': r'epoch',
    'mgmt-state': r'Management state change|no state change|NO Management state change|state change occurred|no Management state change',
}

CLASSES = {
    'write': r'[Ww]rite\s*/\s*destructive',
    'publication': r'[Cc]onfiguration publication',
    'credential': r'[Cc]redential\b',
    'management': r'[Ss]tate-affecting Management',
}

# a class name may carry a qualifier before the separator that introduces its
# clause ("credential issue/rotation/revocation ⇒ …"), so allow bounded text
# that crosses no other separator
SEP = r'[^;⇒:→|]{0,50}?\s*(?:⇒|:|→)'
CLAUSE_WINDOW = 400   # a clause may wrap across lines; the scan is text-wide


def keys(text):
    return {k for k, pat in KEYS.items() if re.search(pat, text)}


def authority():
    """{class: required action-keys} parsed from §4a's per-class table."""
    text = EM.read_text()
    req = {}
    for line in text.splitlines():
        if not line.lstrip().startswith('> |'):
            continue
        cells = [c.strip() for c in line.strip().lstrip('>').strip().strip('|').split('|')]
        if len(cells) != 4 or cells[0].startswith('---') or cells[0] == 'Class':
            continue
        for name, pat in CLASSES.items():
            if re.search(pat, cells[0]) or (name == 'write' and 'Write' in cells[0]) \
               or (name == 'credential' and cells[0].startswith('Credential')) \
               or (name == 'management' and 'Management' in cells[0]) \
               or (name == 'publication' and 'Configuration publication' in cells[0]):
                req[name] = keys(cells[3])
                break
    return req


def perclass_table(path, quoted):
    """The per-class table as {class-cell: (action, precedes, absence)} from a file.
    EVENT-MODEL keeps it inside a blockquote; ADR-0024 keeps it as a bare table."""
    out = {}
    for line in pathlib.Path(path).read_text().splitlines():
        raw = line.strip()
        if quoted:
            if not raw.startswith('> |'):
                continue
            raw = raw.lstrip('>').strip()
        elif not raw.startswith('|'):
            continue
        cells = [c.strip() for c in raw.strip('|').split('|')]
        if len(cells) != 4 or cells[0] in ('Class',) or set(cells[1]) <= set('-: '):
            continue
        out[cells[0]] = tuple(cells[1:])
    return out


def table_drift():
    """EVENT-MODEL §4a and ADR-0024 §D-5 each carry a copy of the per-class table.
    Two copies of one authority must not diverge."""
    a = perclass_table('docs/design/mcp/EVENT-MODEL.md', quoted=True)
    b = perclass_table('docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md', quoted=False)
    v = []
    if not a or not b:
        return ['per-class table not found in one of the two copies — predicate not sound']
    for k in sorted(set(a) | set(b)):
        if k not in a:
            v.append(f'row {k!r} in ADR-0024 only')
        elif k not in b:
            v.append(f'row {k!r} in EVENT-MODEL only')
        elif a[k] != b[k]:
            for i, col in enumerate(('irreversible action', 'commit must precede', 'absence assertion')):
                if a[k][i] != b[k][i]:
                    v.append(f'row {k!r} {col} differs:\n      EVENT-MODEL: {a[k][i]}\n      ADR-0024   : {b[k][i]}')
    return v


def clauses(text):
    """Per-class ABSENCE clauses: the text introduced by `<class> ⇒ | : | →`, up to
    the next `;` or the end of the sentence.

    Scanning is over the WHOLE text with a character window, and carries NO
    line-level prerequisite.  An earlier version required the literal string
    `upstream call` to appear on the same LINE before it would look at a line at
    all — so a purely cosmetic reflow into one bullet or line per class would
    have skipped the configuration-publication and Management clauses entirely
    (neither names an upstream call) and still printed `NONE`.  A Markdown
    reformat must never change what this predicate covers.

    An ORDERING clause ("… ⇒ before the upstream call") is a different statement
    and is excluded — it says when the commit happens, not what the test asserts
    did not happen.
    """
    out = []
    flat = text.replace('\n', ' ')
    for name, pat in CLASSES.items():
        for m in re.finditer(r'(?:' + pat + r')' + SEP, flat):
            clause = re.split(r';|(?<=[a-z])\.\s', flat[m.end():m.end() + CLAUSE_WINDOW])[0]
            bare = re.sub(r'[*_`]', '', clause).strip()
            if bare.lower().startswith('before'):
                continue          # ordering precondition, not an absence assertion
            if not re.search(r'\bno\b|\bNO\b|nothing|NOTHING|unchanged|ABSENCE', clause):
                continue          # not an absence enumeration at all
            out.append((name, clause))
    return out


def run(paths):
    req = authority()
    v = []
    for path in paths:
        text = pathlib.Path(path).read_text()
        for name, clause in clauses(text):
            missing = req.get(name, set()) - keys(clause)
            if missing:
                v.append(f'{path}: {name} clause missing {sorted(missing)} -> {clause.strip()[:110]!r}')
    return v


if __name__ == '__main__':
    req = authority()
    print('=== required action-keys, PARSED from EVENT-MODEL §4a ===')
    for k in sorted(req):
        print(f'  {k:12s} {sorted(req[k])}')
    if len(req) != 4:
        print('  !! authority table did not yield all four classes — predicate is not sound')
        sys.exit(1)

    base = set(run(SITES))

    print('\n=== seeded known-positives (each MUST fire with a NEW violation) ===')
    import tempfile
    import os
    seeds = {
        'SECURITY-REQUIREMENTS: revert (a3b) to state-change only': (
            'docs/design/mcp/SECURITY-REQUIREMENTS.md',
            ('state-affecting Management operation → NO Management state change occurred AND no new configuration '
             'revision exists, nothing was signed or pushed, and every DP remains on the prior epoch',
             'state-affecting Management operation → NO Management state change occurred')),
        'IMPLEMENTATION-SLICES: revert PR-8 write clause to call-only': (
            'docs/design/mcp/IMPLEMENTATION-SLICES.md',
            ('write/destructive: **no upstream call occurred AND no broker-side materialization occurred**',
             'write/destructive: **no upstream call occurred**')),
        'CI-GATES: revert credential clause to broker-state only': (
            'docs/design/mcp/CI-GATES.md',
            ('credential issue/rotation/revocation ⇒ **broker-side credential state unchanged** (nothing minted, rotated or revoked) **AND no upstream call occurred**',
             'credential issue/rotation/revocation ⇒ **broker-side credential state unchanged** (nothing minted, rotated or revoked)')),
        # LAYOUT INDEPENDENCE: a cosmetic reflow into one line per class must not
        # reduce coverage.  This seed reflows AND weakens the publication clause;
        # under the old line-level `upstream call` prerequisite it went undetected.
        'CI-GATES: reflow to one line per class AND drop the publication epoch/push assertions': (
            'docs/design/mcp/CI-GATES.md',
            ('configuration publication ⇒ **no new configuration revision exists, nothing was signed or pushed, and every DP remains on the prior epoch**',
             'configuration publication ⇒ **no new configuration revision exists**\n  (reflowed onto its own line, away from any mention of an upstream call)')),
    }
    ok = True
    tmp = tempfile.mkdtemp()
    for label, (path, (old, new)) in seeds.items():
        src = pathlib.Path(path).read_text()
        if old not in src:
            print(f'  SEED-DID-NOT-APPLY: {label}')
            ok = False
            continue
        dst = os.path.join(tmp, os.path.basename(path))
        pathlib.Path(dst).write_text(src.replace(old, new, 1))
        others = [p for p in SITES if p != path]
        got = [x for x in run(others + [dst]) if x.split(': ', 1)[1] not in {b.split(': ', 1)[1] for b in base}]
        print(f'  {"FIRES" if got else "MISSED"}: {label}' + (f' -> {got[0][:150]}' if got else ''))
        ok &= bool(got)

    print('\n=== ARM 2: the two copies of the per-class table must agree ===')
    d = table_drift()
    print('\n'.join('  ' + x for x in d) if d else '  NONE (EVENT-MODEL §4a == ADR-0024 §D-5)')

    print('\n=== residual on the live documents ===')
    v = run(SITES)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')
    sys.exit(0 if ok and not v and not d else 1)
