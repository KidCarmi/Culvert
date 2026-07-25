#!/usr/bin/env python3
"""Predicate 23 — in CI-GATES' gate-status table, every owner named in a row's
"Target PR" cell must also appear in that row's "Blocking?" cell.

A Target that names two owners with a Blocking cell naming one lets a consumer of
the status column treat the second owner's obligation as advisory and close it on
the first owner's coverage.  Vocabulary is DERIVED from the cells themselves —
any `PR-<n>`, `PR-C`, or a `Future … Gate` phrase — never a hand-written owner
list (amendment 20).
"""
import re
import sys
import pathlib

CI = pathlib.Path('docs/design/mcp/CI-GATES.md')


def owners(cell):
    """Owner tokens named in a cell, derived from the text's own vocabulary."""
    out = set(re.findall(r'PR-(?:\d+|C)\b', cell))
    for m in re.finditer(r'Future ([A-Za-z][A-Za-z \-]*?) Gate', cell):
        out.add('Future ' + m.group(1).strip() + ' Gate')
    # a bare D-nn reference identifies the same future gate by its decision id
    out |= {'D-' + d for d in re.findall(r'\bD-(\d\d)\b', cell)}
    return out


def status_rows(text):
    """Rows of the gate-status table: (name, target_cell, blocking_cell)."""
    rows = []
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip('|').split('|')]
        if len(cells) != 6:
            continue
        if not re.match(r'^(proposed|present|partial)', cells[1], re.I):
            continue
        rows.append((cells[0], cells[1], cells[3]))
    return rows


def run(text):
    v = []
    for name, target, blocking in status_rows(text):
        # "REC — not yet scoped to a specific PR" is an explicit non-assignment
        if 'not yet scoped' in blocking:
            continue
        missing = owners(target) - owners(blocking)
        if missing:
            v.append(f'{name[:60]!r}: Target names {sorted(missing)} — absent from Blocking? cell')
    return v


if __name__ == '__main__':
    text = CI.read_text()
    base = set(run(text))

    print('=== seeded known-positives (each MUST fire with a NEW violation) ===')
    seeds = {
        'drop the future gate from the durability row Blocking cell':
            text.replace('**Yes, for PR-8 AND for the Future Management-Mutation Gate (D-13)**',
                         '**Yes, for PR-8**', 1),
        'drop PR-5 from the SSRF row Blocking cell':
            text.replace('Yes, for PR-1 (INSP-008 **primitive only**, no listener) / **PR-5 (INSP-009 — listener bind + host allowlist + E2E rebinding; the PR-1 unit test does NOT close the listener-side threat)** / PR-7 (SSRF)',
                         'Yes, for PR-1 (INSP-008 **primitive only**, no listener) / PR-7 (SSRF)', 1),
        'drop PR-8 from the secret-scan row Blocking cell':
            text.replace('| Secret-in-events scan (**both capabilities\' streams**) | proposed (target PR-4/PR-8) | Proposed | Yes, for PR-4/PR-8 |',
                         '| Secret-in-events scan (**both capabilities\' streams**) | proposed (target PR-4/PR-8) | Proposed | Yes, for PR-4 |', 1),
    }
    ok = True
    for label, seeded in seeds.items():
        if seeded == text:
            print(f'  SEED-DID-NOT-APPLY: {label}')
            ok = False
            continue
        new = [x for x in run(seeded) if x not in base]
        print(f'  {"FIRES" if new else "MISSED"}: {label}' + (f' -> {new[0]}' if new else ''))
        ok &= bool(new)

    print('\n=== residual on the live document ===')
    v = run(text)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')
    print(f'\n(rows examined: {len(status_rows(text))})')
    sys.exit(0 if ok and not v else 1)
