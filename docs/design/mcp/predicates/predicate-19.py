#!/usr/bin/env python3
"""Predicate 19 (re-derived round 34, persisted round 35) — every DFD whose graph
contains an IRREVERSIBLE-ACTION node must also contain a DURABLE-COMMIT node.

The action vocabulary is derived from MCP-EVENT-002's own words — "before the
upstream call", "before the snapshot is signed, pushed or applied", "before any
broker-side materialization", "before the state change" — not from node names
that happen to exist in the diagrams (amendment 20's failure mode).
"""
import re
import sys
import pathlib

DFD = pathlib.Path('docs/design/mcp/DATA-FLOW-DIAGRAMS.md')

ACTION = re.compile(
    r'upstream call|Publish|publish|sign(ed|ing)?\b|push(ed|ing)?\b|appl(y|ied)\b|'
    r'MATERIALIZE|materializ|mint|rotate|revoke|[Aa]tomic swap|state change',
)
COMMIT = re.compile(r'DURABLE decision-event COMMIT|commit CONFIRMED|commit FAILED')
# a node that only RECORDS what already happened is not an irreversible action,
# and an edge whose own label NEGATES the action documents its absence, not its
# occurrence ("never publishes", "NOTHING published", "No snapshot change")
POST = re.compile(r'Upstream response|outcome event|OUTCOME|records what happened|'
                  r'never |NOTHING |NO |No snapshot|not applied|WITHOUT ')


def blocks(text):
    """(dfd-label, mermaid-source) for each fenced mermaid block, labelled by the
    nearest preceding '## DFD-n' heading."""
    out, cur, buf, inblock = [], None, [], False
    for line in text.splitlines():
        m = re.match(r'^## (DFD-\d+)\b', line)
        if m:
            cur = m.group(1)
        if line.strip().startswith('```mermaid'):
            inblock, buf = True, []
            continue
        if inblock and line.strip().startswith('```'):
            out.append((cur, '\n'.join(buf)))
            inblock = False
            continue
        if inblock:
            buf.append(line)
    return out


def run(text):
    v = []
    for i, (label, src) in enumerate(blocks(text), 1):
        acts = [l for l in src.splitlines() if ACTION.search(l) and not POST.search(l)]
        if not acts:
            continue
        if not COMMIT.search(src):
            v.append(f'block {i} ({label}): irreversible action, NO durable-commit node '
                     f'-> {acts[0].strip()[:80]!r}')
    return v


if __name__ == '__main__':
    text = DFD.read_text()
    base = set(run(text))

    print('=== seed: revert DFD-3\'s gate (APPR --> PUB direct) — MUST fire ===')
    # revert round 34's gate: publish straight from approval, node text preserved
    seeded = re.sub(r'^([ \t]*)APPR --> WALM.*?\n(?:[ \t]*WALM[^\n]*\n)+',
                    lambda m: m.group(1) + 'APPR --> PUB[Publish signed snapshot]\n',
                    text, count=1, flags=re.S | re.M)
    if seeded == text:
        print('  SEED-DID-NOT-APPLY — predicate not proven')
        sys.exit(1)
    new = [x for x in run(seeded) if x not in base]
    print(f'  {"FIRES" if new else "MISSED"}' + (f' -> {new[0]}' if new else ''))

    print('\n=== residual on the live document ===')
    v = run(text)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')
    print(f'\n(mermaid blocks examined: {len(blocks(text))})')
    sys.exit(0 if new and not v else 1)
