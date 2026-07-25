#!/usr/bin/env python3
"""Predicate 22 — no LIVE normative document may state MCP-EVENT-002's commit-ordering
precondition in a form that names FEWER than all four class-specific irreversible actions.

The prohibited thing is a MEANING, not a phrase.  An earlier version of this
predicate matched the single string `committed BEFORE credential use`, so
`durably committed before the upstream call` and `durably persisted before
credential use and the upstream call` — both incomplete in exactly the way
`MCP-EVENT-002` exists to forbid — passed silently, and `CLASS_ACTS` was
asserted but never used in the decision.  Detection now works on the actions a
sentence NAMES.

An ordering sentence is acceptable in exactly two forms:

  * the CLASS-GENERIC form — "durably committed before THAT CLASS'S OWN
    irreversible action" — which delegates the enumeration; or
  * an enumeration naming ALL FOUR actions: the upstream call, the snapshot
    sign/push/apply, broker materialization, and the Management state change.

Naming some but not all is the defect: it reads as complete and leaves the
unnamed classes ungated.  The action vocabulary is DERIVED from MCP-EVENT-002's
own row on every run (amendment 20).

The remediation ledger is EXCLUDED: it records the historical wording verbatim by design.
"""
import re
import sys
import pathlib

D = pathlib.Path('docs/design/mcp')
LEDGER = 'PR1-READINESS-REMEDIATION.md'
FILES = [p for p in D.glob('*.md') if p.name != LEDGER] + \
        [pathlib.Path('docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md')]

# ---- vocabulary derived from MCP-EVENT-002's own class table -----------------
req = (D / 'SECURITY-REQUIREMENTS.md').read_text()
row = next(l for l in req.splitlines() if l.startswith('| MCP-EVENT-002'))
CLASS_ACTS = {
    'upstream call':   'before the upstream call' in row,
    'sign/push/apply': 'signed, pushed or applied' in row,
    'materialization': 'materialization' in row,
    'state change':    'state change' in row,
}

# how each derived action is recognised in an arbitrary sentence
ACT_PATTERNS = {
    'upstream call':   r'upstream call',
    'sign/push/apply': r'sign(?:ed|ing)?\b[^.]{0,20}?push|signed, pushed or applied|sign/push/apply|`SIGN`|publish|publication|published',
    'materialization': r'materializ|mint(?:ing|ed)?\b|rotat|revok',
    'state change':    r'state change',
}

# the ordering assertion itself — any durability-before-action sentence
ORDERING = re.compile(r'durabl\w*\s+(?:committed|persisted|commit)\b[^.]{0,40}?\bBEFORE\b', re.I)
# the class-generic delegation, which is complete by construction
GENERIC = re.compile(r"that class'?s?\s+OWN\s+irreversible action|each class'?s?\s+own\s+"
                     r"(?:side effect|irreversible action)|class-specific", re.I)
# The scan runs over the WHOLE text (a per-line scan would cut every wrapped
# enumeration in half and report it as incomplete), but the span an ordering
# assertion is judged on is the ORDERING SENTENCE ITSELF — terminated at the
# sentence end, never a fixed window.  A fixed window let an incomplete rule
# ("durably committed before the upstream call.") be absolved by unrelated
# following prose that happened to mention publication, materialization and a
# state change (round 39, P1).  WINDOW survives only as a hard backstop for a
# sentence with no terminator before the end of the document.
WINDOW = 600
SENTENCE_END = re.compile(r'(?<=[a-z\)\*`\d])\.\s+(?![a-z])')
LOOKBACK = 200          # scope marker may precede the ordering clause


def perclass_actions():
    """{class-name: its own irreversible actions} from EVENT-MODEL §4a's table.

    A sentence SCOPED to one class completes its obligation by naming that
    class's actions; only an unscoped, general statement of the precondition
    must name all four.  Parsed from the authority, never hand-written.
    """
    out = {}
    for line in (D / 'EVENT-MODEL.md').read_text().splitlines():
        raw = line.strip()
        if not raw.startswith('> |'):
            continue
        cells = [c.strip() for c in raw.lstrip('>').strip().strip('|').split('|')]
        if len(cells) != 4 or cells[0] == 'Class' or set(cells[1]) <= set('-: '):
            continue
        acts = named_acts(cells[1])
        if acts:
            out[cells[0]] = acts
    return out


def named_acts(span):
    return {k for k, pat in ACT_PATTERNS.items() if re.search(pat, span, re.I)}


GENERIC_WORDS = {'operation', 'issue', 'selection', 'affecting', 'destructive'}


def scope_tokens(cls):
    """Distinctive words of a class name, used to detect that a sentence is
    SCOPED to that class ("Management", "publication", "credential")."""
    return {w.lower() for w in re.findall(r'[A-Za-z]{6,}', cls)
            if w.lower() not in GENERIC_WORDS}


def run(texts, scopes=None):
    required = {k for k, present in CLASS_ACTS.items() if present}
    scopes = scopes if scopes is not None else perclass_actions()
    bad = []
    for name, t in texts.items():
        flat = t.replace('\n', ' ')
        for m in ORDERING.finditer(flat):
            span = SENTENCE_END.split(flat[m.start():m.start() + WINDOW])[0]
            ctx = (flat[max(0, m.start() - LOOKBACK):m.start()] + span).lower()
            line = t[:m.start()].count('\n') + 1
            if GENERIC.search(span):
                continue                          # delegates the enumeration
            got = named_acts(span)
            # a sentence SCOPED to one class is complete when it names exactly
            # that class's own actions — only an UNSCOPED statement of the
            # general precondition has to name all four
            if any(got == acts and (scope_tokens(cls) & set(re.findall(r'[a-z]{6,}', ctx)))
                   for cls, acts in scopes.items()):
                continue
            if not got:
                bad.append(f'{name}:{line}: ordering assertion names NO class action and is not '
                           f'class-generic -> {span[:90]!r}')
            elif got != required:
                bad.append(f'{name}:{line}: ordering assertion names only {sorted(got)} — missing '
                           f'{sorted(required - got)} -> {span[:90]!r}')
    return bad


if __name__ == '__main__':
    assert all(CLASS_ACTS.values()), f'authority vocabulary incomplete: {CLASS_ACTS}'
    print('vocabulary derived from MCP-EVENT-002:', CLASS_ACTS)
    texts = {p.name: p.read_text() for p in FILES}
    base = set(run(texts))

    print('\n=== seeded known-positives (each MUST fire) ===')
    # every seed is a DIFFERENT incomplete phrasing — the point of the round-38
    # fix is that the predicate must catch the meaning, not one sentence
    seeds = {
        'EVENT-MODEL.md':
            'the decision event MUST be durably committed BEFORE credential use and before the upstream call.',
        '0024-mcp-agent-security-gateway-trust-boundary.md':
            'the decision event MUST be durably committed before the upstream call.',
        'RECOMMENDED-ARCHITECTURE.md':
            'the decision event MUST be durably persisted before credential use and the upstream call.',
        'CI-GATES.md':
            'the decision event MUST be durably committed before the snapshot is signed or pushed.',
        # ROUND 39 P1: an incomplete rule must NOT be absolved by neighbouring prose.
        # Under the old fixed 600-char window this sentence reported clean, because
        # the following sentence names the other three actions.
        'THREAT-MODEL.md':
            'the decision event MUST be durably committed before the upstream call. '
            'Separately, publication signs and pushes the snapshot, broker materialization '
            'mints credentials, and the Management state change is recorded.',
    }
    ok = True
    for target, sentence in seeds.items():
        seeded = dict(texts)
        seeded[target] = seeded[target] + '\n' + sentence + '\n'
        new = [x for x in run(seeded) if x not in base]
        fired = any(x.startswith(target) for x in new)
        print(f'  {"FIRES" if fired else "MISSED"}: {sentence[:64]}...' +
              (f'\n      -> {new[0][:150]}' if new else ''))
        ok &= fired

    print('\n=== negative control: the CLASS-GENERIC form MUST NOT fire ===')
    ctl = dict(texts)
    ctl['CI-GATES.md'] = ctl['CI-GATES.md'] + \
        "\nthe decision event MUST be durably committed BEFORE THAT CLASS'S OWN irreversible action.\n"
    quiet = not [x for x in run(ctl) if x not in base]
    print(f'  {"OK (silent)" if quiet else "FALSE POSITIVE"}')
    ok &= quiet

    print('\n=== residual on LIVE documents (ledger excluded) ===')
    v = run(texts)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')

    led = (D / LEDGER).read_text()
    print(f'\n(ledger excluded by design; it retains {len(ORDERING.findall(led))} historical '
          f'ordering sentence(s))')
    sys.exit(0 if ok and not v else 1)
