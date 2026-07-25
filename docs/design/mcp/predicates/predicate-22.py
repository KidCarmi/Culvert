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
# The generic marker must QUALIFY THE ACTION.  A bare `class-specific` matched
# anywhere in the sentence let "... committed BEFORE the upstream call, with
# class-specific metrics" escape entirely (round 43): the escape hatch fired
# before the named actions were ever checked.
GENERIC = re.compile(r"that class'?s?\s+OWN\s+irreversible action|each class'?s?\s+own\s+"
                     r"(?:side effect|irreversible action)|"
                     r"class-specific\s+(?:\w+\s+){0,2}?(?:irreversible\s+)?(?:action|side effect)", re.I)
# The scan runs over the WHOLE text (a per-line scan would cut every wrapped
# enumeration in half and report it as incomplete), but the span an ordering
# assertion is judged on is the ORDERING SENTENCE ITSELF — terminated at the
# sentence end, never a fixed window.  A fixed window let an incomplete rule
# ("durably committed before the upstream call.") be absolved by unrelated
# following prose that happened to mention publication, materialization and a
# state change (round 39, P1).  WINDOW survives only as a hard backstop for a
# sentence with no terminator before the end of the document.
WINDOW = 600
# A sentence ends at `.` + whitespace.  Two refinements, each from a review
# finding:
#   * the terminator may be preceded by ANY non-space character — a closing
#     `**`, backtick, bracket, quote or digit (round 40, P1); and
#   * the NEXT sentence may legitimately start with a lowercase technical term
#     ("publication signs and pushes …"), so a blanket `(?![a-z])` lookahead
#     absorbed it and let the following sentence supply the missing actions
#     (round 41, P1).  The exclusion is now the ACTUAL abbreviation set plus
#     decimals, not "anything lowercase".
ABBREV = r'(?<!\be\.g)(?<!\bi\.e)(?<!\bcf)(?<!\bvs)(?<!\betc)(?<!\bapprox)(?<!\bFig)(?<!\bNo)(?<!\bp)(?<!\bpp)'
SENTENCE_END = re.compile(r'(?<=\S)' + ABBREV + r'(?<!\d)\.\s+')
# SCOPE RECOGNITION IS SENTENCE-LOCAL.  A raw 200-character lookback let an
# unrelated PRECEDING sentence supply the scope: "Configuration publication is
# described here. The decision event MUST be durably committed BEFORE the
# snapshot is signed, pushed or applied." was read as scoped and reported clean,
# which recreates the neighbouring-prose false negative the sentence bound was
# introduced to remove (round 42, P1).  The scope marker must appear in the
# assertion's OWN sentence.


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


GENERIC_WORDS = {'operation', 'issue', 'selection', 'affecting', 'high', 'risk'}
# ONE floor, used when deriving a class's tokens AND when tokenising the context.
# Two different floors was the bug: `destructive` satisfied the 6-char
# derivation so the 4-char fallback never ran, `write` was dropped, and the
# context tokeniser could not have seen it anyway (round 43).
TOKEN_FLOOR = 4


def scope_tokens(cls):
    """Distinctive words of a class name, used to detect that a sentence is
    SCOPED to that class ("Management", "publication", "credential",
    "destructive"/"write").

    Every class MUST yield at least one token.  `Write / destructive` produced
    an EMPTY set once "destructive" was in the stopword list and "write" fell
    below the length floor — so a legitimately scoped write sentence was read as
    an unscoped general rule and reported as missing three classes' actions
    (round 41).  A class with no token is a hole, so the floor drops to 4 and
    the result is asserted non-empty by the caller.
    """
    return {w.lower() for w in re.findall(r'[A-Za-z]{%d,}' % TOKEN_FLOOR, cls)
            if w.lower() not in GENERIC_WORDS}


def run(texts, scopes=None):
    required = {k for k, present in CLASS_ACTS.items() if present}
    scopes = scopes if scopes is not None else perclass_actions()
    bad = []
    for name, t in texts.items():
        flat = t.replace('\n', ' ')
        for m in ORDERING.finditer(flat):
            span = SENTENCE_END.split(flat[m.start():m.start() + WINDOW])[0]
            # the assertion's own sentence: back to the previous terminator, no further
            prev = list(SENTENCE_END.finditer(flat[:m.start()]))
            sent_start = prev[-1].end() if prev else 0
            ctx = (flat[sent_start:m.start()] + span).lower()
            line = t[:m.start()].count('\n') + 1
            # THE GENERIC ESCAPE MUST BE THE OBJECT OF `BEFORE`.  Matching the
            # phrase anywhere in the sentence let "... committed BEFORE the
            # upstream call; metrics describe each class's own side effect"
            # skip the whole check — the delegation has to be what the ordering
            # actually points at, not a later aside (round 44, P1).
            obj = re.split(r';|—', span[m.end() - m.start():])[0]
            if GENERIC.search(obj):
                continue                          # delegates the enumeration
            got = named_acts(span)
            # A sentence scoped to one class is complete when it names that
            # class's own actions.  A sentence scoped to SEVERAL classes must
            # name the UNION: `any(...)` passed "For write and configuration
            # publication ... BEFORE the upstream call" on the write class alone
            # while publication's sign/push/apply went unnamed (round 44, P1).
            ctx_toks = set(re.findall(r'[a-z]{%d,}' % TOKEN_FLOOR, ctx))
            scoped = {cls: acts for cls, acts in scopes.items()
                      if scope_tokens(cls) & ctx_toks}
            if scoped:
                need = set().union(*scoped.values())
                if got == need:
                    continue
                bad.append(f'{name}:{line}: assertion scoped to {sorted(scoped)} names {sorted(got)} '
                           f'— missing {sorted(need - got)} -> {span[:90]!r}')
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

    scopes = perclass_actions()
    tokenless = [c for c in scopes if not scope_tokens(c)]
    print(f'per-class scope tokens: ' + ', '.join(f'{c.split()[0]}={sorted(scope_tokens(c))}' for c in scopes))
    if tokenless:
        print(f'  !! classes with NO scope token (they can never be recognised as scoped): {tokenless}')
    ok0 = not tokenless

    print('\n=== seeded known-positives (each MUST fire) ===')
    # every seed is a DIFFERENT incomplete phrasing — the point of the round-38
    # fix is that the predicate must catch the meaning, not one sentence
    # KEYED BY LABEL, not by target file: a dict keyed by filename silently
    # DROPPED two seeds in round 44 when they reused a file another seed already
    # used.  A collision in a seed table is a seed that never ran.
    seeds = [
        ('round 38 — credential use + upstream call', 'EVENT-MODEL.md',
         'the decision event MUST be durably committed BEFORE credential use and before the upstream call.'),
        ('round 38 — upstream call only', '0024-mcp-agent-security-gateway-trust-boundary.md',
         'the decision event MUST be durably committed before the upstream call.'),
        ('round 38 — persisted, credential use + call', 'RECOMMENDED-ARCHITECTURE.md',
         'the decision event MUST be durably persisted before credential use and the upstream call.'),
        ('round 38 — publication only', 'CI-GATES.md',
         'the decision event MUST be durably committed before the snapshot is signed or pushed.'),
        ('round 40 — terminator after markdown, next sentence supplies the rest', 'ABUSE-CASES.md',
         'the decision event MUST be durably committed before **the upstream call**. '
         'Publication signs and pushes the snapshot, materialization mints the credential, '
         'and the Management state change is recorded.'),
        ('round 41 — next sentence starts lowercase', 'THREAT-MODEL.md',
         'the decision event MUST be durably committed before the upstream call. '
         'publication signs and pushes the snapshot, broker materialization mints credentials, '
         'and the Management state change is recorded.'),
        ('round 42 — PRECEDING sentence names a class', 'OPERATIONS-AND-SUPPORT.md',
         'Configuration publication is described here. The decision event MUST be durably '
         'committed BEFORE the snapshot is signed, pushed or applied.'),
        ('round 43 — bare class-specific must not exempt', 'ROLLOUT-AND-ROLLBACK.md',
         'the event is durably committed BEFORE the upstream call, with class-specific metrics.'),
        ('round 44 — generic phrase is a LATER ASIDE, not the object of BEFORE', 'GO-NO-GO-CHECKLIST.md',
         "For all classes, the event MUST be durably committed BEFORE the upstream call; "
         "metrics describe each class's own side effect."),
        ('round 44 — scoped to TWO classes, only one class action named', 'PROTOCOL-COMPATIBILITY.md',
         'For write and configuration publication, the decision event MUST be durably '
         'committed BEFORE the upstream call.'),
    ]
    ok = ok0
    assert len({lbl for lbl, _, _ in seeds}) == len(seeds), 'duplicate seed label'
    assert len({tgt for _, tgt, _ in seeds}) == len(seeds), 'two seeds share a target file'
    for label, target, sentence in seeds:
        seeded = dict(texts)
        seeded[target] = seeded[target] + '\n' + sentence + '\n'
        new = [x for x in run(seeded) if x not in base]
        fired = any(x.startswith(target) for x in new)
        print(f'  {"FIRES" if fired else "MISSED"}: {label}' +
              (f'\n      -> {new[0][:150]}' if new else ''))
        ok &= fired

    print('\n=== negative controls: legitimate forms MUST NOT fire ===')
    controls = {
        'class-generic delegation':
            "the decision event MUST be durably committed BEFORE THAT CLASS'S OWN irreversible action.",
        # ROUND 41: a sentence scoped to the write/destructive class is complete
        # when it names that class's own action — it must not be read as an
        # unscoped general rule.
        'scoped to write / destructive':
            'For a write or destructive operation, the decision event MUST be durably committed '
            'BEFORE the upstream call.',
        # ROUND 43: the SHORT synonym of the write class — the round-41 control
        # said "write or destructive", which masked the missing `write` token.
        'scoped to write (short synonym only, no "destructive")':
            'For a write, the decision event MUST be durably committed BEFORE the upstream call.',
        'scoped to configuration publication':
            'For configuration publication, the decision event MUST be durably committed BEFORE '
            'the snapshot is signed, pushed or applied.',
    }
    for label, sentence in controls.items():
        ctl = dict(texts)
        ctl['CI-GATES.md'] = ctl['CI-GATES.md'] + '\n' + sentence + '\n'
        quiet = not [x for x in run(ctl) if x not in base]
        print(f'  {"OK (silent)" if quiet else "FALSE POSITIVE"}: {label}')
        ok &= quiet

    print('\n=== residual on LIVE documents (ledger excluded) ===')
    v = run(texts)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')

    led = (D / LEDGER).read_text()
    print(f'\n(ledger excluded by design; it retains {len(ORDERING.findall(led))} historical '
          f'ordering sentence(s))')
    sys.exit(0 if ok and not v else 1)
