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
# A clause ends at the next ';' or at a SENTENCE end.  The terminator may be
# preceded by a closing '**', backtick or bracket — requiring a letter there let
# `… ⇒ **no new configuration revision exists**.` run on into the following
# prose, which could then supply the missing action-keys and produce a false
# `NONE` (round 40, P1).
# shared with predicate-22: the terminator may follow markdown, and the NEXT
# sentence may start lowercase — only real abbreviations and decimals are
# excluded (rounds 40/41)
ABBREV = r'(?<!\be\.g)(?<!\bi\.e)(?<!\bcf)(?<!\bvs)(?<!\betc)(?<!\bapprox)(?<!\bFig)(?<!\bNo)(?<!\bp)(?<!\bpp)'
CLAUSE_END = re.compile(r';|(?<=\S)' + ABBREV + r'(?<!\d)\.\s+')


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


ACTION_CLASS_HEADER = 'Action class'


def action_class_table(path):
    """The DURABILITY-UNAVAILABLE per-ACTION-CLASS table (2 columns), as
    {action-class: behaviour}, plus its header cell.

    Distinct from `perclass_table` above: that one is the 4-column
    irreversible-action table.  This is the 2-column table whose denial row
    #926 rewrote — the row that previously let an UNAUTHENTICATED attacker
    trigger a fleet-wide write lockout.  Both documents carry a copy, and
    before #926 nothing mechanically compared them: the two copies had already
    drifted in the header ('a decision event' vs 'the decision event') and in
    four row bodies, unnoticed.  A safety rule with two copies and no equality
    check is one edit away from meaning two different things.
    """
    rows, header, in_table = {}, None, False
    for line in pathlib.Path(path).read_text().splitlines():
        raw = line.strip()
        if not raw.startswith('|'):
            in_table = False
            continue
        cells = [c.strip() for c in raw.strip('|').split('|')]
        if len(cells) != 2:
            in_table = False
            continue
        if cells[0] == ACTION_CLASS_HEADER:
            in_table, header = True, tuple(cells)
            continue
        if not in_table or set(cells[1]) <= set('-: '):
            continue
        rows[cells[0]] = cells[1]
    return header, rows


def action_class_drift():
    """The two copies of the action-class table must be cell-for-cell identical,
    header included (#926 closure item 9)."""
    ha, a = action_class_table('docs/design/mcp/EVENT-MODEL.md')
    hb, b = action_class_table('docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md')
    v = []
    if not a or not b:
        return ['action-class table not found in one of the two copies — predicate not sound']
    if ha != hb:
        v.append(f'HEADER differs:\n      EVENT-MODEL: {ha}\n      ADR-0024   : {hb}')
    for k in sorted(set(a) | set(b)):
        if k not in a:
            v.append(f'action class {k!r} in ADR-0024 only')
        elif k not in b:
            v.append(f'action class {k!r} in EVENT-MODEL only')
        elif a[k] != b[k]:
            v.append(f'action class {k!r} behaviour differs:\n'
                     f'      EVENT-MODEL: {a[k]}\n      ADR-0024   : {b[k]}')
    return v


# ─── ARM 4: the two post-merge #926 leftovers ────────────────────────────────
# Narrow by construction.  This is NOT a prose linter: it reads exactly two
# named blocks (MCP-AC-016 and OPEN-DECISIONS D-5) and checks four stated
# properties.  It was added because the #926 remediation updated some fields of
# those blocks and not others, leaving a single abuse case that simultaneously
# required the denial-event lockout (Expected control / Expected event /
# Closure) and forbade it (Expected policy result / Test) — and a decision block
# still calling the residual "accepted" while THREAT-MODEL R-6 records it as
# PENDING and not human-accepted.  Both survived a full predicate run, CI, and a
# self-check by the authoring session, because nothing quantified over them.
AC = pathlib.Path('docs/design/mcp/ABUSE-CASES.md')
OD = pathlib.Path('docs/design/mcp/OPEN-DECISIONS.md')

AC016_FIELDS = ('Expected control', 'Expected event', 'Expected policy result', 'Test')

# A POSITIVE requirement for the superseded lockout.  Each pattern is a phrase
# that only appears when the text is DEMANDING the lockout as a desired outcome.
LOCKOUT_POSITIVE = (
    r'DURABILITY LOCKOUT',
    r'durability lockout',
    r'the lockout proven',
    r'operations are blocked\b',
    r'blocking NEW\b',
    r'\bcritical degraded state\b',
)
# Text explicitly labelled as describing the REMOVED rule is allowed anywhere in
# the sentence — these words cannot plausibly introduce a live requirement.
HISTORICAL = (
    r'superseded', r'SUPERSEDED', r'\bformer\b', r'\bno longer\b',
    r'\bremoved\b', r'PROVEN TO FAIL', r'\bnot closed by\b',
)
# A grammatical negation only laundates a positive phrase when it is ATTACHED to
# it.  Scanning the whole sentence was too loose: "If the aggregate cannot be
# committed … operations are blocked" contains `cannot` ~110 chars upstream,
# attached to a different clause, and that alone laundered a genuine lockout
# demand (the seed below caught it).  The window is deliberately short.
NEGATED_NEAR = (r'MUST NOT', r'\bnever\b', r'\bdoes not\b', r'\bcannot\b', r'\bno\b')
NEG_WINDOW = 45


def _ac016_block():
    t = AC.read_text()
    i = t.find('### MCP-AC-016')
    j = t.find('### MCP-AC-017', i + 1)
    return t[i:j if j > 0 else len(t)]


def _fields(block):
    """{field name: its text} for the labelled `- **Name:** …` bullets, plus Closure."""
    out = {}
    for name in AC016_FIELDS:
        k = block.find(f'**{name}:**')
        if k < 0:
            continue
        nxt = block.find('\n- **', k)
        out[name] = block[k:nxt if nxt > 0 else len(block)]
    k = block.find('**Closure:**')
    if k >= 0:
        out['Closure'] = block[k:]
    return out


def _demands_lockout(seg):
    """True when the segment REQUIRES lockout semantics rather than denying them.

    A historical label anywhere in the sentence exempts it; a grammatical
    negation exempts it only when ATTACHED (within NEG_WINDOW chars before the
    positive phrase).  Sentence-wide negation matching was too loose and let a
    real lockout demand pass on an unrelated upstream 'cannot'.

    EVERY occurrence is checked, not the first.  `re.search` returns only the
    leftmost match, so a sentence carrying a NEGATED occurrence followed by a
    POSITIVE one — "no operations are blocked, but operations are blocked until
    recovery" — had its first, exempt match end the scan for that pattern and
    the real demand went unreported.  One laundered occurrence must not grant
    the whole sentence immunity, so the loop is over `finditer`.
    """
    for sentence in re.split(r'(?<=[.;])\s+', seg):
        if any(re.search(h, sentence) for h in HISTORICAL):
            continue
        for pat in LOCKOUT_POSITIVE:
            prev_end = 0
            for m in re.finditer(pat, sentence):
                # The window must not reach back ACROSS a previous occurrence:
                # in "no operations are blocked, but operations are blocked
                # until recovery" a plain 45-char lookback around the SECOND
                # match still swallows the FIRST match's "no", so the negation
                # attached to one occurrence would exempt the next.  Each
                # occurrence gets its own window, bounded by the prior match.
                start = max(m.start() - NEG_WINDOW, prev_end)
                near = sentence[start:m.start()]
                prev_end = m.end()
                if not any(re.search(n, near) for n in NEGATED_NEAR):
                    return sentence.strip()
    return None


TM = pathlib.Path('docs/design/mcp/THREAT-MODEL.md')


def _r6_status():
    """R-6's CURRENT acceptance state, parsed from THREAT-MODEL §12.

    Returns 'pending', 'accepted', or None when the row cannot be classified.
    None is a violation, not a pass: an unclassifiable authority means the
    cross-document comparison below cannot be made, and a check that cannot be
    made must not report success.
    """
    for line in TM.read_text().splitlines():
        s = line.strip()
        if not s.startswith('| R-6 |'):
            continue
        if re.search(r'NOT accepted by a named human|acceptance PENDING', s):
            return 'pending'
        if re.search(r'\bACCEPTED\b|accepted by \*\*|accepted on \d{4}-\d{2}-\d{2}', s):
            return 'accepted'
        return None
    return None


def ac016_d5_drift():
    v = []
    block = _ac016_block()
    if not block:
        return ['MCP-AC-016 not found — predicate not sound']
    fields = _fields(block)
    missing = [f for f in AC016_FIELDS + ('Closure',) if f not in fields]
    if missing:
        return [f'MCP-AC-016 missing field(s) {missing} — predicate not sound']

    # (1) + (2): no field may demand the lockout, so all five necessarily agree.
    stances = {}
    for name, seg in fields.items():
        hit = _demands_lockout(seg)
        stances[name] = 'lockout' if hit else 'denial-lane'
        if hit:
            v.append(f'MCP-AC-016 "{name}" states POSITIVE denial-event lockout semantics -> {hit[:130]!r}')
    if len(set(stances.values())) > 1:
        v.append(f'MCP-AC-016 fields disagree: {stances}')

    # The closure must assert the ATTACK FAILS, not that a lockout happened.
    if not re.search(r'ATTACK PROVEN TO FAIL|attack .{0,20}fail', fields['Closure'], re.I):
        v.append('MCP-AC-016 Closure does not assert the lockout ATTACK failed')

    # (3) + (4): D-5's residual status and evidence range.
    t = OD.read_text()
    i = t.find('### D-5')
    j = t.find('### D-6', i + 1)
    d5 = t[i:j if j > 0 else len(t)]
    if not d5:
        return v + ['OPEN-DECISIONS D-5 not found — predicate not sound']
    k = d5.find('**Residual risk:**')
    residual = d5[k:d5.find('\n  - **', k + 1) if d5.find('\n  - **', k + 1) > 0 else len(d5)] if k >= 0 else ''
    if not residual:
        v.append('D-5 has no Residual risk field — predicate not sound')
    else:
        if not re.search(r'`?R-6`?', residual):
            v.append('D-5 residual does not reference R-6')
        # The required status is READ FROM R-6, never hard-coded.  Hard-coding
        # `PENDING` here would break in both directions the moment R-6 is
        # accepted: a correctly-updated D-5 would fail CI, and a STALE D-5 still
        # claiming PENDING would pass — which is precisely the cross-document
        # drift this check exists to catch.  The authority is THREAT-MODEL §12.
        r6 = _r6_status()
        if r6 is None:
            v.append('R-6 status not parseable from THREAT-MODEL §12 — predicate not sound')
        elif r6 == 'pending':
            if not re.search(r'PENDING', residual):
                v.append("D-5 residual does not reproduce R-6's PENDING status")
            # "accepted" is allowed only as an explicit denial of acceptance.
            for sentence in re.split(r'(?<=[.;])\s+', residual):
                if re.search(r'\baccepted\b', sentence) and \
                   not re.search(r'NOT accepted|not accepted|does \*\*not\*\* accept|does not accept|stale|never inferred', sentence):
                    v.append(f'D-5 residual claims acceptance while R-6 is PENDING -> {sentence.strip()[:130]!r}')
        elif r6 == 'accepted':
            # R-6 has been accepted by a named human: D-5 must no longer assert
            # the pending state, and must not still deny acceptance.
            for sentence in re.split(r'(?<=[.;])\s+', residual):
                if re.search(r'PENDING|NOT accepted by a named human', sentence) and \
                   not re.search(r'stale|\bformer\b|\bwas\b', sentence):
                    v.append(f'D-5 residual still claims R-6 is PENDING, but R-6 is ACCEPTED -> {sentence.strip()[:130]!r}')
    ev = d5[d5.find('**Evidence:**', d5.find('CLOSED —')):]
    ev = ev[:ev.find('\n  - **')] if ev.find('\n  - **') > 0 else ev
    for need in ('MCP-EVENT-001..007', 'MCP-OPS-005'):
        if need not in ev:
            v.append(f'D-5 evidence omits {need}')
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
            clause = CLAUSE_END.split(flat[m.end():m.end() + CLAUSE_WINDOW])[0]
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
        # ROUND 40 P1: the clause ends at '**.' and the NEXT sentence supplies the
        # missing action-keys.  A boundary matcher that requires a letter before the
        # period runs straight past it and reports the clause complete.
        'CI-GATES: end the publication clause at "**." with the missing keys in the NEXT sentence': (
            'docs/design/mcp/CI-GATES.md',
            ('configuration publication ⇒ **no new configuration revision exists, nothing was signed or pushed, and every DP remains on the prior epoch**',
             'configuration publication ⇒ **no new configuration revision exists**. Separately the snapshot is signed and pushed and every DP stays on the prior epoch')),
        # ROUND 41 P1: the clause's sentence is followed by a LOWERCASE-starting
        # sentence carrying the missing keys.
        'CI-GATES: publication clause followed by a lowercase-starting sentence with the missing keys': (
            'docs/design/mcp/CI-GATES.md',
            ('configuration publication ⇒ **no new configuration revision exists, nothing was signed or pushed, and every DP remains on the prior epoch**',
             'configuration publication ⇒ **no new configuration revision exists**. signing and pushing are covered elsewhere, and every DP stays on the prior epoch')),
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

    print('\n=== ARM 3: the two copies of the ACTION-CLASS table must agree (#926) ===')
    d3 = action_class_drift()
    print('\n'.join('  ' + x for x in d3) if d3
          else '  NONE (EVENT-MODEL §4a == ADR-0024 §D-5, header + every row)')

    print('\n=== ARM 3 seeded known-positives (each MUST fire) ===')
    _src = pathlib.Path('docs/design/mcp/EVENT-MODEL.md')
    _orig = _src.read_text()
    arm3_seeds = {
        'drop the denial row from EVENT-MODEL only':
            ('| Authentication failure **or** authorization denial |', '| Authentication failure REWORDED |'),
        'reinstate the emergency-policy bypass in EVENT-MODEL only':
            ('and no emergency-policy bypass.**',
             'unless an explicitly approved emergency policy states otherwise.**'),
        'widen the EVENT-MODEL write row past its durability domain':
            ('| Write action | **Fail closed** (deny the operation) **AND** enter `critical-durability-degraded` **scoped to the affected durability domain only**',
             '| Write action | **Fail closed** (deny the operation) **AND** enter `critical-durability-degraded` **fleet-wide**'),
        'silently change the shared header in EVENT-MODEL only':
            ('| Action class | Behavior when the decision event cannot be durably persisted |',
             '| Action class | Behavior when a decision event cannot be durably persisted |'),
    }
    try:
        for label, (old, new) in arm3_seeds.items():
            if old not in _orig:
                print(f'  SEED-DID-NOT-APPLY: {label}')
                ok = False
                continue
            _src.write_text(_orig.replace(old, new, 1))
            got = action_class_drift()
            print(f'  {"FIRES" if got else "MISSED"}: {label}'
                  + (f' -> {got[0].splitlines()[0][:90]}' if got else ''))
            ok &= bool(got)
    finally:
        _src.write_text(_orig)

    print('\n=== ARM 4: MCP-AC-016 + OPEN-DECISIONS D-5 consistency (#926 post-merge) ===')
    d4 = ac016_d5_drift()
    print('\n'.join('  ' + x for x in d4) if d4
          else '  NONE (no positive lockout semantics; five fields agree; D-5 residual PENDING; evidence current)')

    print('\n=== ARM 4 seeded known-positives (each MUST fire) ===')
    # The first two reproduce the ACTUAL text that survived the #926 merge.
    arm4_seeds = {
        'LIVE DEFECT 1a: restore the pre-fix Expected control (demands a DURABILITY LOCKOUT)': (
            AC,
            ('Aggregate-commit failure enters **`denial-lane-degraded` only**, with its own distinct loss counter.',
             'instead **critical degraded state + alert + loss counter + a DURABILITY LOCKOUT blocking NEW *allowed* '
             'write/high-risk operations until durability is restored**.')),
        'LIVE DEFECT 1b: restore the pre-fix Closure ("the lockout proven")': (
            AC,
            ('**Closure:** zero critical loss demonstrated **and the lockout ATTACK PROVEN TO FAIL**',
             '**Closure:** zero critical loss demonstrated **and** the lockout proven')),
        'LIVE DEFECT 2a: restore the stale D-5 residual ("accepted, alertable")': (
            OD,
            ('  - **Residual risk:** tracked as **`R-6`**',
             '  - **Residual risk:** critical-event blocking of new writes during a persistence outage is an '
             'availability trade-off (accepted, alertable); tracked as **`R-6`**')),
        'LIVE DEFECT 2b: revert D-5 evidence to the stale MCP-EVENT-001..006 range': (
            OD,
            ('**MCP-EVENT-001..007** and **MCP-OPS-005**.', 'MCP-EVENT-001..006.')),
        'MCP-AC-016 field disagreement: weaken ONLY Expected event back to blocking': (
            AC,
            ('and **no authenticated operation is blocked anywhere**',
             'and subsequent allowed write/high-risk operations are blocked')),
        # Codex P2 on #971: `re.search` inspects only the LEFTMOST match, so a
        # negated occurrence followed by a positive one exempted the whole
        # pattern for that sentence.  This seed is that exact shape.
        'NEGATED-THEN-POSITIVE: an exempt occurrence must not immunise a later demand': (
            AC,
            ('and **no authenticated operation is blocked anywhere**',
             'and no operations are blocked, but operations are blocked until recovery')),
        # Codex P2 on #971: the required status must be READ from R-6, not
        # hard-coded.  Flipping R-6 to ACCEPTED while D-5 still says PENDING is
        # the stale-D-5 direction, which a hard-coded PENDING check passes.
        'R-6 ACCEPTED while D-5 still claims PENDING (stale cross-document state)': (
            TM,
            ('**SRE / Reliability** (proposed owner — **acceptance PENDING approval, NOT accepted by a named human**)',
             '**SRE / Reliability** — **ACCEPTED** 2026-08-01')),
    }
    originals = {AC: AC.read_text(), OD: OD.read_text(), TM: TM.read_text()}
    try:
        for label, (target, (old, new)) in arm4_seeds.items():
            if old not in originals[target]:
                print(f'  SEED-DID-NOT-APPLY: {label}')
                ok = False
                continue
            target.write_text(originals[target].replace(old, new, 1))
            got = ac016_d5_drift()
            print(f'  {"FIRES" if got else "MISSED"}: {label}' + (f' -> {got[0][:110]}' if got else ''))
            ok &= bool(got)
            target.write_text(originals[target])
    finally:
        for f, src in originals.items():
            f.write_text(src)

    print('\n=== residual on the live documents ===')
    v = run(SITES)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')
    sys.exit(0 if ok and not v and not d and not d3 and not d4 else 1)
