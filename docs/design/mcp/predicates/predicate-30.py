#!/usr/bin/env python3
"""Predicate 30 — the MCP PR-1 entry closure must stay internally consistent and
must not silently reopen any closed entry decision.

Why this exists.  This PR closes every open MCP PR-1 entry gate: ADR-0024 is
Accepted, D-1 and D-15 are CLOSED, the five board blockers (#925-#929) are
recorded complete, and #923's final state is `PR-1 implementation: GO`.  Those
facts live in prose across four authority documents; a later edit could quietly
revert one — flip the ADR back to Proposed, re-admit `2025-03-26`, re-enable a
legacy SSE fallback, restore a fake human-signature gate, add a listener to
PR-1 scope — and every other CI job would stay green because none of them parse
these documents.  This predicate is that guard: it parses
`PR1-ENTRY-CLOSURE.md` as the primary authority, cross-checks it against
ADR-0024, `OPEN-DECISIONS.md` and `MCP-OPERATION-REGISTRY.md`, and fails CI when
any closure invariant is reverted.

Authorities:
  * `PR1-ENTRY-CLOSURE.md`  — the concise closure source of truth (must exist,
    non-vacuous, five-row blocker table, exact version/method/scope sections).
  * `docs/adr/0024-...md`   — Status MUST be Accepted (never Proposed).
  * `OPEN-DECISIONS.md`     — D-1 CLOSED, D-15 CLOSED (both `### D-*` blocks).
  * `MCP-OPERATION-REGISTRY.md` — the six-method admitted surface, cross-checked.

Scope, stated so nobody over-reads it.  This parses a small, explicit set of
named sections and cross-references in these four documents.  It is NOT a
general Markdown linter and does not police prose outside the anchors it names;
historical descriptions and post-V1 roadmap text are deliberately allowed (see
the negative controls).

Run from the repository root:

    python3 docs/design/mcp/predicates/predicate-30.py

Exit 0 = every closure invariant holds, every seed fired, every negative
control stayed silent.  Exit 1 = at least one violation, printed.
Stdlib only; no network, no third-party imports, no repository mutation.
"""

import pathlib
import re
import sys

CLOSURE_DOC = 'docs/design/mcp/PR1-ENTRY-CLOSURE.md'
ADR_DOC = 'docs/adr/0024-mcp-agent-security-gateway-trust-boundary.md'
OPEN_DOC = 'docs/design/mcp/OPEN-DECISIONS.md'
REGISTRY_DOC = 'docs/design/mcp/MCP-OPERATION-REGISTRY.md'
DOCS = {'clo': CLOSURE_DOC, 'adr': ADR_DOC, 'open': OPEN_DOC, 'reg': REGISTRY_DOC}

BASELINE_SHA = '6810fce9bc52c3f567ef6c20630f1c510cc267b6'
SUPPORTED = {'2025-11-25', '2025-06-18'}          # exact V1 supported set
REJECTED = {'2024-11-05', '2025-03-26', '2026-07-28'}  # explicitly rejected
BLOCKERS = ('925', '926', '927', '928', '929')
METHODS = {'initialize', 'notifications/initialized', 'ping',
           'notifications/cancelled', 'tools/list', 'tools/call'}
BLOCKER_NCOLS = 5

VERSION = re.compile(r'20\d\d-\d\d-\d\d')
# a line that negates, so a committee/signature MENTION is a disclaimer not a gate
NEG = re.compile(r'\b(no|not|never|without|no longer|retired|removed|deleted|'
                 r"is not|are not|isn't|neither|none|does not|do not)\b", re.I)
# a stale organizational / human-signature / committee gate presented as required.
# Deliberately NARROW: it triggers on ARB / committee / formal-ratification /
# role-signature language, NOT on the legitimate "named human owner/approver"
# decision-template vocabulary the design package uses for slice decisions.
STALE_GATE = re.compile(
    r'(ARB|Architecture Review Board)\b[^.\n]{0,55}(ratif|sign-?off|review board|approv|attend)'
    r'|(await|pending|require[sd]?|before\s+PR-1|not yet satisfied|blocks?\s+PR-1)'
    r'[^.\n]{0,60}(ARB|Architecture Review Board|committee|formal ratification|role[- ]signatures?)'
    r'|(committee|role[- ]signatures?|human sign-?off|ARB[- ]attendance)'
    r'[^.\n]{0,60}(require[sd]?|before\s+PR-1|ratif|sign-?off|must be|attend)',
    re.I)


def _sentences(txt):
    """Whitespace-normalized sentences.  Soft-wrapped Markdown splits a single
    sentence across physical lines; a raw line scan therefore mis-attributes a
    negation on one line to the wrong clause on the next, so the batch detector
    quantifies over sentences, not lines."""
    flat = re.sub(r'\s+', ' ', txt.replace('\n', ' '))
    return re.split(r'(?<=[.!?])\s+', flat)


def _units(txt):
    """Structure-aware scan units: soft-wrapped PROSE lines merge (so a negation
    is read with its own clause), but table rows, list items, blank lines and
    headings each stay separate (so a table cell's `require` is not masked by an
    unrelated `no` in a neighbouring cell).  The committee/signature detector
    quantifies over these units, because a restored gate typically lives in a
    period-free table cell where sentence-splitting would over-merge."""
    units, cur = [], ''
    for ln in txt.splitlines():
        s = ln.strip()
        is_break = (not s) or s.startswith('|') or s.startswith('#') \
            or re.match(r'^([-*+]\s|\d+\.\s|>)', s)
        if is_break:
            if cur:
                units.append(cur)
                cur = ''
            if s:
                units.append(s)
        else:
            cur = (cur + ' ' + s).strip() if cur else s
    if cur:
        units.append(cur)
    return units


# ── section + table helpers ───────────────────────────────────────────────────
def section(text, header_regex):
    """The body of the heading whose text matches `header_regex`, up to the next
    heading of the same or shallower level (None if the heading is absent)."""
    lines = text.splitlines()
    start = level = None
    for i, ln in enumerate(lines):
        m = re.match(r'^(#{1,6})\s+(.*)$', ln)
        if m and re.search(header_regex, m.group(2)):
            start, level = i + 1, len(m.group(1))
            break
    if start is None:
        return None
    out = []
    for ln in lines[start:]:
        m = re.match(r'^(#{1,6})\s', ln)
        if m and len(m.group(1)) <= level:
            break
        out.append(ln)
    return '\n'.join(out)


def _cells(line):
    s = line.strip()
    if s.startswith('|'):
        s = s[1:]
    if s.endswith('|'):
        s = s[:-1]
    return [c.strip() for c in s.split('|')]


def parse_blocker_table(sec):
    """(ok, rows) for the §2 blocker table — a GFM table of exactly BLOCKER_NCOLS
    columns with >= len(BLOCKERS) data rows.  A mis-shaped or vacuous table is an
    UNCONDITIONAL failure (every row check below quantifies over the rows)."""
    if sec is None:
        return False, []
    lines = sec.splitlines()
    hi = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith('|') and 'Blocker' in ln and 'State' in ln:
            hi = i
            break
    if hi is None or hi + 1 >= len(lines):
        return False, []
    if len(_cells(lines[hi])) != BLOCKER_NCOLS:
        return False, []
    delim = _cells(lines[hi + 1])
    if len(delim) != BLOCKER_NCOLS or not all(re.fullmatch(r':?-{3,}:?', c) for c in delim):
        return False, []
    rows = []
    for ln in lines[hi + 2:]:
        if not ln.strip().startswith('|'):
            break
        c = _cells(ln)
        if len(c) != BLOCKER_NCOLS:
            return False, []
        rows.append(c)
    if len(rows) < len(BLOCKERS):
        return False, rows
    return True, rows


def decision_block(text, dec):
    """The body of the `### <dec>` block in OPEN-DECISIONS.md (heading → next
    `### D-*` heading or `## ` section), or None if the heading is absent."""
    out, cur = [], False
    for ln in text.splitlines():
        m = re.match(r'^###\s+(D-\d+)\b', ln)
        if m:
            cur = (m.group(1) == dec)
            continue
        if cur:
            if re.match(r'^##\s', ln):
                break
            out.append(ln)
    return '\n'.join(out) if out else None


# ── detectors ─────────────────────────────────────────────────────────────────
def check(texts):
    clo = texts['clo']
    adr = texts['adr']
    op = texts['open']
    reg = texts['reg']
    v = []

    # (0) closure doc present + non-vacuous
    if not clo.strip() or 'MCP PR-1 Entry Closure' not in clo:
        v.append('PR1-ENTRY-CLOSURE.md is missing or vacuous (no closure authority to validate)')
        return v  # every check below quantifies over the closure doc; stop.

    # (1) baseline SHA recorded
    if BASELINE_SHA not in clo:
        v.append(f'closure doc does not record the baseline commit {BASELINE_SHA}')

    # (2) blocker table: five rows, each recorded complete/closed
    ok, rows = parse_blocker_table(section(clo, r'2\. Closed board blockers'))
    if not ok:
        v.append('the §2 blocker table is malformed, mis-shaped or has fewer than '
                 f'{len(BLOCKERS)} data rows (a zero/short closure table must fail)')
        rows = []
    # Derive the blocker identity from the FIRST (Blocker) column of each row, not
    # a collective search over every cell — otherwise five duplicate rows for one
    # blocker pass as long as some Evidence cell happens to mention the others.
    row_ids = []
    for r in rows:
        ids = re.findall(r'#(9\d\d)\b', r[0])  # the '#NNN'-prefixed id in the Blocker cell
        if len(ids) != 1:
            v.append(f'blocker row {r[0]!r} does not name exactly one #NNN blocker id in its Blocker column')
            continue
        row_ids.append(ids[0])
        state = r[3].lower()
        if 'closed' not in state or ('complete' not in state and 'completed' not in state):
            v.append(f'blocker row {r[0]!r} is not recorded closed/completed (state={r[3]!r})')
    if sorted(set(row_ids)) != sorted(BLOCKERS):
        v.append(f'the closure blocker rows are not exactly {sorted(BLOCKERS)} '
                 f'(got {sorted(row_ids)}) — missing or unexpected blocker ids')
    if len(row_ids) != len(set(row_ids)):
        v.append('the closure blocker table has duplicate blocker rows')

    # (3) ADR-0024 Accepted, never Proposed (the authority file itself)
    if not re.search(r'\*\*Status:\*\*\s*Accepted', adr):
        v.append('ADR-0024 Status is not Accepted')
    if re.search(r'\*\*Status:\*\*\s*Proposed', adr):
        v.append('ADR-0024 Status is (re)set to Proposed')
    if not re.search(r'ADR-0024[^.\n]{0,40}Accepted|Status:\s*Accepted', clo):
        v.append('closure doc does not record ADR-0024 as Accepted')

    # (4) D-1 CLOSED in its OPEN-DECISIONS block (a reopen must fail)
    d1 = decision_block(op, 'D-1')
    if d1 is None:
        v.append('OPEN-DECISIONS.md has no `### D-1` block to validate')
    else:
        if not re.search(r'\bCLOSED\b', d1) or re.search(r'remains \*{0,2}OPEN|Still OPEN|STATUS:\s*OPEN', d1):
            v.append('D-1 is not CLOSED in its OPEN-DECISIONS `### D-1` block (a reopen must fail)')

    # (5) D-15 CLOSED — implementation contract accepted (not human-approved)
    d15 = decision_block(op, 'D-15')
    if d15 is None:
        v.append('OPEN-DECISIONS.md has no `### D-15` block to validate')
    else:
        if not re.search(r'CLOSED\s+—\s+implementation contract accepted', d15):
            v.append('D-15 is not `CLOSED — implementation contract accepted` in its block')
        if re.search(r'\bhuman-approved\b', d15):
            v.append('D-15 is described as human-approved (must be `CLOSED — implementation contract accepted`)')

    # (6) supported version set is EXACTLY {2025-11-25, 2025-06-18}
    sup = section(clo, r'3\.1 Supported versions')
    if sup is None:
        v.append('closure doc has no §3.1 Supported versions section')
    else:
        # supported set = versions in the §3.1 TABLE data rows (any row that is not
        # the header or the delimiter); the rejected revisions live in prose, never
        # in the table.
        table_versions = set()
        for ln in sup.splitlines():
            s = ln.strip()
            if not s.startswith('|'):
                continue
            if re.search(r'\bRole\b', s) or re.fullmatch(r'\|(?:\s*:?-{3,}:?\s*\|)+', s):
                continue
            table_versions |= set(VERSION.findall(s))
        if table_versions != SUPPORTED:
            v.append(f'the supported-version set is not exactly {sorted(SUPPORTED)}: {sorted(table_versions)}')
        # every explicitly-rejected revision must appear in §3.1 (the rejected prose)
        sup_versions = set(VERSION.findall(sup))
        for x in REJECTED:
            if x not in sup_versions:
                v.append(f'the explicitly-rejected revision {x} is not recorded as rejected in §3.1')
            elif x in table_versions:
                v.append(f'the rejected revision {x} appears in the supported-version table')

    # (7) batch: rejected/unsupported in §3.5; NEVER affirmatively supported anywhere.
    # Sentence-scoped so a "never split, ... dispatched" clause cannot mask a
    # sibling "batch is supported" sentence on the same wrapped line.
    batch = section(clo, r'3\.5 Batch')
    if batch is None or not re.search(r'\b(unsupported|rejected)\b', batch, re.I):
        v.append('§3.5 does not state that JSON-RPC batch is unsupported/rejected')
    for sent in _sentences(clo):
        if re.search(r'\bbatch\b[^.]{0,45}\b(accepted|supported|enabled)\b', sent, re.I) and not NEG.search(sent):
            v.append(f'a sentence affirmatively enables JSON-RPC batch (V1 rejects it): {sent.strip()[:90]!r}')

    # (8) method surface: §3.6 admits EXACTLY the six methods, cross-checked vs the registry
    msec = section(clo, r'3\.6 Method surface')
    if msec is None:
        v.append('closure doc has no §3.6 Method surface section')
    else:
        found = set(re.findall(r'`([a-z]+(?:/[a-z]+)?)`', msec))
        found = {m for m in found if '/' in m or m in {'initialize', 'ping'}}
        if found != METHODS:
            extra = sorted(found - METHODS)
            missing = sorted(METHODS - found)
            v.append(f'the §3.6 admitted-method set is not exactly the six methods '
                     f'(extra={extra}, missing={missing})')
    for m in METHODS:
        if f'`{m}`' not in reg:
            v.append(f'the operation registry does not name admitted method `{m}`')

    # (9) transport: no legacy SSE, Streamable-HTTP-only, GET-without-context terminal 405
    trans = section(clo, r'3\.2 Transport')
    if trans is None or not re.search(r'no[^.\n]{0,20}legacy', trans, re.I):
        v.append('§3.2 does not state that V1 hosts no legacy HTTP+SSE transport')
    if trans is not None and not re.search(r'\b405\b', trans):
        v.append('§3.2 does not record the GET-without-context → terminal 405 rule')
    for ln in clo.splitlines():
        if re.search(r'\b(host|hosts|enabl\w+|allow\w*|offer\w*)\b[^.\n]{0,35}legacy'
                     r'[^.\n]{0,25}(SSE|2024-11-05|HTTP\+SSE)', ln, re.I):
            if not NEG.search(ln) and not re.search(r'\b(historic|formerly|used to|prior|the spec|SDK|probe)\b', ln, re.I):
                v.append(f'a line positively hosts/enables a legacy SSE transport: {ln.strip()[:90]!r}')

    # (10) sessionless missing-header ruling recorded as 400 (never unresolved)
    ns = section(clo, r'3\.4 Sessionless')
    if ns is None:
        v.append('closure doc has no §3.4 Sessionless missing version header section')
    else:
        # tolerate Markdown emphasis inside "does **not** silently assume `2025-03-26`"
        if not (re.search(r'\b400\b', ns) and re.search(r'silently\s+assume', ns, re.I)
                and re.search(r'2025-03-26', ns) and re.search(r'\b(not|never|MUST NOT)\b', ns, re.I)):
            v.append('§3.4 does not record the sessionless missing-header → 400 / no-silent-2025-03-26 ruling')
    if re.search(r'sessionless[^.\n]{0,70}(unresolved|undecided|open question|not yet decided|to be decided)', clo, re.I):
        v.append('the sessionless missing-header ruling is presented as unresolved/undecided')

    # (11) #923 final state = GO, never NO-GO
    if not re.search(r'PR-1 implementation(?:\s+is|:)?\s*\*{0,2}`?GO\b(?!-)', clo):
        v.append('closure doc does not state PR-1 implementation is GO')
    for ln in clo.splitlines():
        if re.search(r'PR-1[^.\n]{0,30}NO-GO', ln, re.I) and not re.search(r'\b(was|were|previously|no longer|former)\b', ln, re.I):
            v.append(f'closure doc asserts PR-1 NO-GO: {ln.strip()[:90]!r}')

    # (12) all four entry gates COMPLETE
    gsec = section(clo, r'8\. Four PR-1 entry gates')
    if gsec is None:
        v.append('closure doc has no §8 entry-gate section')
    else:
        completes = len(re.findall(r'\*\*COMPLETE\*\*', gsec))
        if completes < 4:
            v.append(f'fewer than four entry gates are marked COMPLETE (found {completes})')
        if re.search(r'\b(INCOMPLETE|NO-GO|not (?:yet )?(?:complete|satisfied)|OPEN)\b', gsec):
            v.append('an entry gate is marked incomplete/open/NO-GO in §8')

    # (13) PR-1 scope stays kernel-only — no listener/OAuth/policy/credential/runtime in the ALLOWED scope
    allowed = section(clo, r'9\. PR-1 allowed scope')
    if allowed is None:
        v.append('closure doc has no §9 PR-1 allowed-scope section')
    else:
        for ln in allowed.splitlines():
            if re.search(r'\b(bound|production|public)\b[^.\n]{0,20}\blistener\b'
                         r'|\bOAuth\b|credential brok\w+|policy enforcement|upstream execution'
                         r'|Management MCP implementation', ln, re.I):
                if not NEG.search(ln):
                    v.append(f'PR-1 allowed scope is widened beyond the kernel: {ln.strip()[:90]!r}')
    prohibited = section(clo, r'10\. PR-1 prohibited scope')
    if prohibited is None or not re.search(r'\blistener\b', prohibited, re.I) \
       or not re.search(r'\b(identity|auth|OAuth)\b', prohibited, re.I) \
       or not re.search(r'policy', prohibited, re.I) or not re.search(r'credential', prohibited, re.I):
        v.append('§10 does not prohibit the full listener/identity/policy/credential runtime surface')

    # (14) no stale ARB / committee / human-signature GATE presented as required.
    # Sentence-scoped + negation-guarded, so "there is no ARB/committee ratification
    # step" (a disclaimer) is silent while "role signatures are required before PR-1"
    # (a restored gate) fires.
    for name, txt in (('closure', clo), ('ADR', adr), ('OPEN-DECISIONS', op)):
        for unit in _units(txt):
            if STALE_GATE.search(unit) and not NEG.search(unit):
                v.append(f'a stale ARB/committee/role-signature requirement remains in {name}: {unit.strip()[:90]!r}')

    return v


# ── self-test harness (seeds must fire; controls must stay silent) ────────────
def _mut(texts, key, fn):
    out = dict(texts)
    out[key] = fn(texts[key])
    return out


BLK_DELIM5 = '|---|---|---|---|---|'
BLK_DELIM4 = '|---|---|---|---|'

SEEDS = [
    ('ADR reverted to Proposed',
     lambda t: _mut(t, 'adr', lambda s: s.replace('**Status:** Accepted', '**Status:** Proposed', 1)),
     'Proposed'),
    ('D-1 reopened',
     lambda t: _mut(t, 'open', lambda s: s.replace('**CLOSED — 2026-07-31. V1 protocol baseline frozen.**',
                    'remains OPEN — pending external verification.', 1)),
     'D-1 is not CLOSED'),
    ('D-15 reopened',
     lambda t: _mut(t, 'open', lambda s: s.replace('CLOSED — implementation contract accepted',
                    'OPEN — recommendation recorded, NOT human-approved', 1)),
     'D-15 is not'),
    ('2025-03-26 admitted to supported set',
     lambda t: _mut(t, 'clo', lambda s: s.replace('| Compatibility floor | `2025-06-18` |',
                    '| Compatibility floor | `2025-06-18` |\n| Fallback | `2025-03-26` |', 1)),
     'supported-version set is not exactly'),
    ('2026-07-28 admitted to supported set',
     lambda t: _mut(t, 'clo', lambda s: s.replace('| Compatibility floor | `2025-06-18` |',
                    '| Compatibility floor | `2025-06-18` |\n| Next | `2026-07-28` |', 1)),
     'supported-version set is not exactly'),
    ('batch enabled',
     lambda t: _mut(t, 'clo', lambda s: s.replace('batch arrays are unsupported', 'batch arrays are supported', 1)),
     'affirmatively enables JSON-RPC batch'),
    ('seventh method admitted',
     lambda t: _mut(t, 'clo', lambda s: s.replace('- `tools/call`', '- `tools/call`\n- `resources/read`', 1)),
     'admitted-method set is not exactly'),
    ('legacy SSE enabled',
     lambda t: _mut(t, 'clo', lambda s: s.replace('## 11. Final statement',
                    'Culvert hosts a legacy 2024-11-05 HTTP+SSE endpoint pair for compatibility.\n\n## 11. Final statement', 1)),
     'positively hosts/enables a legacy SSE transport'),
    ('sessionless header rule returned to unresolved',
     lambda t: _mut(t, 'clo', lambda s: s.replace('is **rejected with HTTP `400`**',
                    'is left unresolved and undecided for the sessionless case', 1)),
     'sessionless'),
    ('fake human-signature gate restored',
     lambda t: _mut(t, 'clo', lambda s: s.replace('**no human role signatures**',
                    'eight named human role signatures are required before PR-1', 1)),
     'stale ARB/committee/role-signature requirement'),
    ('tracker returned to NO-GO',
     lambda t: _mut(t, 'clo', lambda s: s.replace('**MCP PR-1 implementation is GO.**',
                    'MCP PR-1 implementation is NO-GO.', 1).replace('`PR-1 implementation: GO`',
                    '`PR-1 implementation: NO-GO`', 1)),
     'PR-1 NO-GO'),
    ('listener added to PR-1 scope',
     lambda t: _mut(t, 'clo', lambda s: s.replace('## 10. PR-1 prohibited scope',
                    '- A bound production listener and public ingress.\n\n## 10. PR-1 prohibited scope', 1)),
     'allowed scope is widened beyond the kernel'),
    ('closure doc missing',
     lambda t: _mut(t, 'clo', lambda s: ''),
     'missing or vacuous'),
    ('duplicate correct-then-wrong batch claim',
     lambda t: _mut(t, 'clo', lambda s: s.replace('## 11. Final statement',
                    'Note: for compatibility a JSON-RPC batch array is accepted and partially dispatched.\n\n## 11. Final statement', 1)),
     'affirmatively enables JSON-RPC batch'),
    ('malformed / short blocker table',
     lambda t: _mut(t, 'clo', lambda s: s.replace(BLK_DELIM5, BLK_DELIM4, 1)),
     'blocker table is malformed'),
    ('duplicate blocker row (renumber #926 -> #925)',
     lambda t: _mut(t, 'clo', lambda s: s.replace(
         '[#926](https://github.com/KidCarmi/Culvert/issues/926) | RPR-2',
         '[#925](https://github.com/KidCarmi/Culvert/issues/925) | RPR-2', 1)),
     'not exactly'),
]

NEGATIVE_CONTROLS = [
    ('historical description of excluded 2025-03-26 batch behavior',
     lambda t: _mut(t, 'clo', lambda s: s.replace('## 11. Final statement',
                    'Historically, `2025-03-26` permitted JSON-RPC batch arrays; V1 excludes and rejects it.\n\n## 11. Final statement', 1))),
    ('post-V1 roadmap mentioning a future listener and 2026 era',
     lambda t: _mut(t, 'clo', lambda s: s.replace('## 11. Final statement',
                    'A future post-V1 decision may admit a 2026-era revision, and PR-5 owns the bound listener.\n\n## 11. Final statement', 1))),
    ('negated disclaimer that there is no ARB/committee ratification',
     lambda t: _mut(t, 'clo', lambda s: s.replace('## 11. Final statement',
                    'There is no ARB, committee, or human role-signature ratification step required for this closure.\n\n## 11. Final statement', 1))),
    ('historical note that predicates were once not wired to CI',
     lambda t: _mut(t, 'clo', lambda s: s.replace('## 11. Final statement',
                    'The predicates were formerly not wired to CI; they are now a required Fast PR Gate.\n\n## 11. Final statement', 1))),
]


def norm(vs):
    return {re.sub(r'line \d+', 'line N', x) for x in vs}


def main():
    texts = {}
    for name, path in DOCS.items():
        p = pathlib.Path(path)
        if not p.exists():
            print(f'FAIL: {path} not found (run from the repository root)')
            return 1
        texts[name] = p.read_text(encoding='utf-8')

    live_v = check(texts)
    print('=== live documents ===')
    if live_v:
        for x in live_v:
            print(f'  VIOLATION: {x}')
    else:
        print('  closure invariants (ADR Accepted; D-1/D-15 CLOSED; #925-929 complete; '
              'version/method/transport/batch/scope; four gates; GO) -> NONE')

    base = norm(live_v)
    print(f'\n=== seeded known-positives ({len(SEEDS)}, each MUST fire its intended violation) ===')
    missed = []
    for name, fn, expect in SEEDS:
        new = norm(check(fn(texts))) - base
        ok = any(expect in x for x in new)
        print(f'  [{"DETECTED" if ok else "MISSED":8}] {name}')
        if not ok:
            missed.append((name, expect, sorted(new)))

    print(f'\n=== negative controls ({len(NEGATIVE_CONTROLS)}, each MUST stay silent) ===')
    noisy = []
    for name, fn in NEGATIVE_CONTROLS:
        new = norm(check(fn(texts))) - base
        quiet = not new
        print(f'  [{"QUIET" if quiet else "FIRED":8}] {name}')
        if not quiet:
            noisy.append((name, sorted(new)))

    bad = bool(live_v) or missed or noisy
    print()
    if live_v:
        print(f'FAIL: {len(live_v)} violation(s) on the live documents')
    for name, expect, new in missed:
        print(f'FAIL: seed {name!r} did not fire its intended violation (expected {expect!r}); new: {new}')
    for name, new in noisy:
        print(f'FAIL: negative control {name!r} fired: {new}')
    if not bad:
        print('PASS: the MCP PR-1 entry closure is internally consistent — ADR-0024 Accepted; '
              'D-1 and D-15 CLOSED; #925-929 complete; the exact version/method/transport/batch/scope '
              'baseline holds; four gates complete; PR-1 is GO; no stale committee/signature gate remains; '
              'all seeds fire; all negative controls silent.')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
