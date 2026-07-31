#!/usr/bin/env python3
"""Predicate 29 — the MCP transport-fallback posture must be terminal, legacy-free
and evidence-backed, with the 2025 and 2026 protocol eras kept separate.

Why this exists.  Board blocker #929 (transport downgrade / legacy SSE fallback)
turns on a self-amplifying vector: a security-motivated `4xx` on the
initialize/transport path recruits a spec-conformant (or catch-any) SDK client
into the legacy `2024-11-05` HTTP+SSE probe, and a stream opened or held awaiting
an `endpoint` event Culvert never emits becomes an unauthenticated, pre-initialize
held stream per rejected client.  The remediation is documentation-only, so the
only durable guard is a mechanical one: this predicate parses
`TRANSPORT-FALLBACK-EVIDENCE.md` and fails CI when the evidence matrix, the
status-terminal / zero-stream invariants, the legacy exclusion, the era
separation, the Gate-3 amendment record, or the D-1-open governance drift.

Authorities:
  * `TRANSPORT-FALLBACK-EVIDENCE.md` — the 14-column evidence matrix (§4) plus the
    binding invariants (§2 legacy exclusion, §3 no-pre-negotiation-stream, §6
    status posture, §7 sessionless D-1 ruling, §8 Gate-3 amendment, §9 fixtures).
  * `OPEN-DECISIONS.md` — D-1 must remain OPEN.

Scope, stated so nobody over-reads it.  This parses ONE named table and a small,
explicit set of normative sentences in ONE document, plus one cross-reference to
OPEN-DECISIONS.  It is NOT a general Markdown linter and does not police prose
outside the anchors it names.

Run from the repository root:

    python3 docs/design/mcp/predicates/predicate-29.py

Exit 0 = every property holds.  Exit 1 = at least one violation, printed.
Stdlib only; no network, no third-party imports, no repository mutation.
"""

import pathlib
import re
import sys

EVIDENCE_DOC = 'docs/design/mcp/TRANSPORT-FALLBACK-EVIDENCE.md'
OPEN_DOC = 'docs/design/mcp/OPEN-DECISIONS.md'
DOCS = {'evidence': EVIDENCE_DOC, 'open': OPEN_DOC}

MIN_ROWS = 12          # the §4 matrix is non-vacuous well beyond this
NCOLS = 14             # the fourteen required columns
STATUS_VOCAB = ('VERIFIED', 'CONFLICTING', 'UNRESOLVED')
# a VERIFIED locator must pin a revision (date) or a commit, or reference one of
# the abbreviations the legend defines with a pinned commit.
LOCATOR_META = re.compile(r'\b(SPEC|TS|PY|GO)\b|20\d\d-\d\d-\d\d|\b[0-9a-f]{6,40}\b')


# ── matrix parsing ────────────────────────────────────────────────────────────
def _cells(line):
    s = line.strip()
    if s.startswith('|'):
        s = s[1:]
    if s.endswith('|'):
        s = s[:-1]
    return [c.strip() for c in s.split('|')]


def parse_matrix(text):
    """(ok, header, rows) for the §4 evidence matrix.

    ok is False when the table is absent, mis-shaped (header / delimiter / any
    data row not exactly NCOLS cells, or a delimiter cell without >=3 hyphens),
    or vacuous (< MIN_ROWS data rows) — every downstream row check is quantified
    over the rows, so a zero-row parse must be an UNCONDITIONAL failure, never a
    silent pass.
    """
    lines = text.splitlines()
    hi = None
    for i, ln in enumerate(lines):
        if ln.strip().startswith('|') and 'Era / revision' in ln and 'Source locator' in ln:
            hi = i
            break
    if hi is None or hi + 1 >= len(lines):
        return False, [], []
    header = _cells(lines[hi])
    delim = _cells(lines[hi + 1])
    if len(header) != NCOLS or len(delim) != NCOLS:
        return False, header, []
    if not all(re.fullmatch(r':?-{3,}:?', c) for c in delim):
        return False, header, []
    rows = []
    for ln in lines[hi + 2:]:
        if not ln.strip().startswith('|'):
            break
        c = _cells(ln)
        if len(c) != NCOLS:
            return False, header, []
        rows.append(c)
    if len(rows) < MIN_ROWS:
        return False, header, rows
    return True, header, rows


# column indices
C_ERA, C_STAGE, C_TRIG, C_NORM, C_HTTP, C_BODY, C_FOLLOW, C_SDK, \
    C_PROBE, C_STREAM, C_DECISION, C_GATE, C_STATUS, C_LOCATOR = range(NCOLS)

REJECT_STATUS = re.compile(r'\b(400|404|405)\b')


def _decision_block(text, dec):
    """The body of the `### <dec>` decision block in OPEN-DECISIONS.md (the lines
    between its heading and the next `### D-*` heading or `## ` section), or None
    if the heading is absent.  Lets the D-1 status be validated as a block rather
    than by same-line proximity, which the multi-line decision format defeats."""
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
    ev = texts['evidence']
    op = texts['open']
    v = []

    ok, header, rows = parse_matrix(ev)
    if not ok:
        v.append('evidence matrix malformed, mis-shaped or vacuous (§4 must be a '
                 f'valid GFM table of exactly {NCOLS} columns with >= {MIN_ROWS} data rows)')
        # every row check below is quantified over `rows`; with no trustworthy
        # rows they would pass vacuously, so stop here rather than pretend.
        rows = []

    for r in rows:
        stage = r[C_STAGE][:32]
        # (3) every row carries a source locator
        if not r[C_LOCATOR]:
            v.append(f'row [{stage}] has an empty source locator (col 14)')
        # (4) VERIFIED rows must pin a revision/commit (directly or via a legend abbrev)
        if 'VERIFIED' in r[C_STATUS] and not LOCATOR_META.search(r[C_LOCATOR]):
            v.append(f'VERIFIED row [{stage}] locator lacks exact revision/SDK-commit metadata: {r[C_LOCATOR]!r}')
        # (13/first-match) evidence status must be exactly one vocabulary token
        toks = [t for t in STATUS_VOCAB if t in r[C_STATUS]]
        if len(toks) != 1:
            v.append(f'row [{stage}] evidence status is not exactly one of {STATUS_VOCAB}: {r[C_STATUS]!r}')
        # (5) UNRESOLVED rows must NOT read as a binding decision
        if 'UNRESOLVED' in r[C_STATUS]:
            d = r[C_DECISION].lower()
            if not ('unresolved' in d or 'd-1' in d or 'pending' in d):
                v.append(f'UNRESOLVED row [{stage}] presents a binding Culvert decision: {r[C_DECISION]!r}')
        # (11) every 400/404/405 row states a client follow-on that TERMINATES
        # (405 / reinitialize / disconnect / benign / no-stream / a probe trigger
        # that resolves to the terminal 405), and retains zero streams.  A
        # non-empty cell is NOT enough: a cell asserting a non-terminating loop
        # ("retries forever", "never issues a follow-on GET") contradicts the
        # very invariant this gate exists to enforce and MUST fail.
        if REJECT_STATUS.search(r[C_HTTP]):
            follow = r[C_FOLLOW]
            if len(follow) < 5:
                v.append(f'400/404/405 row [{stage}] does not state client follow-on behavior (col 7)')
            elif not re.search(r'\b405\b|terminal|terminates?|re-?initiali|disconnect|benign|no\b[^.\n]{0,14}stream|probe trigger', follow, re.I):
                v.append(f'400/404/405 row [{stage}] follow-on does not resolve to the terminal 405 / zero-retention outcome (col 7 = {follow!r})')
            elif re.search(r'\bforever\b|indefinitel|never (terminat|issu\w+ (a )?follow)|retr\w+[^.\n]{0,20}forever', follow, re.I):
                v.append(f'400/404/405 row [{stage}] follow-on describes a non-terminating loop, contradicting the terminal invariant (col 7 = {follow!r})')
            if r[C_STREAM].lower().split()[:1] != ['no']:
                v.append(f'400/404/405 row [{stage}] permits stream allocation — zero-retention violated (col 10 = {r[C_STREAM]!r})')
        # (6) 2025 and 2026 eras must never be collapsed into one row
        era = r[C_ERA]
        if '2025' in era and '2026' in era:
            v.append(f'row [{stage}] collapses the 2025 and 2026 eras into one era cell: {era!r}')

    # (6) both eras must be represented (non-collapsed coverage)
    if rows:
        eras = ' '.join(r[C_ERA] for r in rows)
        if '2025-era' not in eras:
            v.append('the 2025-era is not represented in the evidence matrix')
        if '2026-era' not in eras:
            v.append('the 2026-era is not represented in the evidence matrix')

    # (14) the 2026-07-28 RC must never be labelled stable/final without a negation
    for ln in ev.splitlines():
        if '2026-07-28' in ln and re.search(r'\b(stable|final)\b', ln, re.I):
            if not re.search(r'\b(not|non-|NOT|excluded|exclude|RC|candidate|comparison|non-final|never)\b', ln):
                v.append(f'the 2026-07-28 RC is labelled stable/final without a negation: {ln.strip()[:90]!r}')

    # (7) legacy 2024-11-05 explicitly excluded, and never positively hosted/enabled
    if not re.search(r'legacy[^.\n]{0,40}2024-11-05|2024-11-05[^.\n]{0,40}legacy', ev, re.I) \
       or not re.search(r'\b(EXCLUD\w*|excluded|NOT HOSTED|not hosted|rejected)\b', ev):
        v.append('the legacy 2024-11-05 HTTP+SSE exclusion statement is missing')
    if re.search(r'hosts?\s+\*{0,2}a\*{0,2}\s+legacy', ev, re.I) \
       or re.search(r'\benabl\w+\s+(a\s+|the\s+)?legacy[^.\n]{0,20}2024', ev, re.I):
        v.append('legacy 2024-11-05 transport is positively hosted/enabled somewhere in the evidence doc')

    # (7b) no config field enables legacy SSE / fallback / unknown transport era
    if re.search(r'transport_fallback|allow_unknown_transport|mcp_[a-z_]*legacy[a-z_]*\s*[:=]|re-enable legacy', ev, re.I):
        v.append('a free-form / legacy-enabling transport configuration field is present')

    # server/Culvert must never positively emit an endpoint event
    if re.search(r'\b(Culvert|the server|it)\s+(emits|MAY emit|will emit)\s+an?\s+\*{0,2}`?endpoint`?\*{0,2}\s+event', ev, re.I):
        v.append('the evidence doc asserts Culvert emits a legacy `endpoint` event')

    # (9) GET-without-context is terminal 405 with zero stream
    if not re.search(r'GET[^.\n]{0,60}\b405\b', ev) or not re.search(r'\b405\b[^.\n]{0,40}(zero|no)[^.\n]{0,20}stream|no[^.\n]{0,20}stream[^.\n]{0,20}405', ev, re.I):
        # tolerate either ordering; require the 405-terminal + zero-stream pairing to exist at all
        if not re.search(r'terminal\s+\*{0,2}`?405`?', ev, re.I):
            v.append('the GET-without-context → terminal 405 / zero-stream statement is missing')

    # (10) no pre-negotiation stream: no line may positively open/hold a GET stream
    for ln in ev.splitlines():
        if re.search(r'\bGET\b', ln) and re.search(r'\b(open|opens|allocate|allocates|hold|holds)\b[^.\n]{0,20}\b(SSE|stream|text/event-stream)', ln, re.I):
            if not re.search(r'\b(no|not|never|MUST NOT|without|forbidden|zero|cannot|may not)\b', ln, re.I):
                v.append(f'a line positively opens/holds a pre-negotiation GET stream: {ln.strip()[:90]!r}')

    # (18) no conflicting terminal status for GET-without-context (duplicate correct-then-wrong)
    for ln in ev.splitlines():
        if re.search(r'GET[^.\n]{0,50}\b(200|201|204|30[0-9])\b', ln) and re.search(r'without[^.\n]{0,30}(session|context)', ln, re.I):
            v.append(f'a conflicting non-405 terminal GET status is claimed: {ln.strip()[:90]!r}')

    # (12) Gate-3 amendment record in the evidence doc: C-6 withdrawn, A-7 removed, C-7 narrowed
    if not re.search(r'C-6[^.\n]{0,40}(withdraw|WITHDRAW)', ev):
        v.append('C-6 is not recorded as withdrawn in the evidence doc')
    if re.search(r'C-6[^.\n]{0,40}(valid|stands|restored|upheld|confirmed)', ev, re.I):
        v.append('C-6 is (re)asserted as a valid/standing conflict')
    if not re.search(r'A-7[^.\n]{0,40}(remove|REMOVE)', ev):
        v.append('A-7 is not recorded as removed in the evidence doc')
    if re.search(r'A-7[^.\n]{0,40}(retain|restored|kept|open decision)', ev, re.I):
        v.append('A-7 is (re)asserted as retained/restored')
    if not re.search(r'C-7[^.\n]{0,40}(narrow|NARROW)', ev):
        v.append('C-7 is not recorded as narrowed in the evidence doc')
    if re.search(r'C-7[^.\n]{0,60}every missing', ev, re.I):
        v.append('C-7 is broadened back to every missing header')

    # (13-gov) D-1 must remain OPEN in the evidence doc AND in OPEN-DECISIONS.
    # The evidence doc states it inline; OPEN-DECISIONS keeps D-1 in a structured
    # `### D-1` block whose status lines are on SEPARATE lines from the heading,
    # so a same-line proximity match would miss a `Still OPEN` → `STATUS: CLOSED`
    # flip (Codex #977 review).  Parse the whole D-1 block and validate its status.
    if not re.search(r'D-1 remains \*{0,2}OPEN', ev) or re.search(r'\bD-1\b[^.\n]{0,20}\bCLOSED\b', ev):
        v.append('the evidence doc does not state that D-1 remains OPEN (or marks it closed)')
    block = _decision_block(op, 'D-1')
    if block is None:
        v.append('OPEN-DECISIONS.md has no `### D-1` decision block to validate')
    else:
        # the block is CLOSED if it carries a closure marker the sibling closed
        # decisions use (`CLOSED`, `Status: closed`) and is not still declared OPEN.
        closed = re.search(r'\bCLOSED\b', block) or re.search(r'status\s*[:=]\s*closed', block, re.I)
        still_open = re.search(r'\bOPEN\b', block)
        if closed or not still_open:
            v.append('D-1 is not marked OPEN in its OPEN-DECISIONS `### D-1` block '
                     '(a closure/removal of the OPEN status must fail this gate)')

    # (15) fixtures: version-set-dependent fixtures are D-1 BLOCKED and never pre-marked green
    if ev.count('D-1 BLOCKED') < 1:
        v.append('no fixture is marked D-1 BLOCKED (version-set-dependent fixtures must be)')
    for ln in ev.splitlines():
        if re.search(r'marked green|green before D-1|green — implemented|green -- implemented|green — implemented', ln, re.I):
            if not re.search(r'\b(MUST NOT|must not|not|never|without|cannot|no)\b', ln):
                v.append('a D-1-dependent fixture is marked green before D-1 closes')

    # cross-reference: the owning requirement + threat must exist
    if 'MCP-PROTO-017' not in ev:
        v.append('evidence doc does not reference the owning requirement MCP-PROTO-017')
    if 'MCP-T-078' not in ev:
        v.append('evidence doc does not reference the owning threat MCP-T-078')

    return v


# ── self-test harness (seeds must fire; controls must stay silent) ────────────
def _mut(texts, key, fn):
    out = dict(texts)
    out[key] = fn(texts[key])
    return out


DELIM14 = '| ' + ' | '.join(['---'] * NCOLS) + ' |'
DELIM13 = '| ' + ' | '.join(['---'] * (NCOLS - 1)) + ' |'

SEEDS = [
    ('legacy SSE endpoint enabled',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('hosts **no** legacy `2024-11-05`', 'hosts **a** legacy `2024-11-05`', 1)),
     'positively hosted/enabled'),
    ('endpoint event permitted',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## 3. No pre-negotiation held stream',
                    'Culvert emits an `endpoint` event as the first SSE event on the probe GET.\n\n## 3. No pre-negotiation held stream', 1)),
     'emits a legacy `endpoint` event'),
    ('GET opens pre-session stream',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## 3. No pre-negotiation held stream',
                    'A legacy-probe GET opens an SSE stream and waits for the endpoint event before returning.\n\n## 3. No pre-negotiation held stream', 1)),
     'positively opens/holds a pre-negotiation GET stream'),
    ('400 row missing client follow-on behavior',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('| 400 is a spec-listed probe trigger; client MAY issue the follow-on GET, which MUST be terminal 405 | spec |', '|  | spec |', 1)),
     'does not state client follow-on behavior'),
    ('404 row missing zero-retention assertion',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('| yes | no | 404; follow-on GET 405, zero stream |', '| yes | yes | 404; follow-on GET 405, zero stream |', 1)),
     'permits stream allocation'),
    ('status chosen without source',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('| VERIFIED | SPEC transports.mdx@2025-11-25 L137-141 |', '| VERIFIED |  |', 1)),
     'empty source locator'),
    ('UNRESOLVED row treated as normative',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('UNRESOLVED sessionless ruling (D-1); with session/context Culvert has another way and honoring is conformant; do NOT silently admit 2025-03-26',
                    'Silently admit 2025-03-26 as the sessionless default (binding)', 1)),
     'presents a binding Culvert decision'),
    ('2025 and 2026 semantics merged',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('| 2025-era (2025-06-18 / 2025-11-25) | initial initialize | client offers a version the server supports',
                    '| 2025-era + 2026-era (merged) | initial initialize | client offers a version the server supports', 1)),
     'collapses the 2025 and 2026 eras'),
    ('2026 RC called stable',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## 1. Two protocol eras',
                    'The `2026-07-28` revision is the stable, final baseline for V1.\n\n## 1. Two protocol eras', 1)),
     'labelled stable/final without a negation'),
    ('C-6 restored',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('**C-6 is WITHDRAWN as a false positive.**', 'C-6 is a VALID conflict that still stands.', 1)),
     'C-6'),
    ('A-7 restored',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('**A-7 is REMOVED.**', 'A-7 is RETAINED as an open decision.', 1)),
     'A-7'),
    ('C-7 broadened back to every missing header',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('**C-7 is NARROWED**', 'C-7 applies to every missing `MCP-Protocol-Version` header, C-7 NARROWED-NOT', 1)),
     'C-7 is broadened back to every missing header'),
    ('D-1 marked closed',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('D-1 remains OPEN', 'D-1 is now CLOSED', 1)),
     'marks it closed'),
    ('D-1 closed in the OPEN-DECISIONS block (separate status line)',
     lambda t: _mut(t, 'open', lambda s: s.replace('**Still OPEN.**', '**STATUS: CLOSED.**', 1)),
     'not marked OPEN in its OPEN-DECISIONS'),
    ('free-form fallback config added',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## Cross-references',
                    'Operators can set `mcp_transport_fallback_list: ["legacy-2024-sse"]` to re-enable legacy fallback.\n\n## Cross-references', 1)),
     'free-form / legacy-enabling transport configuration field'),
    ('duplicate correct-then-wrong status claim',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## Cross-references',
                    'A GET without a valid session may instead return 200 with an open SSE stream (compatibility).\n\n## Cross-references', 1)),
     'conflicting non-405 terminal GET status'),
    ('zero-row / malformed evidence table',
     lambda t: _mut(t, 'evidence', lambda s: s.replace(DELIM14, DELIM13, 1)),
     'evidence matrix malformed'),
    ('first-match laundering (VERIFIED then a second status)',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('| VERIFIED | SPEC lifecycle.mdx@2025-11-25 L165-171 |', '| VERIFIED then UNRESOLVED | SPEC lifecycle.mdx@2025-11-25 L165-171 |', 1)),
     'evidence status is not exactly one'),
    ('fixture marked green before D-1',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## Cross-references',
                    'Fixture 8 (sessionless ruling) is marked green before D-1 closes.\n\n## Cross-references', 1)),
     'marked green before D-1'),
]

NEGATIVE_CONTROLS = [
    ('historical description of legacy 2024 behavior',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## 3. No pre-negotiation held stream',
                    'Historically, a 2024-11-05 server opened an SSE channel whose first message was an endpoint event; Culvert implements none of this.\n\n## 3. No pre-negotiation held stream', 1))),
    ('a 2026 comparison row clearly marked non-binding',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## Cross-references',
                    'For comparison only, the `2026-07-28` RC is non-binding and excluded from V1.\n\n## Cross-references', 1))),
    ('a sourced unresolved conflict',
     lambda t: _mut(t, 'evidence', lambda s: s.replace('## Cross-references',
                    'One sourced open item remains UNRESOLVED: the sessionless-header ruling (SPEC transports.mdx@2025-11-25 L274-277) awaits D-1.\n\n## Cross-references', 1))),
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
        ok, _h, rows = parse_matrix(texts['evidence'])
        ver = sum(1 for r in rows if 'VERIFIED' in r[C_STATUS])
        unr = sum(1 for r in rows if 'UNRESOLVED' in r[C_STATUS])
        con = sum(1 for r in rows if 'CONFLICTING' in r[C_STATUS])
        print(f'  evidence matrix rows: {len(rows)} ({ver} VERIFIED, {con} CONFLICTING, {unr} UNRESOLVED)  -> NONE')

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
        print('PASS: the transport-fallback evidence matrix parses non-vacuously; the legacy-2024 '
              'exclusion, terminal-status / zero-stream invariants, era separation, Gate-3 amendment '
              'record and D-1-open governance all hold; all seeds fire; all negative controls silent.')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
