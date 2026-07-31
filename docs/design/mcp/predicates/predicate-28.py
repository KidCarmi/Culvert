#!/usr/bin/env python3
"""Predicate 28 — the MCP operation registry must bind BOTH protocol directions
to an authorized, parity-checked admitted-method surface.

Why this exists.  Board blockers #925 (bidirectional requests / requestor-scoped
protocol state) and #928 (authorize every supported capability, not only
`tools/call`) share one root cause: the design modelled the client→server
envelope only, and admitted "whatever the negotiated version contains" without a
Culvert-reviewed subset or a downstream owner per method.  This predicate makes
the fix mechanical: it parses `MCP-OPERATION-REGISTRY.md` and fails CI when the
admitted surface, the owner parity, the reverse-channel rejection, the
requestor-scoped correlation/cancellation rules, or the cross-document
references drift.

Authorities:
  * `MCP-OPERATION-REGISTRY.md` §4 — the 16-column admitted-method table plus the
    normative peer-role / correlation / cancellation / configuration prose.
  * `DATA-FLOW-DIAGRAMS.md` and `PROTOCOL-COMPATIBILITY.md` — must reference the
    registry (so the flow and compatibility surfaces cannot silently diverge).

Scope, stated so nobody over-reads it.  This parses ONE named table and a small,
explicit set of normative sentences in ONE document, plus two cross-reference
checks.  It is NOT a general Markdown linter.

Run from the repository root:

    python3 docs/design/mcp/predicates/predicate-28.py

Exit 0 = every property holds.  Exit 1 = at least one violation, printed.
Stdlib only; no network, no third-party imports, no repository mutation.
"""

import pathlib
import re
import sys

REG_DOC = 'docs/design/mcp/MCP-OPERATION-REGISTRY.md'
DFD_DOC = 'docs/design/mcp/DATA-FLOW-DIAGRAMS.md'
PROTO_DOC = 'docs/design/mcp/PROTOCOL-COMPATIBILITY.md'
DOCS = {'registry': REG_DOC, 'dfd': DFD_DOC, 'proto': PROTO_DOC}

SECTION = '## 4. The operation registry'
FIRST_HEADER_CELL = 'Capability'
DELIM_CELL = re.compile(r':?-{3,}:?$')

COLUMNS = [
    'Capability', 'Leg / peer role', 'Requestor & direction', 'Method', 'V1 status',
    'Operation class', 'Resource/destination extraction', 'Authorization namespace',
    'Catalog / drift', 'Credential scope', 'Default-deny semantics', 'Audit / durability',
    'Legal policy actions', 'Handling owner', 'Capability advertisement', 'Impl gate',
]
KEY_COLS = ('Capability', 'Leg / peer role', 'Requestor & direction', 'Method')
CAPABILITIES = {'Gateway', 'Management'}

# The EXACT reviewed V1 admitted-method set. An admitted row whose method is not
# in this set is a violation even if it has a well-formed owner — otherwise a
# `resources/subscribe` row with a named decision point would pass while the
# `resources/*` rejection row launders the extra admission (MCP-PROTO-016).
ADMITTED_METHODS = {'initialize', 'notifications/initialized', 'ping',
                    'notifications/cancelled', 'tools/list', 'tools/call'}

# Method families that MUST appear only as rejected rows in V1.
REJECTED_FAMILIES = ['resources', 'prompts', 'completion', 'sampling', 'elicitation', 'roots', 'tasks']
# Specific methods that must remain rejected.
REJECTED_METHODS = ['resources/read', 'tasks/cancel']
# Business methods that must exist for BOTH capabilities (separate rows).
DUAL_CAP_METHODS = ['tools/list', 'tools/call']

# Normative phrases (occurrence-counted where duplication could launder a defect).
# Each: (label, compiled regex over the flattened registry text, min_count).
NORMS = [
    ('correlation key includes requestor/direction',
     re.compile(r'\(session, requestor-role/direction, request-id\)')),
    ('one direction never releases the other direction state',
     re.compile(r'MUST NEVER \*\*resolve, complete, cancel, delete, overwrite or release\*\* the other')),
    ('same id may be outstanding in both directions',
     re.compile(r'concurrently in both directions')),
    ('cancellation references same direction only',
     re.compile(r'reference only a request \*\*issued in the same direction\*\*')),
    ('initialize cannot be cancelled',
     re.compile(r'The `initialize` request MUST NOT be cancelled')),
    ('late cancellation is not a duplicate-completion fault',
     re.compile(r'MUST NOT be\s+classified as a duplicate-completion fault')),
    ('one kernel for both legs (no second decoder)',
     re.compile(r'no second, unspecified decoder for upstream bytes')),
    ('no arbitrary operator method list',
     re.compile(r'no `allow_unknown_methods` option')),
]


def split_cells(line):
    s = line.strip()
    cells, buf, in_code, esc = [], [], False, False
    for ch in s:
        if esc:
            buf.append(ch); esc = False
        elif ch == '\\':
            buf.append(ch); esc = True
        elif ch == '`':
            in_code = not in_code; buf.append(ch)
        elif ch == '|' and not in_code:
            cells.append(''.join(buf)); buf = []
        else:
            buf.append(ch)
    cells.append(''.join(buf))
    return [c.strip() for c in cells[1:-1]]


def parse_table(text):
    """Parse the §4 registry table. Returns (header, rows, violations)."""
    v = []
    L = text.split('\n')
    sec = next((i for i, l in enumerate(L) if l.strip() == SECTION), None)
    if sec is None:
        return None, [], [f'section {SECTION!r} not found — cannot locate the operation registry']
    hdr = next((i for i in range(sec, len(L))
                if L[i].startswith('| ' + FIRST_HEADER_CELL + ' |')), None)
    if hdr is None:
        return None, [], [f'no registry header row starting "| {FIRST_HEADER_CELL} |" after {SECTION!r}']
    header = split_cells(L[hdr])
    if hdr + 1 >= len(L):
        return header, [], ['header row is the last line — no delimiter row']
    delim = split_cells(L[hdr + 1])
    if not delim:
        return header, [], ['delimiter row has no cells']
    for n, cell in enumerate(delim, start=1):
        if not DELIM_CELL.fullmatch(cell):
            v.append(f'delimiter cell {n} is not a valid GFM delimiter: {cell!r} '
                     f'(needs at least three hyphens)')
    if v:
        return header, [], v
    if len(header) != len(delim):
        v.append(f'header/delimiter width mismatch: header={len(header)} delimiter={len(delim)} '
                 f'— GFM yields ZERO rows and every registry property passes vacuously')
        return header, [], v
    rows = []
    for i in range(hdr + 2, len(L)):
        if not L[i].startswith('|'):
            break
        cells = split_cells(L[i])
        if len(cells) != len(header):
            v.append(f'data-row width mismatch at line {i + 1}: {len(cells)} vs header {len(header)}')
            continue
        rows.append((i + 1, dict(zip(header, cells))))
    return header, rows, v


def owner_kind(owner):
    """Classify a Handling-owner cell: 'kt', 'dp', 'rejected', 'both', or 'none'."""
    has_kt = 'kernel-terminal' in owner
    has_dp = 'decision-point:' in owner
    is_rej = owner.strip() == 'rejected'
    if is_rej and not has_kt and not has_dp:
        return 'rejected'
    if has_kt and has_dp:
        return 'both'
    if has_kt:
        return 'kt'
    if has_dp:
        return 'dp'
    return 'none'


def check_registry(text):
    v = []
    header, rows, pv = parse_table(text)
    v += pv
    if not rows:
        if not pv:
            v.append('ZERO parsed registry rows — an UNCONDITIONAL failure (anti-vacuity)')
        return v
    for col in COLUMNS:
        if col not in (header or []):
            v.append(f'required registry column {col!r} missing from the header')
    if any('missing from the header' in x for x in v):
        return v

    seen = {}
    caps, methods_by_cap = set(), {}
    advertised_rejected = []
    families_rejected, methods_rejected = set(), set()
    for ln, r in rows:
        cap = r['Capability']
        method = r['Method'].strip('`')
        status = r['V1 status']
        owner = r['Handling owner']
        advert = r['Capability advertisement']

        key = tuple(r[c] for c in KEY_COLS)
        if key in seen:
            v.append(f'duplicate registry row (composite key not unique) at lines '
                     f'{seen[key]} and {ln}: {key}')
        seen[key] = ln

        caps.add(cap)
        methods_by_cap.setdefault(cap, set()).add(method)

        if status not in ('admitted', 'rejected'):
            v.append(f'row {method!r} (line {ln}) has unknown V1 status {status!r} '
                     f'— must be "admitted" or "rejected"')
            continue

        k = owner_kind(owner)
        if status == 'admitted':
            if method not in ADMITTED_METHODS:
                v.append(f'ADMITTED row {method!r} (line {ln}) is NOT in the reviewed V1 '
                         f'admitted-method set {sorted(ADMITTED_METHODS)} — only the reviewed '
                         f'tools-only surface may be admitted (MCP-PROTO-016); a rejected-family '
                         f'row does not launder an extra admission')
            if k == 'none':
                v.append(f'ADMITTED row {method!r} (line {ln}) has NO handling owner — every '
                         f'admitted method must name a decision point XOR be kernel-terminal')
            elif k == 'both':
                v.append(f'ADMITTED row {method!r} (line {ln}) has TWO owners (both a decision '
                         f'point and kernel-terminal) — it must be exactly one')
            elif k == 'rejected':
                v.append(f'ADMITTED row {method!r} (line {ln}) is owner "rejected" — an admitted '
                         f'method cannot be rejected')
        else:  # rejected
            if k != 'rejected':
                v.append(f'REJECTED row {method!r} (line {ln}) has a dispatch owner ({owner!r}) '
                         f'— a rejected method must have owner "rejected"; no dispatch path may '
                         f'exist for a non-admitted method (reverse parity)')
            if 'not advertised' not in advert:
                advertised_rejected.append((method, ln, advert))
            fam = method.split('/')[0].rstrip('*').strip()
            families_rejected.add(fam)
            methods_rejected.add(method)

    # capability advertisement never wider than the admitted registry
    for method, ln, advert in advertised_rejected:
        v.append(f'capability advertisement wider than the registry: rejected method {method!r} '
                 f'(line {ln}) is advertised as {advert!r} — a rejected class must be "not advertised"')

    # both capabilities, and the dual-capability business methods on both
    for cap in CAPABILITIES:
        if cap not in caps:
            v.append(f'registry has no {cap!r} rows — Management and Gateway must be separate rows')
    for m in DUAL_CAP_METHODS:
        for cap in CAPABILITIES:
            if m not in methods_by_cap.get(cap, set()):
                v.append(f'business method {m!r} is missing a {cap!r} row — Management and Gateway '
                         f'need separate rows even for the same wire method')

    # every rejected family present; the named methods rejected
    for fam in REJECTED_FAMILIES:
        if fam not in families_rejected:
            v.append(f'method family {fam!r} has no rejected row — it must be explicitly rejected in V1')
    for m in REJECTED_METHODS:
        if m not in methods_rejected:
            v.append(f'{m!r} is not explicitly rejected — it must remain a rejected row in V1')
    return v


def check_norms(text):
    v = []
    flat = re.sub(r'\s+', ' ', text)
    for label, rx in NORMS:
        n = len(rx.findall(flat))
        if n == 0:
            v.append(f'normative statement missing: {label} — the registry must state it')
    # first-match laundering guard: a session-only correlation key must not appear
    # anywhere, even after a correct composite-key statement.
    bad = re.findall(r'keyed by[^.]*\(session, request-id\)', flat)
    if bad:
        v.append('correlation key laundering: a session-ONLY "(session, request-id)" key is stated '
                 '— correlation must include the requestor/direction dimension (occurrence-counted)')
    return v


def check_cross_refs(dfd_text, proto_text):
    v = []
    if 'MCP-OPERATION-REGISTRY' not in dfd_text:
        v.append('DATA-FLOW-DIAGRAMS.md does not reference MCP-OPERATION-REGISTRY — the flow surface '
                 'must point at the authoritative registry')
    if 'MCP-OPERATION-REGISTRY' not in proto_text:
        v.append('PROTOCOL-COMPATIBILITY.md does not reference MCP-OPERATION-REGISTRY — the '
                 'compatibility surface must point at the authoritative registry')
    return v


def check(texts):
    v = []
    v += check_registry(texts['registry'])
    v += check_norms(texts['registry'])
    v += check_cross_refs(texts['dfd'], texts['proto'])
    return v


# ── seeds ────────────────────────────────────────────────────────────────────
def _mut(texts, key, fn):
    out = dict(texts); out[key] = fn(out[key]); return out


def s_session_only_key(t):
    return _mut(t, 'registry', lambda s: s.replace(
        'correlation state MUST be keyed by at least the composite\n`(session, requestor-role/direction, request-id)`',
        'correlation state MUST be keyed by\n`(session, request-id)`'))


def s_opposite_dir_deletes(t):
    return _mut(t, 'registry', lambda s: s.replace(
        'One direction MUST NEVER **resolve, complete, cancel, delete, overwrite or release** the other',
        'One direction MAY release the other'))


def s_same_id_disallowed(t):
    return _mut(t, 'registry', lambda s: s.replace('concurrently in both directions',
                                                   'in only one direction at a time'))


def s_initialize_cancellable(t):
    return _mut(t, 'registry', lambda s: s.replace(
        'The `initialize` request MUST NOT be cancelled.',
        'The `initialize` request may be cancelled.'))


def s_late_cancel_dup(t):
    return _mut(t, 'registry', lambda s: s.replace(
        'MUST NOT be\n  classified as a duplicate-completion fault',
        'is classified as a duplicate-completion fault'))


def s_upstream_other_decoder(t):
    return _mut(t, 'registry', lambda s: s.replace(
        'There is **no second, unspecified decoder for upstream bytes.**',
        'Upstream bytes are decoded by a separate decoder.'))


def s_sampling_admitted(t):
    return _mut(t, 'registry', lambda s: s.replace(
        '| Gateway | upstream-server-facing peer | server → Culvert (reverse req) | sampling/createMessage | rejected |',
        '| Gateway | upstream-server-facing peer | server → Culvert (reverse req) | sampling/createMessage | admitted |', 1))


def s_resources_read_admitted(t):
    # flip resources/read to admitted while owner stays "rejected" -> admitted w/ no owner
    return _mut(t, 'registry', lambda s: s.replace(
        '| Gateway | client-facing peer | client → Culvert (req) | resources/read | rejected |',
        '| Gateway | client-facing peer | client → Culvert (req) | resources/read | admitted |', 1))


def s_admit_outside_set(t):
    """A well-formed admitted row for a method OUTSIDE the reviewed set, with a
    named decision point — must fail even though its owner is valid."""
    row = ('| Gateway | client-facing peer | client → Culvert (req) | resources/subscribe | admitted | '
           'read | params → uri | tool-name (Gateway) | not catalogued | none | default-deny | '
           'event / ordinary | ALLOW / DENY | decision-point: rogue handler | tools capability advertised | PR-6 |')
    return _mut(t, 'registry', lambda s: s.replace(
        '| Gateway | client-facing peer | client → Culvert (req) | tools/call | admitted |',
        row + '\n| Gateway | client-facing peer | client → Culvert (req) | tools/call | admitted |', 1))


def s_tasks_cancel_admitted(t):
    return _mut(t, 'registry', lambda s: s.replace(
        '| Gateway | client-facing peer | client → Culvert (req) | tasks/cancel | rejected |',
        '| Gateway | client-facing peer | client → Culvert (req) | tasks/cancel | admitted |', 1))


def s_admitted_no_owner(t):
    return _mut(t, 'registry', lambda s: s.replace(
        ' | decision-point: policy engine (DFD-5) | tools capability advertised | PR-6 |',
        ' | TBD | tools capability advertised | PR-6 |', 1))


def s_admitted_two_owners(t):
    return _mut(t, 'registry', lambda s: s.replace(
        ' | decision-point: policy engine (DFD-5) | tools capability advertised | PR-6 |',
        ' | decision-point: policy engine (DFD-5); kernel-terminal | tools capability advertised | PR-6 |', 1))


def s_duplicate_row(t):
    def dup(s):
        L = s.split('\n')
        for i, l in enumerate(L):
            if l.startswith('| Gateway | client-facing peer | client → Culvert (req) | tools/call | admitted |'):
                return '\n'.join(L[:i + 1] + [l] + L[i + 1:])
        return s
    return _mut(t, 'registry', dup)


def s_dispatch_absent(t):
    # a rejected method given a dispatch owner = a dispatch path for a non-admitted method
    return _mut(t, 'registry', lambda s: s.replace(
        '| prompts/* (list, get) | rejected | read/discovery | n/a — rejected; prompts are not admitted in V1 | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected |',
        '| prompts/* (list, get) | rejected | read/discovery | n/a — rejected; prompts are not admitted in V1 | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | decision-point: prompts handler |', 1))


def s_arbitrary_method_list(t):
    return _mut(t, 'registry', lambda s: s.replace(
        'there is **no `allow_unknown_methods` option**',
        'operators may set an `allow_unknown_methods` list'))


def s_advert_wider(t):
    return _mut(t, 'registry', lambda s: s.replace(
        '| Gateway | upstream-server-facing peer | server → Culvert (reverse req) | sampling/createMessage | rejected | control (reverse-channel inference/exfil oracle) | n/a — server-originated request rejected; Culvert advertises no sampling client capability | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | not advertised | PR-1 |',
        '| Gateway | upstream-server-facing peer | server → Culvert (reverse req) | sampling/createMessage | rejected | control (reverse-channel inference/exfil oracle) | n/a — server-originated request rejected; Culvert advertises no sampling client capability | n/a (not admitted) | not catalogued | n/a (no credential path) | n/a (never reaches policy — rejected at admission) | admission-reject event / ordinary | none (rejected at ADMIT; no wire response where message-class forbids one) | rejected | advertised | PR-1 |', 1))


def s_zero_rows(t):
    return _mut(t, 'registry', lambda s: '\n'.join(
        l for l in s.split('\n') if not (l.startswith('| Gateway |') or l.startswith('| Management |'))))


def s_first_match_laundering(t):
    # a correct composite-key statement, then a session-only duplicate a first-match reader misses
    return _mut(t, 'registry', lambda s: s.replace(
        '(Amends `MCP-PROTO-003`.)',
        '(Amends `MCP-PROTO-003`.) For brevity the table is keyed by (session, request-id).'))


SEEDS = [
    ('session-only correlation key', s_session_only_key, 'requestor/direction'),
    ('opposite-direction cancellation deleting state', s_opposite_dir_deletes, 'never releases the other direction'),
    ('same id disallowed across both directions', s_same_id_disallowed, 'both directions'),
    ('initialize made cancellable', s_initialize_cancellable, 'initialize cannot be cancelled'),
    ('late cancel treated as duplicate completion', s_late_cancel_dup, 'duplicate-completion'),
    ('upstream bytes assigned to another decoder', s_upstream_other_decoder, 'no second'),
    ('server sampling admitted', s_sampling_admitted, "'sampling/createMessage'"),
    ('resources/read admitted with no decision point', s_resources_read_admitted, "'resources/read'"),
    ('admitted method outside the reviewed set (resources/subscribe + owner)', s_admit_outside_set, 'reviewed V1'),
    ('tasks/cancel admitted', s_tasks_cancel_admitted, "'tasks/cancel'"),
    ('admitted row with no owner', s_admitted_no_owner, 'NO handling owner'),
    ('admitted row with two owners', s_admitted_two_owners, 'TWO owners'),
    ('duplicate registry row', s_duplicate_row, 'duplicate registry row'),
    ('dispatch path for a non-admitted method', s_dispatch_absent, 'reverse parity'),
    ('arbitrary operator method list', s_arbitrary_method_list, 'arbitrary operator method list'),
    ('capability advertisement wider than the registry', s_advert_wider, 'wider than the registry'),
    ('malformed / zero-row registry table', s_zero_rows, 'ZERO parsed registry rows'),
    ('first-match laundering (session-only key added after the correct one)', s_first_match_laundering, 'laundering'),
]

NEGATIVE_CONTROLS = [
    ('an unrelated method name in ordinary prose',
     lambda t: _mut(t, 'registry', lambda s: s.replace(
         '## Cross-references',
         'For context, `resources/read` is a common MCP method discussed in the spec.\n\n## Cross-references', 1))),
    ('a fenced example mentioning a method',
     lambda t: _mut(t, 'registry', lambda s: s.replace(
         '## Cross-references',
         '```\nexample: tools/call is the primary path\n```\n\n## Cross-references', 1))),
    ('an unrelated edit to the DFD document body',
     lambda t: _mut(t, 'dfd', lambda s: s + '\n\n<!-- unrelated trailing note -->\n')),
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
        _, rows, _ = parse_table(texts['registry'])
        adm = sum(1 for _l, r in rows if r['V1 status'] == 'admitted')
        rej = sum(1 for _l, r in rows if r['V1 status'] == 'rejected')
        print(f'  registry rows: {len(rows)} ({adm} admitted, {rej} rejected)  -> NONE')

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
        print('PASS: the operation registry parses non-vacuously; owner parity, reverse-channel '
              'rejection, requestor-scoped correlation/cancellation and cross-references all hold; '
              'all seeds fire; all negative controls silent.')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
