#!/usr/bin/env python3
"""Predicate 26 — the MCP config-surface matrix must PARSE, and must never pass
vacuously.

Why this exists.  Every `MCP-CFG-001` assertion is quantified over the rows of
one table: `docs/design/mcp/CONFIG-SURFACE-MATRIX.md` §"The matrix".  A check
quantified over a set it failed to build is not a check — it is a green tick.
PR #947 shipped that exact failure: the header carried 17 cells and the
delimiter row 16, so per GFM ("The header row must match the delimiter row in
the number of cells.  If not, a table will not be recognized.") a conformant
parser yields ZERO rows.  `count(RC-X) == 0` then holds trivially, the
value-kind invariant has nothing to quantify over, and every downstream
assertion passes while asserting nothing.

So the first duty of this predicate is to REFUSE to be vacuous: an empty or
unparseable table is an unconditional FAIL, never a silent pass.

The second duty is to refuse to be *selectively* vacuous.  Three later rounds
of review found the same shape of hole in the checks themselves — a summary row
that was never read, a census claim about something never observed, a member
list collapsed to a set so a duplicate vanished.  Each one passed green.  The
rule that follows from that: a check must quantify over the DECLARED
vocabulary, never over what the document happened to mention, and it must count
occurrences rather than take the first match.

Scope, stated so nobody over-reads it.  This parses ONE named table, located by
its exact heading and its exact first column header, against a documented
schema, plus the summary and census paragraphs of that same document.  It is
NOT a general Markdown validator and proves nothing about any other table,
document or file.  Prose tables elsewhere in the same document are deliberately
ignored — negative control N1 pins that.

Run from the repository root:

    python3 docs/design/mcp/predicates/predicate-26.py

Exit 0 = every property holds.  Exit 1 = at least one violation, printed.
Stdlib only; no network, no third-party imports, no repository mutation.
"""

import pathlib
import re
import sys

DOC = pathlib.Path('docs/design/mcp/CONFIG-SURFACE-MATRIX.md')

# ── documented schema ────────────────────────────────────────────────────────
SECTION = '## The matrix'
FIRST_HEADER_CELL = 'Field ID'
EXPECTED_ROWS = 89                 # live rows; update deliberately, with review

REGISTRY_CLASSES = {'RC-0', 'RC-1', 'RC-2', 'RC-3',
                    'RC-4', 'RC-5', 'RC-6', 'RC-7', 'RC-X'}
SENSITIVE_CLASSES = {'RC-1', 'RC-2'}
FORBIDDEN_CLASS = 'RC-X'           # inline secret material: must stay empty

VALUE_KINDS = {'server-endpoint', 'pinned-identity', 'provider-ref',
               'policy-ref', 'tenant-scope', 'snapshot-meta',
               'listener', 'path', 'tunable', 'none'}
SENSITIVE_KINDS = {'server-endpoint', 'pinned-identity', 'provider-ref'}

# A GFM delimiter cell: at least THREE hyphens, optional alignment colons.
# `-` and `--` are not delimiter cells; accepting them would let a table that
# GitHub refuses to render pass this predicate.
DELIM_CELL = re.compile(r':?-{3,}:?$')

# ── registry-class summary rows ──────────────────────────────────────────────
# Each row declares how its membership is bound.  Two distinct bindings exist,
# and conflating them was defect 1 of the third verification round:
#
#   exhaustive={C}  — the row enumerates EVERY live row of class C, so reverse
#                     parity is checked against the class.
#   members=(...)   — the row is a deliberately BOUNDED subset of a large class;
#                     reverse parity against the class would be wrong (it would
#                     demand all 38 RC-7 rows), so membership is pinned to this
#                     exact name list instead.  Dropping a name is a failure;
#                     other rows of the same class are not demanded here.
#
# A bounded row with `exhaustive=set()` is NOT unchecked — `members` is the
# stronger constraint of the two, because it fixes the set exactly.
SUMMARY_TABLES = {
    'Server endpoint + pinned TLS identity': {
        'allowed': {'RC-1'}, 'exhaustive': {'RC-1'}, 'members': None},
    'Credential-provider references': {
        'allowed': {'RC-2'}, 'exhaustive': {'RC-2'}, 'members': None},
    'Policy / catalog references': {
        'allowed': {'RC-3'}, 'exhaustive': {'RC-3'}, 'members': None},
    'Per-tenant overrides': {
        'allowed': {'RC-4'}, 'exhaustive': {'RC-4'}, 'members': None},
    'Snapshot integrity metadata': {
        'allowed': {'RC-5'}, 'exhaustive': {'RC-5'}, 'members': None},
    'Snapshot publication settings': {
        'allowed': {'RC-7'}, 'exhaustive': set(),
        'members': ('mcp_gateway_snapshot_sync_enabled',
                    'mcp_gateway_snapshot_min_dp_version')},
}

# ── published censuses ───────────────────────────────────────────────────────
# Each must be COMPLETE (every token in the vocabulary, including zero-valued
# ones) and UNIQUE (each token claimed exactly once).  Completeness stops a
# stale claim being hidden by deletion; uniqueness stops two copies disagreeing
# while a first-match reader sees only the correct one.
CENSUS_KIND = '**Current census**'
CENSUS_CLASS = '**Registry-class census**'


def split_cells(line):
    """Split a GFM row on UNESCAPED pipes.  `\\|` inside a cell is literal text."""
    return [c.strip() for c in re.split(r'(?<!\\)\|', line.strip())[1:-1]]


def parse_matrix(text):
    """Parse the named table.  Returns (header, rows, violations).

    Anything that stops the table being a table is a violation, not an
    exception and not an empty result.
    """
    v = []
    lines = text.split('\n')

    sec = next((i for i, l in enumerate(lines) if l.strip() == SECTION), None)
    if sec is None:
        return None, [], [f'section {SECTION!r} not found — cannot locate the matrix']

    hdr = next((i for i in range(sec, len(lines))
                if lines[i].startswith('| ' + FIRST_HEADER_CELL + ' |')), None)
    if hdr is None:
        return None, [], [f'no header row starting "| {FIRST_HEADER_CELL} |" after {SECTION!r}']

    header = split_cells(lines[hdr])
    if hdr + 1 >= len(lines):
        return header, [], ['header row is the last line — no delimiter row']

    delim_raw = lines[hdr + 1].strip()
    if not (delim_raw.startswith('|') and delim_raw.endswith('|')):
        return header, [], [f'row after header is not a pipe-delimited row: {delim_raw[:60]!r}']

    delim = split_cells(lines[hdr + 1])
    if not delim:
        return header, [], [f'delimiter row has no cells: {delim_raw[:60]!r}']

    # EVERY cell is validated independently — a single malformed cell voids the
    # table, so checking only the row shape would miss it.
    for n, cell in enumerate(delim, start=1):
        if not DELIM_CELL.fullmatch(cell):
            v.append(f'delimiter cell {n} is not a valid GFM delimiter: '
                     f'{cell!r} — a delimiter cell requires at least three '
                     f'hyphens (`---`), with optional alignment colons; GFM '
                     f'will not recognise this as a table')
    if v:
        return header, [], v

    if len(header) != len(delim):
        # THE #947 defect.  GFM does not recognise the table at all.
        v.append(f'header/delimiter width mismatch: header={len(header)} '
                 f'delimiter={len(delim)} — GFM will NOT recognise this as a '
                 f'table, so a conformant parser yields ZERO rows and every '
                 f'MCP-CFG-001 assertion passes vacuously')
        return header, [], v

    rows = []
    for i in range(hdr + 2, len(lines)):
        l = lines[i]
        if not l.startswith('|'):
            break                          # table ends at the first non-row line
        cells = split_cells(l)
        if len(cells) != len(header):
            v.append(f'data-row width mismatch at line {i + 1}: '
                     f'{len(cells)} cells vs header {len(header)} — '
                     f'{cells[0][:48] if cells else l[:48]!r}')
            continue
        rows.append((i + 1, dict(zip(header, cells))))
    return header, rows, v


def check(text):
    v = []
    header, rows, pv = parse_matrix(text)
    v += pv

    # ── ANTI-VACUITY.  This must come before every quantified property. ──────
    if not rows:
        v.append('ZERO parsed rows — this is an UNCONDITIONAL FAILURE. Every '
                 'MCP-CFG-001 property is quantified over these rows; an empty '
                 'set satisfies all of them while asserting nothing.')
        return v                            # refuse to "pass" the rest

    if len(rows) != EXPECTED_ROWS:
        v.append(f'unexpected live-row count: parsed {len(rows)}, expected '
                 f'{EXPECTED_ROWS} — if this change is intended, update '
                 f'EXPECTED_ROWS deliberately')

    for col in ('Field ID', 'Value kind', 'Registry class'):
        if col not in (header or []):
            v.append(f'required column {col!r} missing from the header')
    if any('missing from the header' in x for x in v):
        return v

    v += check_rows(rows)
    live = build_live(rows)
    v += check_summaries(text, live)
    v += check_censuses(text, live, len(rows))
    return v


def build_live(rows):
    """field id -> (value kind, registry class, line)."""
    live = {}
    for ln, r in rows:
        live[r['Field ID'].strip('`')] = (r['Value kind'].strip('`'),
                                          r['Registry class'].strip(), ln)
    return live


def check_rows(rows):
    v = []
    seen = {}
    for ln, r in rows:
        fid = r['Field ID'].strip('`')
        kind = r['Value kind'].strip('`')
        cls = r['Registry class'].strip()

        if fid in seen:
            v.append(f'duplicate field name {fid!r} at lines {seen[fid]} and {ln}')
        seen[fid] = ln

        if cls not in REGISTRY_CLASSES:
            v.append(f'unknown registry class {cls!r} for {fid!r} (line {ln})')
        if kind not in VALUE_KINDS:
            v.append(f'unknown value kind {kind!r} for {fid!r} (line {ln})')

        # MCP-CFG-001(6): a sensitive value MUST land in a sensitive class.
        if kind in SENSITIVE_KINDS and cls not in SENSITIVE_CLASSES:
            v.append(f'SENSITIVITY VIOLATION: {fid!r} declares value kind '
                     f'{kind!r} but is classified {cls} (line {ln}) — a '
                     f'sensitive value in a non-sensitive class carries '
                     f'Sensitive: No and is never redacted for an unenrolled peer')

        if cls == FORBIDDEN_CLASS:
            v.append(f'{FORBIDDEN_CLASS} must remain empty, but {fid!r} is '
                     f'classified {FORBIDDEN_CLASS} (line {ln}) — inline secret '
                     f'material is rejected at validation, never stored')

        # Documented corollaries.
        if (cls == 'RC-0') != (kind == 'none'):
            v.append(f'RC-0 <-> value-kind "none" biconditional broken for '
                     f'{fid!r}: kind={kind!r} class={cls} (line {ln})')
        if (kind == 'snapshot-meta') != (cls == 'RC-5'):
            v.append(f'snapshot-meta <-> RC-5 biconditional broken for {fid!r}: '
                     f'kind={kind!r} class={cls} (line {ln})')
    return v


def check_summaries(text, live):
    """Summary <-> live parity, both directions, for EVERY declared summary row."""
    v = []
    for label, spec in SUMMARY_TABLES.items():
        listed, occurrences = summary_members(text, label)

        # A label that appears twice makes "the summary" ambiguous; a
        # first-match reader would validate one copy and ignore the other.
        if occurrences == 0:
            v.append(f'registry-class summary row {label!r} not found — every '
                     f'declared summary must be present exactly once')
            continue
        if occurrences > 1:
            v.append(f'registry-class summary row {label!r} occurs {occurrences} '
                     f'times — it must occur exactly once, or the two copies can '
                     f'disagree while a first-match reader sees only one')
            continue

        # Duplicates vanish on set conversion, so count before converting.
        for fid in sorted(set(listed)):
            if listed.count(fid) > 1:
                v.append(f'summary {label!r} lists {fid!r} {listed.count(fid)} '
                         f'times — each member must appear exactly once')
        named = set(listed)

        for fid in sorted(named):                                # forward
            if fid not in live:
                v.append(f'summary {label!r} names {fid!r}, which is not a live '
                         f'matrix row')
            elif live[fid][1] not in spec['allowed']:
                v.append(f'SUMMARY/LIVE DISAGREEMENT: summary {label!r} lists '
                         f'{fid!r} among {sorted(spec["allowed"])}, but its live '
                         f'row is {live[fid][1]} (line {live[fid][2]})')

        for fid, (_k, cls, ln) in sorted(live.items()):          # reverse, by class
            if cls in spec['exhaustive'] and fid not in named:
                v.append(f'live row {fid!r} is {cls} (line {ln}) but is not '
                         f'named in the {label!r} summary, which is exhaustive '
                         f'for {cls}')

        if spec['members'] is not None:                          # reverse, bounded
            for fid in spec['members']:
                if fid not in named:
                    v.append(f'summary {label!r} is a bounded subset pinned to '
                             f'{list(spec["members"])}, but {fid!r} is missing — '
                             f'this row is not exhaustive for its class, so only '
                             f'this explicit list protects its members')
            for fid in sorted(named - set(spec['members'])):
                v.append(f'summary {label!r} names {fid!r}, which is not in its '
                         f'pinned membership {list(spec["members"])}')
    return v


def check_censuses(text, live, nrows):
    """Both published censuses must be complete, unique and correct."""
    v = []
    kind_tally = {k: 0 for k in VALUE_KINDS}         # every token, including zeros
    class_tally = {c: 0 for c in REGISTRY_CLASSES}
    for _fid, (k, c, _l) in live.items():
        if k in kind_tally:
            kind_tally[k] += 1
        if c in class_tally:
            class_tally[c] += 1

    for what, anchor, vocab, tally in (
            ('value kind', CENSUS_KIND, VALUE_KINDS, kind_tally),
            ('registry class', CENSUS_CLASS, REGISTRY_CLASSES, class_tally)):
        census = census_paragraph(text, anchor)
        if census is None:
            v.append(f'published {what} census ({anchor}) not found — the '
                     f'document must publish a census that can be checked '
                     f'against the parsed rows')
            continue

        for key in sorted(vocab):
            claims = census_claims(census, key)
            if not claims:
                v.append(f'{what} census OMITS {key!r}: every vocabulary token '
                         f'must publish a count (including zero), or a stale '
                         f'claim can be hidden by deleting it')
            elif len(claims) > 1:
                v.append(f'{what} census claims {key!r} {len(claims)} times '
                         f'({claims}) — each token must be claimed exactly once, '
                         f'or two copies can disagree undetected')
            elif claims[0] != tally[key]:
                v.append(f'{what} census disagreement for {key!r}: document '
                         f'states {claims[0]}, parsed rows give {tally[key]}')

        # A token the vocabulary does not contain cannot be reconciled at all.
        pattern = r'`([A-Za-z][A-Za-z0-9-]*)`\s+\d+'
        for tok in set(re.findall(pattern, census)):
            if tok not in vocab:
                v.append(f'{what} census claims unknown token {tok!r} — it is '
                         f'not in the declared vocabulary, so no parsed count '
                         f'can ever confirm or refute it')

    census = census_paragraph(text, CENSUS_KIND)
    if census is not None:
        totals = re.findall(r'\*\*(\d+) rows,\s*(\d+) sensitive-kind rows', census)
        if not totals:
            v.append('census does not publish "<N> rows, <M> sensitive-kind rows" '
                     'totals — both must be checkable against the parsed rows')
        elif len(totals) > 1:
            v.append(f'census publishes the row totals {len(totals)} times — '
                     f'they must be stated exactly once')
        else:
            stated_rows, stated_sens = int(totals[0][0]), int(totals[0][1])
            if stated_rows != nrows:
                v.append(f'census row total disagreement: document states '
                         f'{stated_rows}, parsed rows give {nrows}')
            sens = sum(1 for _f, (k, _c, _l) in live.items() if k in SENSITIVE_KINDS)
            if stated_sens != sens:
                v.append(f'census sensitive-kind total disagreement: document '
                         f'states {stated_sens}, parsed rows give {sens}')
    return v


def summary_members(text, label):
    """(ordered member names, number of rows carrying this label).

    Ordered, because converting to a set first would silently absorb a
    duplicate.  Counted, because stopping at the first match would hide a
    second row using the same label.
    """
    listed, occurrences = [], 0
    for l in text.split('\n'):
        if l.startswith('| ' + label + ' |'):
            occurrences += 1
            cells = split_cells(l)
            if occurrences == 1 and len(cells) >= 2:
                listed = re.findall(r'`(mcp_[a-z0-9_]+)`', cells[1])
    return listed, occurrences


def census_paragraph(text, anchor):
    """The published census PARAGRAPH, joined.

    The census wraps across physical lines; reading only the first one would let
    a claim hide on a continuation line.
    """
    L = text.split('\n')
    for i, l in enumerate(L):
        if l.startswith(anchor):
            para = []
            for j in range(i, len(L)):
                if not L[j].strip():
                    break
                para.append(L[j])
            return ' '.join(para)
    return None


def census_claims(census, key):
    """EVERY stated count for `key` — a list, so duplicates are visible."""
    return [int(m) for m in re.findall(r'`' + re.escape(key) + r'`\s+(\d+)', census)]


# ── seeded controls ─────────────────────────────────────────────────────────
# Each mutation must be DETECTED.  A predicate whose seeds do not fire is
# decoration.

def _delim_cell(t, replacement):
    """Replace the FIRST delimiter cell of the matrix with `replacement`."""
    L = t.split('\n')
    i = next(j for j, l in enumerate(L) if l.startswith('| Field ID |'))
    L[i + 1] = '|' + replacement + '|' + L[i + 1].strip().lstrip('|').split('|', 1)[1]
    return '\n'.join(L)


def seed_delim_one_hyphen(t):
    return _delim_cell(t, '-')


def seed_delim_two_hyphens(t):
    return _delim_cell(t, '--')


def seed_delim_bad_alignment(t):
    return _delim_cell(t, ':-:-:')


def seed_bad_delimiter(t):
    """The #947 defect: 17-cell header, 16-cell delimiter."""
    L = t.split('\n')
    i = next(j for j, l in enumerate(L) if l.startswith('| Field ID |'))
    L[i + 1] = L[i + 1].rstrip()[:-8] + '------|'   # 17 cells -> 16
    return '\n'.join(L)


def seed_zero_rows(t):
    """Table parses to nothing: every data row removed."""
    L = t.split('\n')
    i = next(j for j, l in enumerate(L) if l.startswith('| Field ID |'))
    return '\n'.join(L[:i + 2] + [l for l in L[i + 2:] if not l.startswith('| `mcp_')])


def seed_provider_ref_rc6(t):
    """A sensitive value kind moved into a non-sensitive class."""
    return re.sub(r'(\| `mcp_gateway_credential_profiles` \|.*)\| RC-2 \|',
                  r'\1| RC-6 |', t)


def seed_rc0_in_rc2_summary(t):
    """The D-2 defect: a checklist-only RC-0 row named in the RC-2 summary."""
    return t.replace('| Credential-provider references | `mcp_gateway_credential_profiles`',
                     '| Credential-provider references | `mcp_mgmt_credential_profiles`, '
                     '`mcp_gateway_credential_profiles`')


def seed_duplicate_field(t):
    """Same field ID twice."""
    L = t.split('\n')
    for i, l in enumerate(L):
        if l.startswith('| `mcp_gateway_server_registry` |'):
            return '\n'.join(L[:i + 1] + [l] + L[i + 1:])
    return t


def seed_missing_summary_member(t):
    """A live RC-2 row dropped from the summary (class-exhaustive direction)."""
    return t.replace('`mcp_gateway_connector_mtls_profile_ref`, ', '', 1)


def seed_missing_bounded_member(t):
    """An RC-7 publication setting dropped from its BOUNDED summary.

    This is the case the mixed RC-5/RC-7 summary row could not catch: RC-7 has
    38 live rows, so class-level reverse parity is inapplicable and only the
    pinned membership protects these two names.
    """
    return t.replace('`mcp_gateway_snapshot_sync_enabled`, '
                     '`mcp_gateway_snapshot_min_dp_version`',
                     '`mcp_gateway_snapshot_sync_enabled`')


def seed_duplicate_summary_member(t):
    """The same field named twice inside one summary row."""
    return t.replace('| Per-tenant overrides | `mcp_gateway_per_tenant_overrides`,',
                     '| Per-tenant overrides | `mcp_gateway_per_tenant_overrides`, '
                     '`mcp_gateway_per_tenant_overrides`,')


def seed_duplicate_summary_row(t):
    """Two summary rows carrying the same category label."""
    L = t.split('\n')
    for i, l in enumerate(L):
        if l.startswith('| Per-tenant overrides |'):
            return '\n'.join(L[:i + 1] + [l] + L[i + 1:])
    return t


def seed_unknown_value_kind(t):
    return t.replace('| `tunable` | RC-7 |', '| `mystery-kind` | RC-7 |', 1)


def seed_rcx_row(t):
    return re.sub(r'(\| `mcp_gateway_listen_bind` \|.*)\| RC-6 \|', r'\1| RC-X |', t)


def seed_rc1_summary_corrupt(t):
    """A different registry-class summary (RC-1) disagreeing with the live rows."""
    return t.replace('| Server endpoint + pinned TLS identity | `mcp_gateway_server_registry`',
                     '| Server endpoint + pinned TLS identity | `mcp_mgmt_enabled`')


def seed_census_claim_deleted(t):
    """A published value-kind census count silently removed."""
    return t.replace('`tunable` 56 · ', '')


def seed_zero_kind_census_wrong(t):
    """A zero-row value kind's published count falsified."""
    return t.replace('`pinned-identity` 0', '`pinned-identity` 99')


def seed_census_total_wrong(t):
    """The published row total falsified."""
    return t.replace('**89 rows, 5 sensitive-kind rows', '**88 rows, 5 sensitive-kind rows')


def seed_class_census_missing_rc3(t):
    """A registry-class claim silently removed."""
    return t.replace('`RC-3` 5 ·\n', '')


def seed_class_census_rc7_wrong(t):
    """A registry-class count falsified."""
    return t.replace('`RC-7` 38', '`RC-7` 37')


def seed_class_census_duplicate_rc2(t):
    """The same class claimed twice — first-match parsing would miss this."""
    return t.replace('`RC-2` 4 ·', '`RC-2` 4 · `RC-2` 9 ·')


def seed_class_census_rcx_nonzero(t):
    """The forbidden class published as non-empty."""
    return t.replace('`RC-X` 0.', '`RC-X` 1.')


SEEDS = [
    # defect 4 — delimiter-cell validity
    ('delimiter cell with ONE hyphen', seed_delim_one_hyphen),
    ('delimiter cell with TWO hyphens', seed_delim_two_hyphens),
    ('delimiter cell with malformed alignment syntax', seed_delim_bad_alignment),
    ('17-col header with 16-col delimiter (the #947 defect)', seed_bad_delimiter),
    # anti-vacuity
    ('table parses to ZERO rows (anti-vacuity)', seed_zero_rows),
    # defect 1 — bounded summary membership
    ('RC-7 publication setting dropped from its bounded summary', seed_missing_bounded_member),
    # defect 2 — duplicate members and duplicate summary rows
    ('duplicate member inside one summary row', seed_duplicate_summary_member),
    ('duplicate summary row with the same label', seed_duplicate_summary_row),
    # defect 3 — registry-class census
    ('registry-class census OMITS RC-3', seed_class_census_missing_rc3),
    ('registry-class census states the wrong RC-7 count', seed_class_census_rc7_wrong),
    ('registry-class census claims RC-2 twice', seed_class_census_duplicate_rc2),
    ('registry-class census states RC-X as 1', seed_class_census_rcx_nonzero),
    # value-kind census
    ('a published census count deleted', seed_census_claim_deleted),
    ('zero-row value kind census falsified (pinned-identity 0 -> 99)', seed_zero_kind_census_wrong),
    ('published row total falsified', seed_census_total_wrong),
    # summary parity
    ('RC-1 summary disagrees with live rows (non-RC-2 summary)', seed_rc1_summary_corrupt),
    ('live RC-0 row listed in the RC-2 summary (the D-2 defect)', seed_rc0_in_rc2_summary),
    ('missing summary member (class-exhaustive reverse parity)', seed_missing_summary_member),
    # row-level invariants
    ('provider-ref -> RC-6', seed_provider_ref_rc6),
    ('duplicate field name', seed_duplicate_field),
    ('unknown value-kind token', seed_unknown_value_kind),
    ('a live row classified RC-X', seed_rcx_row),
]

# Negative controls: mutations that must NOT be reported, proving the predicate
# is bound to THIS table and does not police unrelated prose.
NEGATIVE_CONTROLS = [
    ('an unrelated prose table gains a row',
     lambda t: t.replace('| **RC-X** | **Inline secret material** |',
                         '| **RC-W** | Placeholder prose row |\n| **RC-X** | **Inline secret material** |')),
    ('a fenced example mentioning mcp_ field names',
     lambda t: t.replace('## The matrix',
                         '```\n| `mcp_fake_row` | x | `provider-ref` | RC-6 |\n```\n\n## The matrix', 1)),
    ('ordinary prose edit outside any table',
     lambda t: t.replace('## The matrix', 'Extra explanatory sentence.\n\n## The matrix', 1)),
]


def norm(vs):
    """Violation set with line numbers erased.

    Seeds and controls shift line numbers; comparing raw strings would report a
    pure re-numbering as a new finding.
    """
    return {re.sub(r'\(line \d+\)', '(line N)', x) for x in vs}


def main():
    if not DOC.exists():
        print(f'FAIL: {DOC} not found (run from the repository root)')
        return 1
    text = DOC.read_text(encoding='utf-8')

    live_v = check(text)

    print('=== live document ===')
    if live_v:
        for x in live_v:
            print(f'  VIOLATION: {x}')
    else:
        _, rows, _ = parse_matrix(text)
        print(f'  parsed rows: {len(rows)}  -> NONE')

    print(f'\n=== seeded known-positives ({len(SEEDS)}, each MUST be detected) ===')
    missed = []
    for name, fn in SEEDS:
        found = check(fn(text))
        ok = bool(norm(found) - norm(live_v))   # seed must introduce a NEW violation
        print(f'  [{"DETECTED" if ok else "MISSED":8}] {name}')
        if not ok:
            missed.append(name)

    print(f'\n=== negative controls ({len(NEGATIVE_CONTROLS)}, each MUST stay silent) ===')
    noisy = []
    for name, fn in NEGATIVE_CONTROLS:
        found = check(fn(text))
        quiet = not (norm(found) - norm(live_v))
        print(f'  [{"QUIET" if quiet else "FIRED":8}] {name}')
        if not quiet:
            noisy.append(name)

    bad = bool(live_v) or missed or noisy
    print()
    if live_v:
        print(f'FAIL: {len(live_v)} violation(s) on the live document')
    if missed:
        print(f'FAIL: {len(missed)} seed(s) not detected: {missed}')
    if noisy:
        print(f'FAIL: {len(noisy)} negative control(s) fired: {noisy}')
    if not bad:
        print('PASS: matrix parses, is non-empty, and every invariant holds; '
              'all seeds fire; all negative controls silent.')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
