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

Scope, stated so nobody over-reads it.  This parses ONE named table, located by
its exact heading and its exact first column header, against a documented
schema.  It is NOT a general Markdown validator and proves nothing about any
other table, document or file.  Prose tables elsewhere in the same document are
deliberately ignored — negative control N3 pins that.

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

# Registry-class summary tables whose membership must agree with the live rows.
# label -> the class every field it names must actually carry.
SUMMARY_TABLES = {'Credential-provider references': 'RC-2'}


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
    if not re.fullmatch(r'\|(\s*:?-+:?\s*\|)+', delim_raw):
        return header, [], [f'row after header is not a GFM delimiter row: {delim_raw[:60]!r}']

    delim = split_cells(lines[hdr + 1])
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
    if v and any('missing from the header' in x for x in v):
        return v

    seen = {}
    live = {}
    for ln, r in rows:
        fid = r['Field ID'].strip('`')
        kind = r['Value kind'].strip('`')
        cls = r['Registry class'].strip()

        if fid in seen:
            v.append(f'duplicate field name {fid!r} at lines {seen[fid]} and {ln}')
        seen[fid] = ln
        live[fid] = (kind, cls, ln)

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

    # ── summary <-> live parity, BOTH directions ────────────────────────────
    for label, want in SUMMARY_TABLES.items():
        named = summary_members(text, label)
        if named is None:
            v.append(f'registry-class summary row {label!r} not found')
            continue
        for fid in named:                                   # forward
            if fid not in live:
                v.append(f'summary {label!r} names {fid!r}, which is not a live '
                         f'matrix row')
            elif live[fid][1] != want:
                v.append(f'SUMMARY/LIVE DISAGREEMENT: summary {label!r} lists '
                         f'{fid!r} as {want}, but its live row is '
                         f'{live[fid][1]} (line {live[fid][2]})')
        for fid, (_, cls, ln) in live.items():              # reverse
            if cls == want and fid not in named:
                v.append(f'live row {fid!r} is {cls} (line {ln}) but is not '
                         f'named in the {label!r} summary')

    # ── census reproducibility: prose counts must match parsed rows ─────────
    for label, counter in (('value kind', 0), ('registry class', 1)):
        tally = {}
        for _, (k, c, _l) in live.items():
            key = (k, c)[counter]
            tally[key] = tally.get(key, 0) + 1
        for key, n in sorted(tally.items()):
            claim = census_claim(text, key)
            if claim is not None and claim != n:
                v.append(f'census disagreement for {label} {key!r}: document '
                         f'states {claim}, parsed rows give {n}')
    return v


def summary_members(text, label):
    """Backticked field names in the summary row whose first cell is `label`."""
    for l in text.split('\n'):
        if l.startswith('| ' + label + ' |'):
            cells = split_cells(l)
            if len(cells) >= 2:
                return set(re.findall(r'`(mcp_[a-z0-9_]+)`', cells[1]))
    return None


def census_claim(text, key):
    """The document's own stated count for `key`, if it publishes one.

    Matches the "Current census" line, e.g. `` `tunable` 56 ``.
    """
    m = re.search(r'`' + re.escape(key) + r'`\s+(\d+)', text)
    return int(m.group(1)) if m else None


# ── seeded controls ─────────────────────────────────────────────────────────
# Each mutation must be DETECTED.  A predicate whose seeds do not fire is
# decoration.

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
    """A live RC-2 row dropped from the summary (reverse-parity direction)."""
    return t.replace('`mcp_gateway_connector_mtls_profile_ref`, ', '', 1)


def seed_unknown_value_kind(t):
    return t.replace('| `tunable` | RC-7 |', '| `mystery-kind` | RC-7 |', 1)


def seed_rcx_row(t):
    return re.sub(r'(\| `mcp_gateway_listen_bind` \|.*)\| RC-6 \|', r'\1| RC-X |', t)


SEEDS = [
    ('17-col header with 16-col delimiter (the #947 defect)', seed_bad_delimiter),
    ('table parses to ZERO rows (anti-vacuity)', seed_zero_rows),
    ('provider-ref -> RC-6', seed_provider_ref_rc6),
    ('live RC-0 row listed in the RC-2 summary (the D-2 defect)', seed_rc0_in_rc2_summary),
    ('duplicate field name', seed_duplicate_field),
    ('missing summary member (reverse parity)', seed_missing_summary_member),
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

    print('\n=== seeded known-positives (each MUST be detected) ===')
    missed = []
    for name, fn in SEEDS:
        found = check(fn(text))
        ok = bool(set(found) - set(live_v))   # seed must introduce a NEW violation
        print(f'  [{"DETECTED" if ok else "MISSED":8}] {name}')
        if not ok:
            missed.append(name)

    print('\n=== negative controls (each MUST stay silent) ===')
    noisy = []
    for name, fn in NEGATIVE_CONTROLS:
        found = check(fn(text))
        quiet = not (set(found) - set(live_v))
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
