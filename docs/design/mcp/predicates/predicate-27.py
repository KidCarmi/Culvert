#!/usr/bin/env python3
"""Predicate 27 — every published MCP requirement/threat census must be
mechanically derived from its authoritative live registry, and must FAIL when it
is missing, duplicated, incomplete, stale or internally inconsistent.

Why this exists.  During RPR-2 the same shape of drift appeared repeatedly: a
document published an OLD total (a "91 requirements" that predated a later-added
ID) while every existing CI check stayed green, because nothing in CI recounted
the live registry and compared it against the published figure.  Incrementing a
carried-forward number instead of recounting is exactly how that survives.  This
predicate closes the recount-vs-increment class for the two registries that own
these numbers.

Two authorities, and ONLY these two:

  * Requirement registry — ``SECURITY-REQUIREMENTS.md``: the requirement rows of
    the per-family GFM tables (header ``| ID | Statement | ...`` or
    ``| ID | Normative statement | ...``).  The live facts are the total ID
    count, the per-family counts, per-ID uniqueness, and the complete set of
    live families.
  * Threat registry — ``THREAT-MODEL.md`` §11 "Risk register (canonical threat
    IDs)": the canonical ``MCP-T-###`` rows in the first column of the §11
    sub-tables.  The live facts are the total ID count and per-ID uniqueness.
    Incidental ``MCP-T-###`` references elsewhere in the file (STRIDE tables,
    control columns, residual-risk prose) are NOT the registry and are not
    counted.

A published prose total is never trusted as the authority — it is the thing
under test.  Every governed census is compared against the value DERIVED from
the live registry above.

Scope, stated so nobody over-reads it.  This parses two named registries and a
small, explicit set of census statements that summarise them.  It is NOT a
general Markdown linter and asserts nothing about any other number, table or
file.  A number in ordinary prose, and a statement that explicitly describes an
EARLIER state ("the previously published 91 was stale"), are deliberately not
governed — negative controls N1/N2/N3 pin that.

Run from the repository root:

    python3 docs/design/mcp/predicates/predicate-27.py

Exit 0 = every property holds.  Exit 1 = at least one violation, printed.
Stdlib only; no network, no third-party imports, no repository mutation.
"""

import pathlib
import re
import sys

REQ_DOC = 'docs/design/mcp/SECURITY-REQUIREMENTS.md'
THREAT_DOC = 'docs/design/mcp/THREAT-MODEL.md'
TRACE_DOC = 'docs/design/mcp/TEST-TRACEABILITY-MATRIX.md'

DOCS = {'requirements': REQ_DOC, 'threats': THREAT_DOC, 'traceability': TRACE_DOC}

# A GFM delimiter cell: at least THREE hyphens, optional alignment colons.  `-`
# and `--` are not delimiter cells; GitHub refuses to render such a table, so a
# conformant parser yields ZERO rows — accepting them would be the #947 hole.
DELIM_CELL = re.compile(r':?-{3,}:?$')

# A live requirement ID and the family it belongs to.  The family is the segment
# between `MCP-` and the trailing number, derived from the ROW — never from a
# heading (the `## MCP-CPDP / MCP-HA` heading names two families in one line, so
# heading parsing would miscount; rows are unambiguous).
REQ_ID = re.compile(r'^MCP-([A-Z][A-Z0-9]*)-\d+$')
THREAT_ID = re.compile(r'^MCP-T-\d+$')

# Requirement tables are recognised by their first two header cells; the second
# cell is `Statement` in most families and `Normative statement` in MCP-PROTO /
# MCP-AUTH.  Threat tables (second cell `Threat`) are thereby excluded.
REQ_SECOND_CELLS = {'Statement', 'Normative statement'}

THREAT_SECTION = '## 11.'          # canonical registry starts here
THREAT_SECTION_END = '## 12.'      # ... and ends at the residual-risk section


# ── GFM parsing ──────────────────────────────────────────────────────────────

def split_cells(line):
    """Split a GFM row into cells the way GitHub renders it.

    A pipe is a column separator ONLY when it is neither backslash-escaped nor
    inside an inline-code span — GitHub does not split on `|` inside backticks
    (e.g. a cell reading `` `RC-1|RC-2` `` is one cell, not two).  A splitter
    that ignored code spans would over-count that cell's row and drop it as a
    width mismatch, silently losing a live registry row.
    """
    s = line.strip()
    cells, buf = [], []
    in_code = esc = False
    for ch in s:
        if esc:
            buf.append(ch)
            esc = False
        elif ch == '\\':
            buf.append(ch)
            esc = True
        elif ch == '`':
            in_code = not in_code
            buf.append(ch)
        elif ch == '|' and not in_code:
            cells.append(''.join(buf))
            buf = []
        else:
            buf.append(ch)
    cells.append(''.join(buf))
    return [c.strip() for c in cells[1:-1]]        # drop the outer empty cells


def parse_registry(lines, lo, hi, first_cell, second_pred, what):
    """Collect first-column values of every GFM table in lines[lo:hi] whose
    header opens with `first_cell` and whose second header cell satisfies
    `second_pred`.  Returns (first_col_values, violations).

    Anything that stops a matched table being a table (bad delimiter cell,
    header/delimiter or data-row width mismatch) is a violation, not an
    exception and not a silent empty result.
    """
    v = []
    values = []
    i = lo
    tables = 0
    while i < hi:
        cells = split_cells(lines[i]) if lines[i].lstrip().startswith('|') else []
        if not (len(cells) >= 2 and cells[0] == first_cell and second_pred(cells[1])):
            i += 1
            continue
        tables += 1
        header = cells
        if i + 1 >= hi:
            v.append(f'{what}: header at line {i + 1} is the last line — no delimiter row')
            break
        delim = split_cells(lines[i + 1])
        if not delim:
            v.append(f'{what}: table at line {i + 1} has no delimiter row')
            i += 1
            continue
        bad_delim = False
        for n, cell in enumerate(delim, start=1):
            if not DELIM_CELL.fullmatch(cell):
                v.append(f'{what}: delimiter cell {n} at line {i + 2} is not a valid '
                         f'GFM delimiter: {cell!r} — needs at least three hyphens '
                         f'(`---`); GFM will not recognise this as a table')
                bad_delim = True
        if len(header) != len(delim):
            v.append(f'{what}: header/delimiter width mismatch at line {i + 2}: '
                     f'header={len(header)} delimiter={len(delim)} — GFM yields '
                     f'ZERO rows and every census over them passes vacuously')
            bad_delim = True
        if bad_delim:
            i += 2
            continue
        j = i + 2
        while j < hi and lines[j].lstrip().startswith('|'):
            row = split_cells(lines[j])
            if len(row) != len(header):
                v.append(f'{what}: data-row width mismatch at line {j + 1}: '
                         f'{len(row)} cells vs header {len(header)}')
                j += 1
                continue
            values.append((j + 1, row[0].strip().strip('`').strip('*').strip()))
            j += 1
        i = j
    if tables == 0:
        v.append(f'{what}: no registry table found (header opening "| {first_cell} | ...") '
                 f'— the registry section is missing or its header was altered')
    return values, v


# ── live-registry derivation ─────────────────────────────────────────────────

def derive_requirements(text):
    """(family_counts, ids, violations) from the requirement registry."""
    lines = text.split('\n')
    rows, v = parse_registry(lines, 0, len(lines), 'ID',
                             lambda c: c in REQ_SECOND_CELLS, 'requirement registry')
    family_counts = {}
    ids = []
    seen = {}
    for ln, val in rows:
        m = REQ_ID.match(val)
        if not m:
            v.append(f'requirement registry: data row at line {ln} has first cell '
                     f'{val!r}, which is not a valid MCP requirement ID — a row inside '
                     f'a matched registry table must carry a valid ID or be reported, '
                     f'never silently dropped (a dropped row is an untracked requirement '
                     f'a recount-and-reduce would hide)')
            continue
        ids.append(val)
        if val in seen:
            v.append(f'duplicate requirement ID {val!r} at lines {seen[val]} and {ln}')
        seen[val] = ln
        family_counts[m.group(1)] = family_counts.get(m.group(1), 0) + 1
    if not ids:
        v.append('requirement registry parsed ZERO requirement rows — an '
                 'UNCONDITIONAL failure; every requirement census is quantified '
                 'over these rows and an empty set satisfies all of them while '
                 'asserting nothing')
    return family_counts, ids, v


def derive_threats(text):
    """(threat_ids, violations) from the §11 canonical registry only."""
    lines = text.split('\n')
    lo = next((i for i, l in enumerate(lines) if l.startswith(THREAT_SECTION)), None)
    if lo is None:
        return [], [f'threat registry: section {THREAT_SECTION!r} not found']
    hi = next((i for i in range(lo + 1, len(lines))
               if lines[i].startswith(THREAT_SECTION_END)), len(lines))
    rows, v = parse_registry(lines, lo, hi, 'ID',
                             lambda c: c == 'Threat', 'threat registry')
    ids = []
    seen = {}
    for ln, val in rows:
        if not THREAT_ID.match(val):
            v.append(f'threat registry: data row at line {ln} has first cell {val!r}, '
                     f'which is not a canonical MCP-T-### ID — a row inside the §11 '
                     f'registry table must carry a valid ID or be reported')
            continue
        ids.append(val)
        if val in seen:
            v.append(f'duplicate threat ID {val!r} at lines {seen[val]} and {ln}')
        seen[val] = ln
    if not ids:
        v.append('threat registry parsed ZERO canonical MCP-T rows — an '
                 'UNCONDITIONAL failure (anti-vacuity)')
    return ids, v


# ── census parsing helpers ───────────────────────────────────────────────────

def summary_section(text):
    """The entire bounded `## Summary` section (its heading up to the next `## `).

    Census claims are counted over the WHOLE section, not just its first
    paragraph: a stale duplicate total or namespace claim placed after a blank
    line would otherwise escape the occurrence-counting that the duplicate /
    first-match-laundering protection depends on.
    """
    L = text.split('\n')
    start = next((i for i, l in enumerate(L) if l.strip() == '## Summary'), None)
    if start is None:
        return None
    end = len(L)
    for j in range(start + 1, len(L)):
        if L[j].startswith('## '):
            end = j
            break
    return '\n'.join(L[start:end])


def flatten(text):
    return re.sub(r'\s+', ' ', text)


def totals_check(name, values, expected, unique=True):
    """Missing / duplicate / mismatch for one governed total, occurrence-counted."""
    v = []
    if not values:
        v.append(f'{name}: no census claim found — a governed total must be '
                 f'published so it can be checked against the live registry')
        return v
    if unique and len(values) > 1:
        v.append(f'{name}: stated {len(values)} times {values} — a unique total '
                 f'claim must appear exactly once, or two copies can disagree '
                 f'while a first-match reader sees only the correct one')
    for val in values:
        if val != expected:
            v.append(f'{name}: document states {val}, live registry has {expected}')
    return v


# ── governed censuses ────────────────────────────────────────────────────────

def check_requirement_family_census(req_text, family_counts):
    """SECURITY-REQUIREMENTS.md `## Summary`: the COMPLETE per-family census, the
    total, and the namespace (family) count — all vs the live registry."""
    v = []
    n_fam = len(family_counts)
    total = sum(family_counts.values())

    sec = summary_section(req_text)
    if sec is None or 'Total requirements:' not in sec:
        return ['requirement family census (SECURITY-REQUIREMENTS `## Summary`) not '
                'found — the "Total requirements: N ... (per-family)" census is '
                'missing or was relabelled']
    plain = sec.replace('*', '')

    v += totals_check('requirement total (SECURITY-REQUIREMENTS Summary)',
                      [int(x) for x in re.findall(r'Total requirements:\s*(\d+)', plain)],
                      total)
    v += totals_check('namespace count (SECURITY-REQUIREMENTS Summary)',
                      [int(x) for x in re.findall(r'across\s+(\d+)\s+namespaces', plain)],
                      n_fam)

    mp = re.search(r'namespaces\s*\(([^)]*)\)', plain)
    if not mp:
        v.append('requirement family census: the per-family parenthetical '
                 '"(MCP-PROTO N, ...)" was not found after "across N namespaces"')
        return v

    claims = {}
    for fam, cnt in re.findall(r'(?:MCP-)?([A-Z][A-Z0-9]*)\s+(\d+)', mp.group(1)):
        claims.setdefault(fam, []).append(int(cnt))

    for fam in sorted(claims):                                  # forward + uniqueness + value
        if fam not in family_counts:
            v.append(f'requirement family census names unknown family {fam!r} — '
                     f'no live requirement ID belongs to it')
        elif len(claims[fam]) > 1:
            v.append(f'requirement family census claims family {fam!r} '
                     f'{len(claims[fam])} times {claims[fam]} — each family must '
                     f'be claimed exactly once, or two copies can disagree')
        elif claims[fam][0] != family_counts[fam]:
            v.append(f'requirement family census: family {fam!r} claims '
                     f'{claims[fam][0]} but the live registry has {family_counts[fam]}')

    for fam in sorted(family_counts):                           # reverse (completeness)
        if fam not in claims:
            v.append(f'requirement family census OMITS live family {fam!r} '
                     f'(live count {family_counts[fam]}) — a complete census must '
                     f'name every live family, or a stale total is hidden by dropping one')

    published_sum = sum(c[0] for c in claims.values() if len(c) == 1)
    if set(claims) == set(family_counts) and all(len(c) == 1 for c in claims.values()):
        if published_sum != total:
            v.append(f'requirement family census is internally inconsistent: the '
                     f'per-family counts sum to {published_sum}, but the live '
                     f'registry total is {total}')
    return v


def check_traceability_censuses(trace_text, req_total, req_family_counts, threat_total):
    """TEST-TRACEABILITY-MATRIX.md governed censuses."""
    v = []
    flat = flatten(trace_text)

    # Final-totals bullet — the requirement total is anchored to the adjacent
    # threat total ("**75 threats**; **94 requirements**"), so the historical
    # '"**91 requirements**" was stale' sentence is NOT matched.
    ft = re.findall(r'\*\*(\d+) threats\*\*;\s*\*\*(\d+) requirements\*\*', trace_text)
    v += totals_check('requirement total (traceability final-totals)',
                      [int(r) for _t, r in ft], req_total)

    # Threat total — "**N threats**" occurs only in the final-totals bullet.
    v += totals_check('threat total (traceability final-totals)',
                      [int(x) for x in re.findall(r'\*\*(\d+) threats\*\*', trace_text)],
                      threat_total)

    # §3 coverage assertion — "all N requirements, 0 unreachable" (wraps lines).
    v += totals_check('requirement total (traceability §3 coverage)',
                      [int(x) for x in re.findall(r'all\s+(\d+) requirements,\s*0 unreachable', flat)],
                      req_total)

    # Partial per-family spot-claims in the final-totals parenthetical.  A
    # deliberately partial list ("the other families unchanged"), so each named
    # family is checked but completeness is NOT required here.
    for fam, cnt in re.findall(r'MCP-([A-Z][A-Z0-9]*)\s+\*\*(\d+)\*\*', trace_text):
        if fam not in req_family_counts:
            v.append(f'traceability family spot-claim names unknown family {fam!r}')
        elif int(cnt) != req_family_counts[fam]:
            v.append(f'traceability family spot-claim: family {fam!r} states {cnt} '
                     f'but the live registry has {req_family_counts[fam]}')
    return v


# ── top-level check ──────────────────────────────────────────────────────────

def check(texts):
    v = []
    family_counts, _req_ids, rv = derive_requirements(texts['requirements'])
    threat_ids, tv = derive_threats(texts['threats'])
    v += rv
    v += tv

    if not family_counts:
        return v                            # refuse to run censuses over an empty registry
    v += check_requirement_family_census(texts['requirements'], family_counts)
    v += check_traceability_censuses(texts['traceability'], sum(family_counts.values()),
                                     family_counts, len(threat_ids))
    return v


# ── seeded controls ──────────────────────────────────────────────────────────
# Each seed carries the substring its INTENDED violation must contain, so a seed
# that only trips a different (e.g. anti-vacuity) check is reported as MISSED —
# not laundered into a pass by an unrelated failure.

def _mut(texts, key, fn):
    out = dict(texts)
    out[key] = fn(out[key])
    return out


def seed_wrong_req_total(t):
    return _mut(t, 'traceability',
                lambda s: s.replace('**94 requirements**', '**93 requirements**', 1))


def seed_wrong_family_count(t):
    return _mut(t, 'requirements',
                lambda s: s.replace('MCP-PROTO 14', 'MCP-PROTO 13', 1))


def seed_family_omitted(t):
    return _mut(t, 'requirements', lambda s: s.replace(', TOOL 6', '', 1))


def seed_family_duplicated(t):
    return _mut(t, 'requirements', lambda s: s.replace(', ID 8,', ', ID 8, ID 8,', 1))


def seed_family_unknown(t):
    return _mut(t, 'requirements', lambda s: s.replace('**OPS 5**)', '**OPS 5**, FOO 2)', 1))


def seed_duplicate_req_total(t):
    return _mut(t, 'requirements',
                lambda s: s.replace('**Total requirements: 94**',
                                    '**Total requirements: 94** **Total requirements: 94**', 1))


def seed_add_req_row(t):
    """A new valid live requirement row, no census updated."""
    row = ('| MCP-AUTH-009 | A newly added **MUST** control. | Rationale. | '
           'MCP-T-001 | Sec / Eng | Test | Evidence | PR-3 |')
    return _mut(t, 'requirements',
                lambda s: s.replace(
                    '| MCP-AUTH-008 | Management MCP and Gateway MCP',
                    row + '\n| MCP-AUTH-008 | Management MCP and Gateway MCP', 1))


def seed_remove_req_row(t):
    """A valid live requirement row deleted, no census updated (OPS 5 -> 4)."""
    return _mut(t, 'requirements',
                lambda s: re.sub(r'\n\| MCP-OPS-005 \|[^\n]*', '', s, count=1))


def seed_wrong_threat_total(t):
    return _mut(t, 'traceability',
                lambda s: s.replace('**75 threats**', '**74 threats**', 1))


def seed_duplicate_threat_total(t):
    return _mut(t, 'traceability',
                lambda s: s.replace('**75 threats**', '**75 threats** **75 threats**', 1))


def seed_add_threat_row(t):
    """A new valid canonical threat row in §11, no census updated."""
    row = '| MCP-T-076 | A newly added threat | High | MCP-AUTH-001 | Sec |'
    return _mut(t, 'threats',
                lambda s: s.replace('| MCP-T-001 | Token theft | High',
                                    row + '\n| MCP-T-001 | Token theft | High', 1))


def seed_remove_threat_row(t):
    return _mut(t, 'threats',
                lambda s: re.sub(r'\n\| MCP-T-003 \|[^\n]*', '', s, count=1))


def seed_req_zero_rows(t):
    """Every requirement data row removed — anti-vacuity."""
    def strip(s):
        return '\n'.join(l for l in s.split('\n') if not REQ_ID.match(
            (split_cells(l)[0].strip('`').strip('*').strip() if l.lstrip().startswith('|')
             and len(split_cells(l)) >= 1 else '')))
    return _mut(t, 'requirements', strip)


def seed_bad_req_delimiter(t):
    """An 8-cell requirement header over a 7-cell delimiter (the #947 shape)."""
    def bust(s):
        L = s.split('\n')
        for i, l in enumerate(L):
            if l.startswith('| ID | Statement |') and L[i + 1].startswith('|---'):
                L[i + 1] = '|---|---|---|---|---|---|---|'      # 7 cells vs 8
                break
        return '\n'.join(L)
    return _mut(t, 'requirements', bust)


def seed_malformed_req_id(t):
    """A requirement row's ID mistyped to a non-matching form. It must be
    REPORTED, not silently dropped — otherwise a recount-and-reduce of the
    published totals hides an untracked requirement still in the table."""
    return _mut(t, 'requirements', lambda s: s.replace('| MCP-OPS-005 |', '| MCP-OPS-0O5 |', 1))


def seed_duplicate_total_later_paragraph(t):
    """A stale duplicate total placed in a SECOND paragraph of `## Summary` —
    invisible to a first-paragraph-only reader, caught once the whole section is
    counted."""
    return _mut(t, 'requirements',
                lambda s: s.replace('and the Phase 5 consistency checks.',
                                    'and the Phase 5 consistency checks.\n\n'
                                    '**Total requirements: 91** (stale second copy).', 1))


def seed_first_match_laundering(t):
    """First total correct, a second duplicate total wrong — a first-match
    reader passes on the correct one; occurrence counting catches the second."""
    return _mut(t, 'requirements',
                lambda s: s.replace('**Total requirements: 94**',
                                    '**Total requirements: 94** (see also **Total requirements: 91**)', 1))


SEEDS = [
    ('wrong total requirement count', seed_wrong_req_total, 'requirement total'),
    ('wrong count for one live requirement family (PROTO)', seed_wrong_family_count, "family 'PROTO'"),
    ('one live family omitted from the family census (TOOL)', seed_family_omitted, "OMITS live family 'TOOL'"),
    ('duplicate family census claim (ID)', seed_family_duplicated, "claims family 'ID'"),
    ('unknown family census claim (FOO)', seed_family_unknown, "unknown family 'FOO'"),
    ('duplicate total requirement claim', seed_duplicate_req_total, 'stated 2 times'),
    ('add one valid live requirement row without updating censuses', seed_add_req_row, "family 'AUTH'"),
    ('remove one valid live requirement row without updating censuses', seed_remove_req_row, "family 'OPS'"),
    ('wrong total threat count', seed_wrong_threat_total, 'threat total'),
    ('duplicate total threat claim', seed_duplicate_threat_total, 'threat total'),
    ('add one valid live threat row without updating censuses', seed_add_threat_row, 'threat total'),
    ('remove one valid live threat row without updating censuses', seed_remove_threat_row, 'threat total'),
    ('requirement registry table parses to zero rows', seed_req_zero_rows, 'ZERO'),
    ('malformed requirement registry delimiter/header width', seed_bad_req_delimiter, 'width mismatch'),
    ('first-match laundering (correct then wrong duplicate total)', seed_first_match_laundering, 'stated 2 times'),
    ('malformed requirement ID dropped instead of reported', seed_malformed_req_id, 'not a valid MCP requirement ID'),
    ('duplicate total in a later Summary paragraph', seed_duplicate_total_later_paragraph, 'stated 2 times'),
]

# Negative controls: mutations that MUST stay silent, proving the predicate is
# bound to the two registries and their explicit censuses — not a prose linter.
NEGATIVE_CONTROLS = [
    ('a historical statement citing an earlier total',
     lambda t: _mut(t, 'traceability',
                    lambda s: s.replace('## 3. Coverage assertions (validated in Phase 5)',
                                        'An earlier draft counted "**88 requirements**" before the '
                                        'split; that figure is historical.\n\n'
                                        '## 3. Coverage assertions (validated in Phase 5)', 1))),
    ('an incidental threat-ID reference outside the §11 first column',
     lambda t: _mut(t, 'threats',
                    lambda s: s.replace('| MCP-T-001 | Token theft | High |',
                                        '| MCP-T-001 | Token theft (cf. MCP-T-002, MCP-T-075) | High |', 1))),
    ('an unrelated number in ordinary requirement prose',
     lambda t: _mut(t, 'requirements',
                    lambda s: s.replace('## MCP-PROTO',
                                        'There are 3 illustrative data flows discussed below.\n\n## MCP-PROTO', 1))),
]


def norm(vs):
    """Violation set with line numbers erased, so a pure re-numbering from a seed
    is not reported as a new finding."""
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
        fc, ids, _ = derive_requirements(texts['requirements'])
        tids, _ = derive_threats(texts['threats'])
        print(f'  requirements: {len(ids)} across {len(fc)} families  |  '
              f'threats: {len(tids)}  -> NONE')

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
        print(f'FAIL: seed {name!r} did not fire its intended violation '
              f'(expected substring {expect!r}); new violations: {new}')
    for name, new in noisy:
        print(f'FAIL: negative control {name!r} fired: {new}')
    if not bad:
        print('PASS: both registries parse non-vacuously and every governed '
              'requirement/threat census matches the live registry; all seeds '
              'fire their intended violation; all negative controls silent.')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
