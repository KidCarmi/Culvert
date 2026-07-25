#!/usr/bin/env python3
"""Predicate 25 — every PROVENANCE claim ("what this remediation changed") must
match the actual diff against the merge base.

Round 38's finding: `SECURITY-REQUIREMENTS.md` said the requirement "IDs and
statements are unchanged except MCP-AUTH-006", while the same change added
sixteen IDs and rewrote seven statements.  A provenance note is the one thing a
reviewer reads INSTEAD of the diff, so a false one is worse than none — and
nothing but a diff can check it.

Three claims are enforced, each parsed out of the document that makes it:

  1. `SECURITY-REQUIREMENTS.md` — the ADDED and STATEMENT-REWRITTEN requirement
     ID sets, and the assertion that none were removed.
  2. `OPEN-DECISIONS.md` — the set of `### D-nn` blocks this remediation touched,
     plus any new decision.
  3. `VERIFIED-REPOSITORY-CONTEXT.md` — that every table row changed relative to
     the base is either marked `⟳` or named in the citation-correction note.

Run from the repository root.  Requires git: the PRE-REMEDIATION tree is the
ground truth for every claim here.

BASE STABILITY.  The base is a RECORDED IMMUTABLE COMMIT, not `git merge-base
HEAD origin/main`.  Once this branch merges, `origin/main` contains it and the
merge base becomes the current tree — the diff empties, the live provenance
claims "fail", and the seeds report MISSED.  A predicate advertised as
re-runnable has to stay re-runnable after the merge it describes.  Override with
CULVERT_PROVENANCE_BASE=<rev> for a rebased or transplanted history.
"""
import os
import re
import subprocess
import sys
import pathlib

D = pathlib.Path('docs/design/mcp')

# The commit this remediation branched from — the tree every provenance claim in
# this package is stated against.  Immutable by construction.
RECORDED_BASE = '1203e04bb7da6eb5803512f53d7bd7747d04c540'


def base_rev():
    override = os.environ.get('CULVERT_PROVENANCE_BASE')
    for rev, why in ((override, 'CULVERT_PROVENANCE_BASE'), (RECORDED_BASE, 'recorded base')):
        if not rev:
            continue
        ok = subprocess.run(['git', 'cat-file', '-e', rev + '^{commit}'],
                            capture_output=True, text=True)
        if ok.returncode == 0:
            return rev, why
        if rev is override:
            raise SystemExit(f'CULVERT_PROVENANCE_BASE={rev} is not a commit in this repository')
    raise SystemExit(
        f'recorded base {RECORDED_BASE[:12]} is not present (shallow clone?). '
        f'Re-run with CULVERT_PROVENANCE_BASE=<pre-remediation rev>.')


def at_base(path, rev):
    out = subprocess.run(['git', 'show', f'{rev}:{path}'], capture_output=True, text=True)
    return out.stdout if out.returncode == 0 else ''


def note_block(text, anchor):
    """The blockquote paragraph containing `anchor`.

    A fixed character window is the same defect as predicate-22's fixed span: as
    the document grows, unrelated IDs downstream of the note drift into the
    claim.  The note is a `>` blockquote, so its own delimiters bound it.
    """
    lines = text.splitlines()
    idx = next(i for i, l in enumerate(lines) if anchor in l)
    start = idx
    while start > 0 and lines[start - 1].lstrip().startswith('>'):
        start -= 1
    end = idx
    while end + 1 < len(lines) and lines[end + 1].lstrip().startswith('>'):
        end += 1
    return '\n'.join(lines[start:end + 1])


# ---------------------------------------------------------------- claim 1
def req_rows(text):
    return {m.group(1): m.group(2).strip()
            for m in (re.match(r'^\| (MCP-[A-Z]+-\d{3}) \|(.*?)\|', l) for l in text.splitlines())
            if m}


def claim_requirements(new, old):
    """The note's own claimed sets, parsed from its bullets."""
    note = note_block(new, 'What this remediation changed in THIS registry')
    claimed_added = set()
    for lo, hi in re.findall(r'`MCP-PROTO-(\d{3})\.\.(\d{3})`', note):
        claimed_added |= {f'MCP-PROTO-{n:03d}' for n in range(int(lo), int(hi) + 1)}
    bullets = note.split('- **')
    added_b = next((b for b in bullets if b.startswith('16 requirement IDs ADDED')
                    or 'IDs ADDED' in b[:40]), '')
    stmt_b = next((b for b in bullets if 'STATEMENTS rewritten' in b[:60]), '')
    claimed_added |= set(re.findall(r'`(MCP-(?!PROTO)[A-Z]+-\d{3})`', added_b))
    claimed_changed = set(re.findall(r'`(MCP-[A-Z]+-\d{3})`', stmt_b))

    o, n = req_rows(old), req_rows(new)
    actual_added = set(n) - set(o)
    actual_removed = set(o) - set(n)
    actual_changed = {k for k in set(o) & set(n) if o[k] != n[k]}

    v = []
    if claimed_added != actual_added:
        v.append(f'SECURITY-REQUIREMENTS: claimed ADDED {sorted(claimed_added)} != actual '
                 f'{sorted(actual_added)} (missing from note: {sorted(actual_added - claimed_added)})')
    if claimed_changed != actual_changed:
        v.append(f'SECURITY-REQUIREMENTS: claimed REWRITTEN {sorted(claimed_changed)} != actual '
                 f'{sorted(actual_changed)} (missing from note: {sorted(actual_changed - claimed_changed)})')
    if actual_removed:
        v.append(f'SECURITY-REQUIREMENTS: note claims 0 removed, but {sorted(actual_removed)} were removed')
    return v


# ---------------------------------------------------------------- claim 2
def decision_blocks(text):
    out, cur, buf = {}, None, []
    for l in text.splitlines():
        m = re.match(r'^### (D-\d+)\b', l)
        if m:
            if cur:
                out[cur] = '\n'.join(buf)
            cur, buf = m.group(1), []
        elif cur is not None:
            buf.append(l)
    if cur:
        out[cur] = '\n'.join(buf)
    return out


def claim_decisions(new, old):
    note = note_block(new, 'five decisions closed')
    claimed = set(re.findall(r'\bD-(\d+)\b', note))
    o, n = decision_blocks(old), decision_blocks(new)
    actual = {k[2:] for k in set(n) ^ set(o)} | \
             {k[2:] for k in set(o) & set(n) if o[k] != n[k]}
    v = []
    # BOTH directions: naming a decision the change never touched is the same
    # false-provenance defect as omitting one it did (round 39).
    if actual - claimed:
        v.append(f'OPEN-DECISIONS: blocks changed but NOT named in the note: '
                 f'{sorted("D-" + d for d in actual - claimed)}')
    if claimed - actual:
        v.append(f'OPEN-DECISIONS: note names decisions that are byte-UNCHANGED: '
                 f'{sorted("D-" + d for d in claimed - actual)}')
    return v


# ---------------------------------------------------------------- claim 3
def vrc_rows(text):
    out = {}
    for l in text.splitlines():
        if l.startswith('| ') and l.count('|') >= 4:
            cells = [c.strip() for c in l.strip('|').split('|')]
            key = re.sub(r'[⟳*` ]', '', cells[0])
            if key and key not in ('Primitive', '---'):
                out.setdefault(key, l)
    return out


def claim_vrc(new, old):
    note = note_block(new, 'Citation-correction note')
    o, n = vrc_rows(old), vrc_rows(new)
    v = []
    # the UNION, not the intersection: an added row, a deleted row and a renamed
    # label are all changes to a table whose note claims every other row is
    # byte-unchanged, and the intersection sees none of them (round 39).
    for k in sorted(set(o) | set(n)):
        if k in o and k in n and o[k] == n[k]:
            continue
        row = n[k] if k in n else o[k]
        kind = 'changed' if (k in o and k in n) else ('ADDED' if k in n else 'REMOVED')
        if kind == 'changed' and '⟳' in row:
            continue                       # covered by the ⟳ marker
        label = re.sub(r'[*`]', '', row.strip('|').split('|')[0]).strip()
        if label.lower() not in note.lower():
            v.append(f'VERIFIED-REPOSITORY-CONTEXT: row {label!r} was {kind}, carries no ⟳ cover, '
                     f'and is not named in the citation-correction note')
    return v


CLAIMS = [
    ('docs/design/mcp/SECURITY-REQUIREMENTS.md', claim_requirements),
    ('docs/design/mcp/OPEN-DECISIONS.md', claim_decisions),
    ('docs/design/mcp/VERIFIED-REPOSITORY-CONTEXT.md', claim_vrc),
]


def run(rev, override=None):
    v = []
    for path, fn in CLAIMS:
        new = (override or {}).get(path) or pathlib.Path(path).read_text()
        v += fn(new, at_base(path, rev))
    return v


if __name__ == '__main__':
    rev, why = base_rev()
    print(f'provenance base: {rev[:12]} ({why}) — stable across the merge this PR describes')
    base = set(run(rev))

    print('\n=== seeded known-positives (each MUST fire) ===')
    live = {p: pathlib.Path(p).read_text() for p, _ in CLAIMS}
    seeds = {
        'drop MCP-INSP-009 from the requirements provenance note': (
            'docs/design/mcp/SECURITY-REQUIREMENTS.md',
            [('`MCP-PROTO-001..014`, `MCP-ID-008`, `MCP-INSP-009`', '`MCP-PROTO-001..014`, `MCP-ID-008`')]),
        'drop MCP-OPS-002 from the rewritten-statements list': (
            'docs/design/mcp/SECURITY-REQUIREMENTS.md',
            [('and `MCP-OPS-002` (runtime bounds', 'and (runtime bounds')]),
        'drop D-14 from the decisions note': (
            'docs/design/mcp/OPEN-DECISIONS.md',
            [('**D-14 is NEW**', '**A further decision is NEW**'),
             ('plus the new\n> **D-14**', 'plus one more')]),
        'drop the ID-token row from the citation-correction note': (
            'docs/design/mcp/VERIFIED-REPOSITORY-CONTEXT.md',
            [('`ID-token validation` (the', '`(redacted)` (the')]),
        # ---- round 39: the note must be exact in BOTH directions -------------
        'name a decision the change never touched (D-3)': (
            'docs/design/mcp/OPEN-DECISIONS.md',
            [('plus the new\n> **D-14**', 'plus **D-3** and the new\n> **D-14**')]),
        # ---- round 39: one-sided rows are changes too -------------------------
        'ADD an unmarked repository-context row': (
            'docs/design/mcp/VERIFIED-REPOSITORY-CONTEXT.md',
            [('| ID-token validation |',
              '| Fabricated primitive | `nowhere.go · nothing · 1-2` | Nothing | Unreviewed |\n| ID-token validation |')]),
        'DELETE a non-⟳ repository-context row': (
            'docs/design/mcp/VERIFIED-REPOSITORY-CONTEXT.md',
            [('| OpenAPI contract + CI gate |', '| (deleted) x |')]),
    }
    ok = True
    for label, (path, edits) in seeds.items():
        if any(o not in live[path] for o, _ in edits):
            print(f'  SEED-DID-NOT-APPLY: {label}')
            ok = False
            continue
        override = dict(live)
        text = live[path]
        for o, nw in edits:
            text = text.replace(o, nw, 1)
        override[path] = text
        new = [x for x in run(rev, override) if x not in base]
        print(f'  {"FIRES" if new else "MISSED"}: {label}' + (f'\n      -> {new[0][:160]}' if new else ''))
        ok &= bool(new)

    print('\n=== base stability: the base must NOT track origin/main ===')
    mb = subprocess.run(['git', 'merge-base', 'HEAD', 'origin/main'],
                        capture_output=True, text=True).stdout.strip()
    head = subprocess.run(['git', 'rev-parse', 'HEAD'],
                          capture_output=True, text=True).stdout.strip()
    anc = subprocess.run(['git', 'merge-base', '--is-ancestor', rev, 'HEAD'],
                         capture_output=True, text=True).returncode == 0
    print(f'  recorded base is an ancestor of HEAD: {anc}')
    print(f'  recorded base != HEAD: {rev != head}  (after merge, merge-base would be {mb[:12]})')
    ok &= anc and rev != head

    print('\n=== residual on the live documents ===')
    v = run(rev)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')
    sys.exit(0 if ok and not v else 1)
