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

Run from the repository root.  Requires git (the merge base is the ground truth).
"""
import re
import subprocess
import sys
import pathlib

D = pathlib.Path('docs/design/mcp')


def base_rev():
    out = subprocess.run(['git', 'merge-base', 'HEAD', 'origin/main'],
                         capture_output=True, text=True)
    if out.returncode:
        raise SystemExit('cannot resolve merge base against origin/main: ' + out.stderr.strip())
    return out.stdout.strip()


def at_base(path, rev):
    out = subprocess.run(['git', 'show', f'{rev}:{path}'], capture_output=True, text=True)
    return out.stdout if out.returncode == 0 else ''


# ---------------------------------------------------------------- claim 1
def req_rows(text):
    return {m.group(1): m.group(2).strip()
            for m in (re.match(r'^\| (MCP-[A-Z]+-\d{3}) \|(.*?)\|', l) for l in text.splitlines())
            if m}


def claim_requirements(new, old):
    """The note's own claimed sets, parsed from its bullets."""
    note = new[new.index('What this remediation changed in THIS registry'):][:2500]
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
    note = new[new.index('five decisions closed'):][:900]
    claimed = set(re.findall(r'\bD-(\d+)\b', note))
    o, n = decision_blocks(old), decision_blocks(new)
    actual = {k[2:] for k in set(n) - set(o)} | \
             {k[2:] for k in set(o) & set(n) if o[k] != n[k]}
    v = []
    if actual - claimed:
        v.append(f'OPEN-DECISIONS: blocks changed but NOT named in the note: '
                 f'{sorted("D-" + d for d in actual - claimed)}')
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
    note = new[new.index('Citation-correction note'):][:1600]
    o, n = vrc_rows(old), vrc_rows(new)
    v = []
    for k in sorted(set(o) & set(n)):
        if o[k] == n[k]:
            continue
        if '⟳' in n[k]:
            continue                       # covered by the ⟳ marker
        label = re.sub(r'[*`]', '', n[k].strip('|').split('|')[0]).strip()
        if label.lower() not in note.lower():
            v.append(f'VERIFIED-REPOSITORY-CONTEXT: row {label!r} changed, is not marked ⟳, and is '
                     f'not named in the citation-correction note')
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
    rev = base_rev()
    print(f'merge base: {rev[:12]}')
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

    print('\n=== residual on the live documents ===')
    v = run(rev)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')
    sys.exit(0 if ok and not v else 1)
