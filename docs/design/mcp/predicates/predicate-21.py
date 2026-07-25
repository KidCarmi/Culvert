#!/usr/bin/env python3
"""Predicate 21 — every DFD's own header declaration must agree with the
coverage-summary row that restates it, on BOTH the trust-boundary set and the
threat set.  Vocabulary is derived from the two documents (the DFD headers and
the coverage table), never from a hand-written token list, so it cannot decay
as the package grows (amendment 20).

Also checks THREAT-MODEL.md's per-DFD STRIDE rows against the same header.
"""
import re, sys, pathlib

DFD = pathlib.Path('docs/design/mcp/DATA-FLOW-DIAGRAMS.md')
TM = pathlib.Path('docs/design/mcp/THREAT-MODEL.md')


# both range syntaxes used by these documents: `MCP-T-011..017` in the DFD
# headers, `011–017` (en-dash) in the coverage rows.  A hyphen form is accepted
# too, since nothing stops a future edit from using it.
RANGE = re.compile(r'(\d{3})\s*(?:\.\.|[–—-])\s*(?:MCP-T-)?(\d{3})')


def nums(s):
    """3-digit threat numbers named by a threat list, with ranges EXPANDED.

    Keeping only a range's endpoints would let `057, 074` compare equal to
    `057..074` — i.e. certify parity for a row that dropped 058-073.  A
    compressed notation must be expanded before the sets are compared, never
    matched literally.
    """
    s = s.split('(')[0]
    out = set()
    for lo, hi in RANGE.findall(s):
        if int(lo) <= int(hi):
            out |= {f'{n:03d}' for n in range(int(lo), int(hi) + 1)}
    return out | set(re.findall(r'\d{3}', RANGE.sub(' ', s)))


def tbs(s):
    return set(re.findall(r'TB-(\d+)', s))


def headers(text):
    """{dfd_number: (boundary_set, threat_set)} from each '## DFD-n' section header."""
    out = {}
    cur = None
    for line in text.splitlines():
        m = re.match(r'^## DFD-(\d+)\b', line)
        if m:
            cur = m.group(1)
            continue
        if cur and line.startswith('Crosses'):
            decl, _, threats = line.partition('Threats:')
            # the DECLARATION is the clause before any explanatory prose — a later
            # prose mention of a boundary is not a declaration of it.
            decl = decl.split(' — ')[0].split('. ')[0]
            out[cur] = (tbs(decl), nums(threats))
            cur = None
    return out


def coverage(text):
    """{dfd_number: (boundary_set, threat_set)} from the coverage-summary table."""
    out = {}
    for line in text.splitlines():
        m = re.match(r'^\|\s*(\d+)\s*\|([^|]*)\|([^|]*)\|([^|]*)\|', line)
        if m:
            out[m.group(1)] = (tbs(m.group(3)), nums(m.group(4)))
    return out


def tm_rows(text):
    """{dfd_number: threat_set} from THREAT-MODEL's per-DFD rows."""
    out = {}
    for line in text.splitlines():
        m = re.match(r'^\|\s*DFD-(\d+)\s*\|([^|]*)\|([^|]*)\|', line)
        if m:
            out[m.group(1)] = nums(m.group(3))
    return out


def run(dfd_text, tm_text):  # STRICT arm only
    h, c, tm = headers(dfd_text), coverage(dfd_text), tm_rows(tm_text)
    violations = []
    for n in sorted(h, key=int):
        if n not in c:
            violations.append(f'DFD-{n}: header present, NO coverage row')
            continue
        hb, ht = h[n]
        cb, ct = c[n]
        if hb != cb:
            violations.append(f'DFD-{n}: boundary mismatch — header TB{sorted(hb)} vs coverage TB{sorted(cb)}')
        if ht != ct:
            violations.append(f'DFD-{n}: threat mismatch — header {sorted(ht)} vs coverage {sorted(ct)}')
    for n in sorted(c, key=int):
        if n not in h:
            violations.append(f'DFD-{n}: coverage row present, NO header declaration')
    return violations


if __name__ == '__main__':
    dfd_text, tm_text = DFD.read_text(), TM.read_text()

    print('=== seeded known-positives (each MUST fire) ===')
    seeds = {
        'drop TB-7 from DFD-15 header':
            (dfd_text.replace('Crosses **TB-1, TB-7** — Gateway', 'Crosses **TB-1** — Gateway', 1), tm_text),
        'drop 031/055 from DFD-1 coverage row':
            (dfd_text.replace('| 1 | A (mgmt) | TB-7 | 034, 035, 010, **031, 055** |',
                              '| 1 | A (mgmt) | TB-7 | 034, 035, 010 |', 1), tm_text),
        'drop TB-5 from DFD-2 coverage row':
            (dfd_text.replace('| 2 | A (mgmt) | TB-7, TB-5 |', '| 2 | A (mgmt) | TB-7 |', 1), tm_text),
        # a range collapsed to its endpoints drops 058-073 and MUST NOT compare equal
        'collapse DFD-15 coverage range 057-074 to its endpoints':
            (dfd_text.replace('| 057–074 (parser/framing/version/state) |',
                              '| 057, 074 (parser/framing/version/state) |', 1), tm_text),
        # ...and the same collapse on the header side
        'collapse DFD-4 header range 011..017 to its endpoints':
            (dfd_text.replace('Threats: MCP-T-011..017, MCP-T-020.',
                              'Threats: MCP-T-011, MCP-T-017, MCP-T-020.', 1), tm_text),
    }
    ok = True
    for name, (d, t) in seeds.items():
        base = set(run(dfd_text, tm_text))
        v = [x for x in run(d, t) if x not in base]
        want = name.split('DFD-')[1].split()[0].rstrip(':')
        fired = any(x.startswith(f'DFD-{want}:') for x in v)
        print(f'  {"FIRES" if fired else "MISSED"}: {name}' + (f' -> {v[0]}' if v else ' -> (no NEW violation)'))
        ok &= fired

    print('\n=== STRICT arm residual (header <-> coverage row) ===')
    v = run(dfd_text, tm_text)
    print('\n'.join('  ' + x for x in v) if v else '  NONE')

    print('\n=== ADVISORY: DFD header vs THREAT-MODEL STRIDE row (NOT gated) ===')
    h, tm = headers(dfd_text), tm_rows(tm_text)
    adv = [f'DFD-{n}: header {sorted(h[n][1])} vs THREAT-MODEL {sorted(tm[n])}'
           for n in sorted(h, key=int) if n in tm and tm[n] != h[n][1]]
    print('\n'.join('  ' + x for x in adv) if adv else '  NONE')
    sys.exit(0 if ok and not v else 1)
