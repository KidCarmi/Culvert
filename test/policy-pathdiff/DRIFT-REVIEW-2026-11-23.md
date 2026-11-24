# Baseline drift review — after #2055, #2053 and #2050

The three fixes this verifier led to are merged. This is the review of what they changed in the
baselines. Nothing was re-recorded until every changed entry had an explanation; the table below is
that explanation. Same seed (`heldout-1`), same generator (`pathdiffgen/1`), same 25,000 requests.

## Step 1 — the unchanged verifier against the fixed code

141 drift lines. All but one group traced to a fix:

| What moved | Cause |
|---|---|
| 14 aliases left `tester-answers-unroutable` (backslash, frag, idn_bad, nul, pct_char, pct_dot, port_name, sp_head, sp_tail, star, tab, v4_bracket, v6_dblbracket, v6_zone_raw); the class fell from 3,059 to 796 | #2053: the tester refuses what the request parser or the host gate refuses |
| `v6_zone`: HTTP and CONNECT went from deciding to `refused:400` (31 requests); the tester refuses too | #2055 |
| `action="Frobnicate" default=allow`: `http=forward(200)`, `DIFFERS-FROM-CONTRACT` became `http=block(403)`, `as-specified` | #2050 (POL-004) |
| **364 new `decision-split`** on `query`, `slash`, `userinfo` (`http=refused connect=refused tester=M eval=N`) | **not a product defect: a fault in this verifier**, below |

## Step 2 — the fault in the verifier

The wire paths sent the authority under test as the `Host` header as well as the request target.
For absolute-form and CONNECT the proxy takes its destination from the request target; `net/http`
only validates the header. An odd authority in the header (`example.com?x`, `user@example.com`, a
raw non-ASCII name) drew `400` from `net/http` for the header, and the verifier recorded that as
"the wire refuses this destination". A client reaches the handler with the same request target by
sending any valid header, so those rows described the header check, not the proxy.

This is the same mistake the independent review of #2053 found in that PR's first parity test.

Correction (`FROZEN.md`, change 4):

1. Wire requests carry a fixed valid `Host` header.
2. The two evaluator paths are asked about the host the request delivers (the standard library's
   request-target parse, called directly, not through the product's helper), not the typed string.
   No ingress hands the evaluator `example.com?x`. A target the parser refuses is recorded as
   `refused:parse` for those two paths.

The comparison semantics (X1, X2, the two tester classes, the oracle, D1–D4) are unchanged. The
generator and reference are unchanged. The verifier fingerprint changes, as it must.

## Step 3 — the corrected verifier, both sides of the fixes

| | Pre-fix code (`e1a3710`) | Final code |
|---|---|---|
| `tester-answers-unroutable` | 1,933 across 15 aliases | 34, one alias (`v6_nobracket`) |
| `decision-split` | 364 (`query`, `slash`, `userinfo`: tester matched the typed text, the wire matched the host) | **0** |
| `tester-refuses-routable` | 99 (`empty`) | 99 (`empty`) |
| `oracle-mismatch`, `alias-split` among *Same* aliases, `anomaly` | 0 | 0 |
| `Frobnicate` under default allow | forwarded, `DIFFERS-FROM-CONTRACT` | blocked, `as-specified` |
| `v6_zone` on HTTP / CONNECT | decided (24 of 27 matched bases lost their rule) | `refused:400` |

So the corrected verifier still reports each of the three defects on the old code, and reports none
of them on the new code. The 364 pre-fix `decision-split` rows are a real pre-fix tester
infidelity that the old verifier had filed under a weaker class.

## What remains in the baseline, and why it is not a defect

- **`tester-answers-unroutable|v6_nobracket` (34).** The tester brackets a bare IPv6 literal
  because that is what an administrator types and what the rule editor submits. Intentional (#2053).
- **`tester-refuses-routable|empty` (99).** `GET http:/// HTTP/1.1` reaches the handler with an
  empty host and source-only rules decide it; the tester says "host is required". Unchanged from
  the first baseline. A compatibility difference, already reported.

## Entries that did not change

- Strata `identity`, `plain`, `publish`, `src`, `stale`: every count identical.
- 23 of 47 alias tables identical (all the IPv4 spellings, the dot and label variants, the punycode
  forms, `parent`, `sub`, the suffix variants, and `empty` on all five paths).
- Dial-alias baseline: identical. Its zoned rows run only where IPv6 loopback exists; they are
  logged by CI, not baselined.
- Dispatch baseline: one row changed (above); the other nine identical.

## Alias tables that changed only because the wire is now observed

`fullwidth_dot`, `homoglyph`, `ideo_dot`, `idn_u`, `zwsp`, `query`, `slash`, `userinfo`: HTTP and
CONNECT used to read `refused:400` (the header); they now show the proxy's decision, and on every
one of them all five paths agree. Worth knowing as behaviour, not as a finding: a zero-width space
or a fullwidth dot in a request-target host is normalized by IDNA and decided as the mapped name.

## Controls rerun

- `TestPathDiff_Controls` (determinism; a fault injected into one path is detected): pass.
- Pre-fix negative control: the column above.
- Mutation campaign, verifier side, rerun on the final code with three added mutants that each
  undo one fix: see `mutation/RESULTS.md`.

## Limits of this review

- Run on a host without IPv6 loopback, so the zoned dial rows did not execute here. They execute in
  the shadow CI job, and #2055's own qualification job covers the backend-never-reached claim.
- The evaluator paths now share the standard library's parse with the wire paths. That is the
  parse the product sits behind, so it is the right input, but those two paths no longer exercise
  the evaluator on strings the parser refuses.
