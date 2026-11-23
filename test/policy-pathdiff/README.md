# Cross-path policy differential (shadow)

Verification only. No production code and no contract is changed. Every Go file is behind the build
tag `policy_pathdiff`, so `go build ./...` and `go test ./...` never compile it.

## Why this exists

A methodology experiment on five independent ports of another authorization library (kept outside
this repository) showed two things worth carrying over:

1. Divergences that matter live in **how each entry path turns a raw request into evaluator
   input**: host spelling, address representation, what a parser accepts.
2. **Generated differential testing and independent review find different things.** Neither
   replaces the other.

`#2029` already compares the evaluator and the Policy Tester core with an independent reference
model, at the evaluator's own interface. This suite covers the layer in front of it: the same
logical request, asked of every real entry path, starting from the bytes a client sends.

It claims no new method and no formal guarantee. It is differential testing with a reviewed
baseline.

## What is compared

| Path | What runs |
|---|---|
| `http` | `GET http://AUTHORITY/` over a real socket to a listener serving `handleRequest` |
| `connect` | `CONNECT AUTHORITY` over the same listener |
| `tester` | `apiPolicyTest`, the admin Policy Tester endpoint |
| `eval` | `policyStore.Evaluate`, the shared evaluator entry point |
| `reload` | the same rule base saved by one store and loaded by a fresh one, then evaluated |

The answer of a path is the **name of the rule that decided**, `-` for no match, or
`refused:<status>`. Every generated rule blocks and the default is deny, so nothing is dialled.
Rule identity is a stricter outcome than allow or deny.

Requests that vary the client address call the real handler with `RemoteAddr` set, after parsing
the same wire bytes with `net/http`'s own reader. All others use the socket.

SOCKS5 is not compared. On `main` it does not call the policy engine, and contract SWG-901 marks
that as undecided, so a difference there would be a known open question, not a finding.

## How a difference is read

A difference is evidence that two paths disagree. It is not, by itself, evidence that either is
wrong.

| Class | Meaning | Treated as |
|---|---|---|
| `decision-split` | two paths that both decide name different rules | asserted: must not occur |
| `refusal-split-enforcement` | HTTP and CONNECT disagree on whether to refuse | asserted: must not occur |
| `alias-split` | two spellings the reference calls the same destination decide differently on one path | asserted: must not occur |
| `oracle-mismatch` | a path disagrees with the reference on the literal fragment | asserted: must not occur |
| `tester-answers-unroutable` | the tester decides a spelling both enforcement verbs refuse | compatibility difference, baselined |
| `tester-refuses-routable` | the tester refuses a request enforcement decides | compatibility difference, baselined |
| unspecified alias behaviour | spellings the reference does not rule on | reported as a table, baselined, never asserted |

## The three methods

**A. Model.** `internal/pathdiffgen/ref.go`, standard library only (`TestIndependence` enforces it).

- D1 the port is not part of the host (RFC 3986 §3.2.2).
- D2 names compare case-insensitively (RFC 4343).
- D3 one trailing dot names the same name (RFC 1034 §3.1).
- D4 textual forms of one IPv6 address are one address (RFC 5952).
- POL-001 on the literal fragment: enabled rules in priority order, first match decides; a bare
  name covers its subdomains (`internal/hostutil` `MatchFQDN`).
- Publication transitions: replace, disable, delete.
- Two fixed tables: action dispatch against POL-001/003/004, and the invariant that spellings
  reaching the same address get the same decision.

Everything else is **Unspecified** and is reported, not asserted: IPv4-mapped against bare IPv4,
numeric IPv4 forms, zones, IDN, percent-encoding.

**B. Generator.** `internal/pathdiffgen/gen.go`. It knows the documented rule fields and a generic
catalogue of 60-odd spelling edits. It encodes no expectation about how production treats any of
them. Seven strata: `plain`, `dest`, `src`, `identity`, `stale`, `publish`, `combo`.

**C. Independent review.** A separate agent read production source only, saw no harness, case or
result, and wrote `review_predictions.jsonl` before the held-out run. `TestPathDiff_Review`
executes each prediction.

## Results after the three fixes (2026-11-23)

The verifier's leads became #2055 (zoned IPv6), #2053 (tester fidelity) and #2050 (POL-004), all
merged. The baselines were then reviewed entry by entry and re-recorded, and one fault in the
verifier's own wire model was corrected: `DRIFT-REVIEW-2026-11-23.md`. On the final code:
`decision-split` 0, `tester-answers-unroutable` 34 (bare IPv6, intentional),
`tester-refuses-routable` 99 (empty host, unchanged). The section below is the original result and
is kept as recorded.

## Results at `155df09`

Freeze record and expectations: `FROZEN.md`. Held-out seed `heldout-1`.

| Measure | Value |
|---|---|
| Generated cases / requests / path decisions | 2,600 / 25,000 / 125,000 |
| `decision-split`, `refusal-split-enforcement`, `alias-split`, `oracle-mismatch` | **0 / 0 / 0 / 0** |
| `tester-answers-unroutable` | 3,059 requests, 46 signatures |
| `tester-refuses-routable` | 99 requests (empty host) |
| Controls | identical runs agree; an injected fault in one path is detected |
| Campaign time | 18 s; whole `run.sh` about 30 s after compilation |

All six frozen expectations held. **The generator found no cross-path defect.** That is the result,
and it is reported as such.

### What each method found

| # | Observation | Found by | Class |
|---|---|---|---|
| 1 | A percent-encoded non-ASCII host (`b%C3%BCcher.de`) is decoded by `net/http` before `handleRequest`, so enforcement matches the rule for that name. The Policy Tester, given the same string, reports no match. | Review only (rev04); confirmed by the harness | Tester fidelity. Enforcement is correct. |
| 2 | A rule with an unrecognised action published through `ReplaceAll` or `Load` is dropped. Under default allow the traffic it covered is forwarded. The dispatch-level block that POL-004 describes is not reachable through these doors. | Model table (action dispatch) | Contract question, see below |
| 3 | A zoned IPv6 destination (`[2001:db8::7%25eth0]`) misses a rule for `2001:db8::7` on every path. Whether it reaches the same address was **not tested**: this environment has no IPv6 loopback. `TestPathDiff_DialAlias` logs it as `LEAD` where IPv6 exists. | Generator (unspecified table) | Unresolved |
| 4 | Numeric IPv4 spellings (`2130706433`, `0x7f.0.0.1`, `127.1`, zero-padded) miss a rule for the dotted form, and **do not reach the address** (502) with the shipped pure-Go resolver. | Generator and review (rev03), then the dial table | No defect. Baselined so a resolver change is visible. |
| 5 | The tester answers for spellings the wire refuses: `host:http`, raw UTF-8 names, unbracketed IPv6, invalid punycode. | Generator and review (rev01, rev07, rev08, rev10) | Compatibility difference, baselined |
| 6 | The request log carries no groups, so an operator cannot replay a group-based decision in the tester from the log alone. | Review only (rev02); not a harness-testable claim | Workflow gap, reported |

Review: 11 predictions. 9 executed exactly as predicted. Only one of them (rev04, #1) is a split
between two paths that both decide. rev01, 07, 08 and 10 are the tester answering a spelling the
wire refuses (#5); rev06 is a length gate the evaluator does not have, by design; rev03, 05 and 09
are alias observations on which all paths agree. rev02 (#6) is not harness-testable and rev11 was
not confirmed. **Unique to review: #1 and #6.** The generator edits ASCII percent-escapes, which
`net/http` rejects, so it could not reach #1.

**Unique to the generator:** #3, and the evidence of absence: HTTP and CONNECT agreed on all 25,000
requests; the reloaded store agreed with the live one on all of them; IPv4-mapped and IPv6 text
forms were canonicalised alike on every path.

### Observation 2 in detail (not a regression; an owner decision)

- **Contract:** POL-004, invariant "a matched rule with an unrecognised action blocks the request
  and is terminal"; compatibility "a rulebase written by a newer release must not become
  permissive on an older one".
- **Behaviour:** `policyRulePersistable` drops such a rule at `ReplaceAll` and `Load`
  (SEC-POLICYACTION-1, deliberate, pinned by
  `TestSECPOLICYACTION1_ReplaceAllDropsUnknownActionKeepsValid`). The rule therefore never matches.
- **Consequence:** with default allow, `action="Frobnicate"` on a rule for the backend: plain HTTP
  is forwarded (200). The tester reports no match and default allow, so the two agree.
- **Reproduce:** `go test -tags policy_pathdiff -run TestPathDiff_ActionDispatch -v .`
- **Options:** keep the rule installed and let dispatch block it; refuse the whole publication;
  or amend POL-004's compatibility sentence to say the guarantee holds under default deny only.

### Mutation campaign

15 single-edit mutants of the production paths, each run against this suite and against the full
existing root and `hostutil` suites. Details: `mutation/RESULTS.md`.

| | Count |
|---|---|
| Killed by this suite | 12 / 15 |
| Killed by existing tests | 11 / 15 |
| Killed only by this suite | 2 (invalid-host refusal removed; one source-CIDR unmap site) |
| Killed only by existing tests | 1 (bulk replace not sorting, which does not change decisions) |
| Killed by neither | 2 (probably equivalent) |

The existing suite is strong here, so the gain is modest. Every kill by this suite came from
baseline drift, which shows that behaviour changed and leaves the judgement to a reviewer.

## Running it

```bash
test/policy-pathdiff/run.sh <report dir>            # exit 0 pass, 1 drift, 2 incomplete
PATHDIFF_WRITE_BASELINE=1 test/policy-pathdiff/run.sh   # re-record after a reviewed change
PATHDIFF_SEED=other test/policy-pathdiff/run.sh         # a fresh seed (will not match the baseline)
```

## Making drift visible

- `baseline.json` holds every difference signature with its count, the per-stratum outcome table
  and the unspecified-alias table. Any change in any cell fails the run.
- It also holds a fingerprint of the generator, the reference and the harness. Changing the
  verifier fails the run until the baseline is re-recorded, so the change shows in the diff.
- The workflow warns when one pull request changes the verifier or its baselines together with
  the production paths they check.

This makes a simultaneous edit visible. It does not prevent it: whoever approves the baseline diff
is the control. Protecting `test/policy-pathdiff/` and `internal/pathdiffgen/` with CODEOWNERS is
the step that would make it binding, and is the owner's decision.

## Limits

- One product revision, one held-out seed. Zero splits on 25,000 requests is evidence, not proof.
- Rule identity is observed through hit counters, which are part of the product.
- Allow, redirect and drop are covered by a ten-row table, not by the campaign.
- Categories are exercised only as stale references; real membership is covered by `#2029`.
- Auth (Stage-1) rules are not generated. The identity provider is a test double.
- The reviewer is a model, standing in for an engineer.

## Next domain

**SOCKS5 against the shared evaluator**, once `#2041` (shadow evaluation) merges. It is the one
entry path with its own destination handling (`ATYP` address types instead of an authority
string), the contract is still open (SWG-901), and adding a sixth observer here is small. The
zoned-IPv6 lead should be closed first, on a runner with IPv6.
