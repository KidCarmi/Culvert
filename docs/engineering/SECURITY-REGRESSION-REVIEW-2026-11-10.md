# Security Regression Review — 2026-11-10

**Scope.** `d11ed3a…ac4e223` (`origin/main`) — the window since the 2026-11-09
review, 10 merged pull requests (#1844 #1845 #1846 #1847 #1848 #1849 #1850
#1851 #1852 #1853), 45 files, +5,563/−537.

| PRs | Change | Security surface |
|---|---|---|
| **#1853** | `fix(policy)`: category-group rules match on category MEMBERSHIP, not on the classification winner | **policy fail-open**, and the widening reaches **Allow**, SSL bypass/inspect and **Stage-1 auth `Exempt`** |
| **#1849** | CHAOS-115: bound the scan sidecar's buffered-body concurrency; refuse the overflow with 429 | **memory-exhaustion DoS → fleet-wide scanning fail-open**; new fail-CLOSED refusal path |
| **#1845** | IM-008: extract the destination pseudonymizer to `internal/pseudonym`, plus a fold fix found in flight | **destination redaction** (plaintext-host leak + panic), key/id state, HMAC token stability |
| **#1850** | `perf(inspect)`: name and document the inspect-leg read buffer instead of shrinking it | inspected-tunnel **trailer window**, per-tunnel resident heap |
| **#1844** | diagnostics row when the admin UI degraded to plain HTTP | **cleartext admin credentials/session cookies**, operator visibility |
| **#1848** | the 2026-11-09 review and its two comment corrections | `apiDiagnostics` disclosure boundary, decision-line log-field barrier |
| **#1852** | let the SimpleSAMLphp interop test reach its loopback fixture | **SSRF guard** test seam, SAML metadata fetch path |
| **#1851** | raise the Security Release Gate race budget to 70m / 60m | CI gate availability (a timing-out gate is a gate that does not run) |
| **#1846 #1847** | terminology and documentation governance reviews (no findings) | none |

**Question asked.** Not "is the change good?" but the inverse: **did it weaken
the posture that existed at `d11ed3a`?** Every verdict below is measured against
that revision, not against an ideal.

**Method.** This window's risk sits in two changes that alter what the gateway
*decides*, and the rest is documentation, extraction and CI budget. #1853 widens
a matcher, so it was read as a *direction* question first — which rule actions
get wider, not just which get correctly narrower — and its one remaining
short-circuit (the uncategorized host) was checked for soundness against the
index code on both resolution paths rather than against its own comment. #1849
converts a heap-exhaustion fail-OPEN into a capacity fail-CLOSED, so the load-
bearing question is the status code and the ordering, and both were traced to
the caller's classifier. #1845 moves secret-adjacent code between packages,
where the only interesting question is whether anything changed in transit, so
the symbol inventory was diffed and every non-wrapper divergence was run down.

Claims that mattered were **executed or traced to source, not taken from a
comment**: the window's own gates were run at this SHA (`go build ./...` clean;
`internal/catgroup`, `internal/pseudonym`, `internal/secscan` pass, the latter
two also under `-race`; and the root-package gates this window added or touched
pass), the 429 → fail-CLOSED chain was followed through `scanOnce` into
`remoteScanRefused`, the admission gate's startup ordering was checked against
`main.go`'s init sequence rather than assumed, the uncategorized guard was
derived from `urlcat.lookupIn` versus `urlcat.matchesHostIn` key-for-key, and
the entropy-failure fallback the extracted package advertises was tested
directly — it does not exist on the pinned toolchain, which is finding C.

**No security regression. Three findings, all Low, all fixed here. Five
residual risks recorded, none introduced by this window.**

---

## Executive Summary

**No security regression was introduced by this window, and two of its changes
are material improvements to posture.**

The category-group membership fix (#1853) **closes a real fail-open and is
sound**, including the short-circuit it keeps. A category-group rule used to
decide "is this host in ANY category of the group?" from the single category the
host *classifies* as. Because the signed-feed resolution puts admin categories
first on a path that is armed on every startup, an admin category covering a
host by parent suffix beats a built-in exact entry — so a Block rule on
`{Social Media, News}` stopped matching `news.example.test` while
`destCategory=News` still blocked it. The fix uses the membership primitive the
single-category leg already used, and the differential oracle
(`TestCategoryGroupMembership_EqualsOrOfSingleCategoryMembership`) pins the new
behaviour as exactly the OR of single-category matches over the group, on both
the armed and unarmed paths.

The one place that could still fail open is the `hostCat == ""` early return,
which now rests on a semantic claim rather than a tautology: "no tier classifies
this host" must imply "no category can claim it". That claim is true, and not
only by sweep. `urlcat.lookupIn` probes exactly `{h} ∪ {suffix after each '.'}`
against an index holding a `patternRef` for **every** pattern in `entries`,
while `matchesHostIn` probes the same key set against `index[catKey]`, whose
members are those same patterns filed under their category — so a membership hit
on any category implies a classification hit, per tier and per index pair
(`hostIndex`/`index`, `adminHostIndex`/`adminIndex`). On the view-armed leg
`entries` is a pure projection of `members` (`embeddedBaselinePair`, one store
read), so the same implication holds there. `TestCategoryGroupMembership_UncategorizedGuardIsSound` then sweeps the shipped taxonomy over both paths and refuses to
pass vacuously.

**What the fix also does, and what the upgrade note did not say, is widen three
rule actions.** Membership is strictly wider than winner-only, so every rule
keyed on a category group matches more hosts — including **Allow**, SSL
bypass/inspect, and **Stage-1 auth `Exempt`**, which waives proxy
authentication. The CHANGELOG named the first two and omitted the third, even
though the window's own gate (`TestCategoryGroupMembership_ArmedCDRAndAuthAgree`)
asserts the widening on an `OutcomeExempt` rule and that outcome is runtime-live
(`resolveNoCredAuthOutcome` → proxy arm-3). That is finding A. The fix itself is
right — the narrow behaviour was the defect, and group semantics now match
single-category semantics — but an admin deciding what to audit before upgrading
was pointed away from the authentication boundary.

CHAOS-115 (#1849) retires a **measured, unauthenticated** memory-exhaustion
amplifier whose end state was a security control collapsing fleet-wide. The
sidecar's `/scan` read the body before anything bounded it, so buffered-body
exposure was `open_connections × (window+1)` — 244.5 MiB at 192 stalled callers
on a 1 MiB window, extrapolating to ~1.2 GiB at the shipped 5 MiB default — and
the OOM's consequence is not one node's: every caller pointed at a silent
sidecar takes `internal/secscan`'s fail-OPEN branch and forwards bodies
**unscanned**. The gate acquires **before** the read, which is the whole fix,
and the refusal is **429 specifically**: 429 and 413 are the only statuses
`scanOnce` classifies as something other than a fault, and a fault fails OPEN.
That chain was traced, not inferred. The byte-denominated budget is also derived
at the right instant — `loadScanning` runs `globalSecScanner.Init(…,
cfg.MaxScanBytes, …)` before `startScanServiceSidecar`, `initSSLBypassAndDPI`
precedes `initScanning`, and `Scanner.Init` is the only writer of `maxBytes` —
so the slot count reflects the operator's configured window rather than a
pre-settings default.

The pseudonymizer extraction (#1845) is **faithful in every reachable
behaviour**, and it carried a genuine redaction fix. `ReplaceHostFold` searched
`strings.ToLower(s)` and used the match index to slice `s`; `ToLower` is not
length-preserving (U+023A grows 2→3 bytes, each invalid UTF-8 byte becomes a
3-byte U+FFFD), so any growing byte before the host shifted every later offset
and the "redacted" URI either kept the host in **plaintext** or sliced past the
end and panicked. The defect predates the extraction. Narrowing the fold to
ASCII loses no case the old code handled *correctly*: every non-ASCII character
whose `ToLower` could create a new match also changes byte length, which is the
condition that already broke the offsets. The one divergence worth reporting is
finding C, and it is not a live bug: root's `mintTrafficKeyID` now mints and
discards a 32-byte key to obtain an id, and takes `MintPair`'s zero-id leg on
entropy failure — a leg that cannot fire, because since Go 1.24
`crypto/rand.Read` never returns an error and crashes the process instead.

The inspect-buffer change (#1850) **changes no byte and no accepted traffic**:
`inspectLoopReadBufSize` is `32 * 1024`, byte-identical to the two literals it
replaced, and the two readers are now built through one constructor the gates
measure. Its value is the recorded reason — the size bounds the chunked-trailer
block an inspected tunnel will accept, so shrinking it would make inspection
*refuse* responses that pass with inspection off.

The admin-UI plain-HTTP row (#1844) is a **disclosure improvement** that keeps
the raw crypto error off the new surface. The CI change (#1851) raises a budget
and nothing else: no `permissions:`, `egress-policy`, `secrets.`,
`continue-on-error`, `if:` or `GOTOOLCHAIN` line changed anywhere in the window,
and the race gate still runs `-race -count=1 ./...` behind the same ≥ 55%
coverage threshold. The SAML interop change (#1852) touches only a `_test.go`
file that is skipped unless `CULVERT_SIMPLESAML_METADATA_URL` is set, registers
its cleanups in the correct LIFO order, and adds no non-test caller of the SSRF
seam — all 34 `ssrf.AllowLoopbackForTest` call sites in the tree remain in test
files. No `requireRole`, `uiRoutes`, `saveConfigVersion` or `auditEvent`
behaviour changed in the window at all.

---

## Security Findings

### SEC-2026-11-10-A — the upgrade note omits the authentication direction of the category-group widening (Low)

**Affected contract.** Stage-1 authentication exemption (`AuthSpec.Outcome =
OutcomeExempt`) scoped by `DestCategoryGroup` / `DestCategoryGroupID`.

**What the code does.** `categoryGroupMatchesHostScratch` is reached from
`matchDestNorm`, which `authRuleMatchesScratch` calls for every Stage-1 auth
rule (`authpolicy.go:646`). Membership is strictly wider than winner-only, so
after #1853 an `Exempt` rule keyed on a category group matches hosts that belong
to one of its categories **without classifying as it** — and
`resolveNoCredAuthOutcome` is the live runtime path for that outcome ("RUNTIME
PATH — proxy.go's arm-3 hook handles Exempt (waive)", `authpolicy.go:309`). The
window's own gate asserts the widened match on an `OutcomeExempt` rule.

**What the note said.** The CHANGELOG's **Behaviour change** sentence named the
widened directions as "Allow rules, and rules carrying an SSL bypass or inspect
action". Its preceding sentence does list "Stage-1 auth rules" among the scans
the fix reaches, but an operator reads the behaviour-change sentence to decide
what to re-audit, and that sentence pointed only at what gets *allowed* or *left
uninspected*, never at what gets *unauthenticated*.

**Why it matters more than wording.** Of the three widened actions this is the
only one that removes an identity requirement, and it is the one a reader is
least likely to re-derive: the taxonomy overlap that triggers the widening
(an admin category covering a parent suffix) is invisible from the rule itself.
`CredentialRequired` widens in the safe direction — more destinations
challenged — so the asymmetry is real and worth naming.

**Fix.** The behaviour-change note now names the `Exempt` direction explicitly,
states that `CredentialRequired` widens fail-closed, and points at the rule
surfaces and the Policy Tester (which evaluates the same matcher). No code
change: the matcher is correct and the gate already exists.

**CWE-285** (improper authorization) / **CWE-1059** (insufficient documentation)
· **OWASP A01:2021 Broken Access Control** · severity **Low** (documentation of
a correct, intentional, already-gated behaviour change) · regression risk
**none**.

### SEC-2026-11-10-B — `scanOnce`'s 429 branch still described itself as unreachable after CHAOS-115 (Low)

**Affected contract.** Fail-closed posture for sidecar capacity
(`remoteOutcomeCapacity`), `internal/secscan/remote.go`.

**What the code says.** The 429 branch carried: *"The shipped sidecar never
emits 429 today; a load balancer or a third-party scanner in front of it can,
and classifying it correctly costs nothing."* After #1849 that is false —
`refuseScanAtCapacity` makes the shipped sidecar emit exactly 429, and the
window's own `remoteScanRefused` doc says so ("CHAOS-115 gave the shipped
sidecar an admission gate, so this is now the line an operator reads in the
saturation regime"). One comment was updated; the branch's own, 170 lines below,
was not. `scan_svc_admission.go` then quoted the stale sentence approvingly.

**Attack-relevant consequence.** The status code is load-bearing in one
direction: 429 and 413 are the only non-200 statuses `scanOnce` classifies as
something other than a fault, and the fault leg returns
`"sidecar returned HTTP %d"` → `remoteScanFail` → **fail OPEN** (WK-2b). A
maintainer who trusts the comment and treats the branch as dead — reclassifying
it, folding it into the default, or removing it in a cleanup — converts a
fail-CLOSED capacity refusal into a fleet-wide unscanned forward under exactly
the load the gate exists to survive. No gate asserts the branch is reachable;
`TestChaos115_CapacityRefusalFailsClosedAtTheCaller` asserts the *classification*
once the status arrives.

**Fix.** The comment now states that the branch is live, why the status is
load-bearing, and what reclassifying it would cost. The quotation in
`scan_svc_admission.go` is corrected to record that the sentence was falsified
by that file, rather than repeating it.

**CWE-1059** · severity **Low** · regression risk **none** (comment only).

### SEC-2026-11-10-C — the extracted pseudonymizer's id-only path spends a key and relies on an unreachable fallback (Low)

**Affected contract.** The non-secret pseudonym **generation id** (2E-B §B):
durable identity that makes rotation exactly-once observable.

**What changed in transit.** Pre-extraction, `mintTrafficKeyID` read 8 random
bytes and, on failure, returned a monotonic `gen-N` id — documented as "so a key
install never silently loses its observable generation". Post-extraction it
reads `trafficPseudonymizer.MintPair()`, which mints a **32-byte key the caller
discards** and whose failure leg returns `("", err)`; the wrapper drops the
error and returns the **empty** id. `""` is precisely what `KeyID()` reports for
*no key installed*, so the single caller —
`applyAdminTrafficPseudonym`'s legacy-upgrade leg, a persisted key with no
persisted id — could publish a valid key beside a keyless-looking id, which is
the state the generation identity exists to rule out.

**Why this is Low and not Medium.** The leg is unreachable. Verified against the
pinned toolchain's source (`crypto/rand/rand.go`: *"It never returns an error…
crashes the program irrecoverably if an error is returned"*) and demonstrated by
execution — swapping `crypto/rand.Reader` for a failing source does not exercise
the fallback, it terminates the test binary with `crypto/rand: failed to read
random data`. So no reachable behaviour regressed, in either direction, and the
same is true of the error returns on `Rotate`, `Ensure` and `MintPair`.

**Fix.** `Pseudonymizer.MintID()` exposes the id-only mint; root's
`mintTrafficKeyID` calls it. One top-level exported name was *not* added (MintID
is a method), so the IM-008 isolation row's "6 exported names" still holds.
`mintID`'s comment now records that its fallback is dead code on this toolchain
and why it is kept, instead of advertising a guarantee that cannot fire — the
failure mode the 2026-11-09 review's R4 named.

**CWE-1059**, **CWE-665** (improper initialization) adjacent · severity **Low**
· regression risk **none** reachable.

---

## Risk Rating

| ID | Finding | Severity | Exploitable now | Regression? |
|---|---|---|---|---|
| A | Upgrade note omits the auth-`Exempt` direction of the category-group widening | Low | No | No — documentation of an intentional, gated behaviour change |
| B | `scanOnce`'s 429 comment claims the branch is unreachable after CHAOS-115 made it live | Low | No | No — comment only; the code is correct |
| C | id-only mint spends a key and routes through an unreachable zero-id leg | Low | No | No reachable behaviour change |

**Window verdict: no security regression.** No finding at Medium or above. All
three are documentation or contract-shape corrections of correct code, fixed
here; the only code change is the `MintID` seam, which alters no reachable
behaviour.

---

## Regression Analysis

Measured against `d11ed3a`, per surface.

**Policy and authorization.** The only behavioural change in the window.
`matchDestNorm`'s category-group leg moves from winner-only to membership;
classification itself (order and winner) is untouched, so decision logs and
`lookupHostCategory` still report one category. The widening is bounded by group
membership and is exactly the OR of single-category matches, pinned by a
differential oracle over five group shapes × seven hosts × both the armed and
unarmed paths. `matchesMember`'s winner fast path (`g.catSet[catKey]`) is what
guarantees **no host that matched before stops matching**; the probe loop is fed
`g.Categories`, which `normCats` produces as `ToLower(TrimSpace(·))` and
`buildCatSet` keys with `CategoryKey` = `ToLower`, so entries *are* catSet keys
and the `c != catKey` skip is exact rather than approximate. Unknown group and
empty `catKey` both still fail closed, including on the un-migrated name
fallback leg. The widened directions are enumerated under finding A.

**Authentication / SAML.** No production change. #1852 edits one `_test.go`
file, gated behind an environment variable, and uses the pre-existing
`ssrf.AllowLoopbackForTest` seam with `t.Cleanup` in the correct LIFO order
(cache reset, then guard-table restore, which resets again). `grep` over the
tree confirms every one of the 34 seam call sites is in a test file, so no
production path relaxes the SSRF guard. Stage-1 auth logic itself is unchanged;
only what its destination matcher matches is wider (finding A).

**Proxy / request processing.** `proxy.go` is comment-only. `proxy_tunnel.go`
replaces two `bufio.NewReaderSize(…, 32*1024)` literals with one constructor
over `inspectLoopReadBufSize = 32 * 1024` — byte-identical, so the chunked-
trailer window an inspected tunnel accepts, and the per-tunnel residency, are
both unchanged. No change to request parsing, header handling, destination
canonicalization or the H1 keep-alive loop's teardown.

**Scanning.** The posture change is in the fail-CLOSED direction and does not
invent a verdict: the sidecar refuses with 429 and the caller's existing
`remoteOutcomeCapacity` → `remoteScanRefused` path blocks, counting
`statRemoteScanSaturated` and reusing the `scan_timeout` alert. Acquire-before-
read is the ordering that matters and is what the handler does. `release()`
decrements the gauge before the channel receive, so the gauge cannot read above
the slot count; a failed `acquire` returns a nil release and the handler returns
before the `defer`, so there is no nil call. The waiting bound is
`scanSvcQueueWait = 5s`, chosen below the caller's 10s `ScanBodyTimeout` so a
capacity refusal is classified as capacity rather than as a timeout — correct,
and the file is explicit that `r.Context()` contributes cancellation only. The
new `/health` and `/metrics` fields ride the existing `Configured` guard, so a
node that never ran a sidecar exports no sidecar saturation plane.

**Redaction, secrets and persistence.** The extraction is wrapper-for-wrapper:
every root name kept its signature and its call sites, the HMAC algorithm,
`h_` prefix, 12-hex token width, lowercase alphabet, pooled-hasher generation
binding and `hasherScratchCap` are unchanged, and the fail-closed sentinel on a
missing key is unchanged. The symbol inventory was diffed function by function;
the one divergence is finding C. `ReplaceHostFold`'s ASCII fold is a strict
improvement — it closes a plaintext-host leak and a panic — and loses no case
the previous `strings.ToLower` form handled correctly, because any character
whose Unicode folding could create a new match also changes byte length, which
is the precondition that already corrupted the offsets. The boundary gate
(no application imports, no package-level mutable state, no `init()`) still
passes with the added method.

**Admin control plane and disclosure.** `apiDiagnostics` keeps its role gate;
no `requireRole` check, `uiRoutes` entry, audit call or `saveConfigVersion` call
changed anywhere in the window. The new `ui_tls_fallback_http` row reports the
*fact* of the plain-HTTP degradation and deliberately keeps the raw crypto error
on the viewer-gated network endpoint, matching the sibling rows' pattern. The
`apiDiagnostics` comment correction replaces a wrong reason ("unexported") with
the invariant that actually holds (the struct is never marshaled and carries no
JSON tags) and tells the next reader to keep reading it field by field — the
right remedy, since the field is in fact exported.

**CI and supply chain.** #1851 raises `timeout-minutes` 50 → 70 and
`go test -timeout` 40m → 60m on the Security Release Gate, with the measurements
behind both numbers recorded in the workflow. Nothing else moved: the race gate
still runs `go test -v -race -count=1 … ./...` with the same `TEST_SEED` and the
same ≥ 55% coverage threshold, the runner stays pinned to `ubuntu-24.04`, and a
grep across the window's `.github/**` diff shows no `permissions:`,
`egress-policy`, `secrets.`, `continue-on-error`, `if:` or `GOTOOLCHAIN` change.
Raising a budget makes a gate *more* likely to run to completion; the failure it
replaces turned into a refused Auto-Tag Release.

**Edge-case lab.** `_host_in_group` moves to membership so the oracle keeps
matching the product it is the differential oracle for, with the uncategorized
host still failing closed, and four new oracle checks cover exact, parent-suffix,
non-member and uncategorized shapes.

---

## Attack Scenarios

**S1 — authentication exemption widened by taxonomy overlap (finding A).**
*Preconditions:* a Stage-1 auth rule with `Outcome = Exempt` scoped to a
category group; an admin-created category whose pattern covers a parent suffix
of a host that a built-in category claims exactly. *Scenario:* before the
upgrade, `news.example.test` classified as the admin `webmail` category and the
`{News}`-scoped Exempt rule did not match, so the request was challenged. After
it, membership matches and authentication is waived for that destination.
*Exploitability:* none directly — an attacker cannot create the overlap; it is
an admin's taxonomy. *Likelihood:* low but non-zero, and silent. *Impact:*
unauthenticated egress to destinations the policy intended to challenge, with no
log distinguishing it from an intended exemption (`authSource="exempt"` either
way). *Mitigation shipped:* the upgrade note now tells the operator to audit
exactly these rules, and the Policy Tester evaluates the same matcher.

**S2 — reclassifying the sidecar's 429 as a fault (finding B).**
*Preconditions:* a future change that treats the 429 branch as dead, acting on
the stale comment. *Scenario:* the sidecar saturates under load and refuses;
`scanOnce` falls through to `"sidecar returned HTTP %d"` → `remoteScanFail` →
fail OPEN. *Impact:* every node pointed at that sidecar forwards bodies
**unscanned** for the duration of the load, which is the precise failure
CHAOS-115 exists to prevent and the one an OOM used to cause. *Mitigation
shipped:* the comment now names the consequence at the branch.

**S3 — inducing the fail-closed refusal (residual R1, not a finding).**
*Preconditions:* network reach to the sidecar's `/scan` port, which is
unauthenticated. *Scenario:* occupy every admission slot with callers that
declare a `Content-Length` and stall; arriving requests are refused with 429 and
callers **block** traffic. *Comparison with `d11ed3a`:* the same reach
previously bought an OOM and therefore a fail-OPEN **bypass** — strictly worse
for confidentiality — so this is the correct direction, but the denial is now
cheaper to induce (slots, not gigabytes). Containment is a deployment property:
bind the sidecar to a trusted network.

---

## Suggested Fix

All three findings are fixed in this change.

**A** — `CHANGELOG.md`: the category-group **Behaviour change** note now names
the Stage-1 auth `Exempt` widening, states the asymmetry with
`CredentialRequired`, and points at the rule surfaces and the Policy Tester. No
code change; the matcher is correct and the behaviour is already gated.

**B** — `internal/secscan/remote.go`: the 429 branch's comment now states that
the branch is live, that 429 and 413 are the only non-fault statuses, and that
reclassifying it converts a fail-CLOSED refusal into a fleet-wide fail-open.
`scan_svc_admission.go`'s quotation of the old sentence is corrected to record
that this file falsified it.

**C** — `internal/pseudonym/pseudonym.go`: add `(*Pseudonymizer).MintID()`, the
id-only mint, and record in `mintID` that its counter fallback is dead code on
the pinned toolchain and why it is kept. `traffic_redaction.go`:
`mintTrafficKeyID` routes through `MintID`, so it no longer mints a key it
discards and no longer has a leg that would publish the keyless-looking empty
id.

**Safe implementation.** No posture, default, validation, dependency or
security-setting change. `MintID` is additive and touches no key state — pinned
by a gate that checks the installed key, the installed id and the derived token
across the call.

---

## Files

Reviewed (window diff, 45 files). Behavioural surfaces:

- `categorygroup.go`, `internal/catgroup/catgroup.go`, `policy.go` — the
  membership fix and its matchers.
- `policy_hostcat.go`, `saas_feed_view.go`, `internal/urlcat/urlcat.go` — read
  (unchanged in-window) to settle the uncategorized guard's soundness.
- `scan_svc_admission.go`, `scan_svc.go`, `internal/secscan/remote.go`,
  `metrics.go`, `scanning_startup.go`, `scanning_startup_config.go`,
  `security_scan.go`, `main.go` — CHAOS-115 and its startup ordering.
- `traffic_redaction.go`, `internal/pseudonym/{pseudonym,doc}.go` — the
  extraction and the fold fix.
- `proxy.go`, `proxy_tunnel.go` — comment-only / constant-naming.
- `diagnostics.go`, `diagnostics_ui_tls_cert.go` — disclosure surfaces.
- `.github/workflows/security-release-gate.yml` — gate budget.
- `auth_saml_simplesamlphp_integration_test.go`, `internal/ssrf/ssrf.go` — the
  SSRF test seam and its callers.
- `edge-case-lab/harness/lab/oracle.py`, `edge-case-lab/harness/test_harness.py`
  — the differential oracle.

Changed by this review:

- `CHANGELOG.md` — finding A.
- `internal/secscan/remote.go`, `scan_svc_admission.go` — finding B.
- `internal/pseudonym/pseudonym.go`, `traffic_redaction.go` — finding C.
- `internal/pseudonym/mintid_test.go` — new gates for C.
- `docs/engineering/SECURITY-REGRESSION-REVIEW-2026-11-10.md` — this review.

---

## Required Tests

**Shipped by the window and run at this SHA** (all pass):

- `TestCategoryGroupMembership_{ArmedAdminSuffixDoesNotHideBuiltInMember,
  ArmedAccessEvaluateBlocks, ArmedCDRAndAuthAgree, ControlNonMembersDoNotMatch,
  UnarmedPathUnchanged, EqualsOrOfSingleCategoryMembership,
  UncategorizedGuardIsSound}` — positive, negative, differential-oracle and
  soundness coverage across access, CDR and Stage-1 auth, armed and unarmed.
- `TestMatchesMember_{NonWinnerMembershipMatches, WinnerFastPathSkipsProbe,
  NonMembersAndFailClosed, AgreesWithWinnerOnlyFormWhenProbeIsSilent,
  AllocationContract}`.
- `TestChaos115_*`, `TestChaos_SidecarCapacityRefusalFailsClosed`,
  `TestBenchGate_*` — concurrency, capacity refusal, caller-side fail-closed
  classification and the heap ceiling.
- `TestInspectLoopReadBuf_TrailerWindowIsLoadBearing`,
  `TestInspectLoopReaders_UseTheConfiguredSize`.
- `TestReplaceHostFold_LengthChangingPrefixStillRedacts` — malformed-input and
  panic coverage for the fold fix (U+023A, invalid UTF-8, repeated expanders).
- `TestPseudonymBoundary_*`, `TestPolicyDecisionLine_*`.

**Added by this review** (`internal/pseudonym/mintid_test.go`, pass under
`-race`):

- `TestMintID_ReturnsAUsableID` — positive and boundary: non-empty, 16
  characters, lowercase hex only. The empty id is the keyless sentinel, so
  "non-empty" is the security assertion.
- `TestMintID_DoesNotTouchKeyState` — negative control on a **keyed**
  pseudonymizer: the installed key, the installed id and the derived token are
  all unchanged across the call, which is what "mints an id and nothing else"
  means.
- `TestMintID_IndependentOfKeyMaterial` — two instances holding the same key
  must not mint the same id (nothing derivable from the key leaves the node).
- `TestMintID_ConcurrentIDsAreUniqueAndNonEmpty` — concurrency: 64 parallel
  mints, all non-empty and distinct; also the race gate for the lock-free id
  path.

**Not tested, and why.** The entropy-failure fallback is deliberately not
covered: on the pinned toolchain `crypto/rand.Read` never returns an error and
terminates the process instead, so swapping `crypto/rand.Reader` kills the test
binary rather than exercising the branch. The test file records that, and
`mintID`'s comment records the dead branch, instead of a gate that would only
appear to cover it.

**Verification run.** `go build ./...` clean; `go vet` clean on the changed
packages; `go test -race ./internal/pseudonym ./internal/secscan` pass;
`go test ./internal/catgroup`; and a root-package `-run` pass over this
window's gates — the `TestCategoryGroupMembership`, `TestChaos115`,
`TestChaos_SidecarCapacity`, `TestInspectLoop`,
`TestBenchGate_InspectReadBuf`, `TestBenchGate_PolicyEvalCategoryGroupAllocs`,
`TestPolicyDecisionLine`, `TestNormHoist`, `TestDiagnosticsUITLS`, `Pseudonym`
and `Redact` families — passes.

Lint was run the way the gate runs it, with the gate's own pinned version rather
than the container's: `GOTOOLCHAIN=go1.27.3 go install
github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0`, then
`golangci-lint run --timeout=10m --new-from-rev origin/main`. It reported one
issue — `gocritic stringXbytes` on the new test's key comparison — which is
fixed, and re-ran clean (0 issues). The full-tree complexity comparison the
conventions ask for is not informative here: `cyclop`, `funlen` and `gocognit`
attribute to a function's declaration line, and no function body changed in this
review except `mintTrafficKeyID`, which went from three statements to one.

These are focused checks, **not** the full module or aggregate CI result for
this SHA. **A passing local check is not a passing hosted review or merge gate**
— the PR's own gates remain authoritative.

---

## Residual Risk

**R1 — the sidecar's `/scan` is unauthenticated, and the new refusal is cheap to
induce.** Pre-existing and unchanged by this window; CHAOS-115 changes what
saturation *costs*. Anyone with network reach to the port can occupy every
admission slot with stalled callers and make every node pointed at that sidecar
**block** traffic (fail-closed), where the same reach previously bought an OOM
and therefore an unscanned **bypass**. The direction is right and the trade is
the intended one, but the precondition is a deployment property, not a code one:
the sidecar must be bound to a trusted network. A parked waiter costs a
goroutine and a connection it already had, and no buffer, so the amplification
is far smaller than the heap it replaces — but it is not zero, and the sidecar
listener has no admission bound of its own in front of the gate.

**R2 — scanning still fails open when the sidecar is unreachable or erroring.**
Unchanged (WK-2b). CHAOS-115 closes the *capacity* leg fail-closed and CHAOS-114
improved detection of a flapping listener, but a sidecar that is down or
returning 5xx still causes every caller to forward bodies **unscanned**, and
there is no operator-selectable fail-closed for *sidecar-unavailable* — unlike
YARA timeout and saturation, which do offer `fail_closed`. An operator who
believes the two are configured alike will be wrong. Carried forward from the
2026-11-09 review unchanged.

**R3 — `ssrf.AllowLoopbackForTest` is production-compiled with no static caller
gate.** It is exported, lives in a non-`_test.go` file, and swaps the process-
wide guard table. Every one of its 34 call sites is currently in a test file, and
`TestSSRFGuard_NoTestExemptionActive` asserts that loopback, RFC-1918 and
`169.254.169.254` are refused — but that gate proves *runtime state at the moment
it runs*, not the *absence of a production caller*: the root test binary never
executes `main()`, and tests calling the seam run in the same binary, so the
assertion also depends on ordering and on every caller's cleanup. This window
added a root-package caller (behind an environment-variable skip), which raises
the copy-paste surface. The durable fix is a static gate — an AST or `grep` check
that no non-`_test.go` file in the module references the symbol — of the kind the
tree already uses elsewhere. Not introduced here; worth its own change.

**R4 — the admission gate is sized once per sidecar start, and its floor makes
the byte budget advisory on a wide window.** Documented in
`scan_svc_admission.go` and correct as far as it goes: the slot count is derived
from the window configured at `NewScanService`, which this review confirmed is
the operator's final value on the startup path. Two edges remain. A window
changed after construction does not retune the gate (recorded, not fixed). And
`scanSvcMinSlots = 2` means a window above ~128 MiB yields a real ceiling above
the stated 256 MiB budget — 1 GiB at a 512 MiB window — which the constant's own
comment calls advisory and the `/health` and `/metrics` surfaces now expose, so
it is visible rather than silent.

**R5 — entropy-failure error paths across the tree cannot fire.** Since Go 1.24
`crypto/rand.Read` never returns an error; it terminates the process. Every
`if _, err := rand.Read(…); err != nil` in the tree is therefore dead, including
the three in `internal/pseudonym` and `mintID`'s counter fallback. The posture
this produces is the right one — a gateway with no entropy must not keep
deriving tokens, keys or session identifiers — so the recommendation is not to
remove the branches but to stop *reasoning* from them: a comment promising
graceful degradation on entropy failure is promising something the runtime will
not do, and finding C is the first case where a caller's shape depended on that
promise. This is the 2026-11-09 review's R4 recurring in a new place:
comment-stated security properties are not mechanically checked.
