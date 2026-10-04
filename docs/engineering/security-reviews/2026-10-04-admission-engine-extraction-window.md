# Security review — the admission-engine extraction (ADR-0039)

**Date:** 2026-10-04
**Reviewer role:** Security Regression Engineer (scheduled run)
**Scope reviewed:** `31a7562..3fcc07e` — 51 files, +2,779/−1,955. PRs #1524
(`refactor: extract instance-owned admission engine`, `refactor: separate
admission snapshot configuration`) and #1525 (`fix: refresh vulnerable frontend
transitive dependency locks`), plus the seven CI/gate configuration changes that
rode with them.

**Verdict: no security regression found.** Every allow/deny decision in the
moved code is byte-identical to its pre-move form, and the extraction *narrows*
one reachability surface rather than widening it (§4.1). Two observations are
recorded — one pre-existing hazard this change did not introduce and does not
worsen (§5.1), one test-strength reduction (§5.2). Neither is a vulnerability.

---

## 1. Executive summary

This window moves Culvert's two front-door admission gates — `IPFilter`
(allow/block by address and CIDR) and `RateLimiter` (per-IP sliding window,
exemptions, cluster-aware gossip, CHAOS-61 broadcast freshness) — out of
`security.go` and into `internal/admission`, behind an exported API. Both gates
sit ahead of authentication on every proxied request (`proxy.go:1477`,
`socks5.go:430`), so a behavioural drift here is an unauthenticated
authorization change. That makes this the highest-value regression target in the
recent history, which is why it was reviewed in full rather than sampled.

It is a clean extraction. The substantive result is a **byte-equivalence proof**
(§3.1): after normalising the four renames, the diff between the old 1,244-line
`security.go` and the new 1,193-line `engine.go` contains **no hunk inside any
function that makes a security decision**. `Allowed`, `contains`,
`PrefixFromIPNet`, `IsExempt`, `Allow`, `AllowClusterAware`, `FreshCount`,
`expire`, `add` and `grow` are untouched. The only changes are the package
clause, the removal of the SSRF/host wrappers (which stayed behind in
`security.go`, verified byte-identical, §3.2), constructor extraction, the
wire-DTO split, one constant rename, and added doc comments.

The parts that were genuinely *restructured* rather than moved — the CHAOS-61
freshness plane, split into an engine verdict plus a main-side renderer — keep
every invariant that note was written to protect, including the two that cost a
Codex round each: `Armed` still requires **both** `ClusterEnabled() && Enabled()`,
and a negative broadcast age is still **stale**, not fresh (§3.3).

The CI follow-through is complete, which is the failure mode I expected to find
and did not. A moved security file routinely falls out of path-filtered SAST and
out of tagged gate selectors — the "muted gate" class this repository documents
repeatedly. Here, PR-time CodeQL already covered `internal/**`, the Deep Gate's
security classifier already matched `internal/*` (bash `case` globs match `/`),
all three benchgate workflows were extended to `./internal/admission`, the
race-shard classifier gained a case pinning that engine changes run the race
suite, and per-file coverage floors were added for both new files with
`security.go`'s own floor retained. The authors then **walled each of those four
plumbing risks with a test** (`admission_contract_test.go`, §4.3), so a future
change cannot silently mute them.

The dependency half is four forward patch bumps (`brace-expansion` 2.1.4→2.1.7
and 5.0.9→5.0.12, `undici` 6.28.0→6.28.1 and 8.10.0→8.10.2) with no package
added or removed and every `resolved` URL still on `registry.npmjs.org` (§6).

---

## 2. What was verified, and how

| Question | Method | Result |
|---|---|---|
| Did any allow/deny logic change? | Normalised textual diff, old `security.go` vs new `engine.go` | No hunk in any decision function |
| Did the SSRF / IDNA guards survive the file's demolition? | Symbol-by-symbol diff of the eight retained declarations | Byte-identical |
| Did the CHAOS-61 freshness invariants survive restructuring? | Line-by-line reading of both halves against the recorded invariants | All preserved |
| Did the CP→DP snapshot apply path change? | Caller graph of the split `applySnapshotAdmission` | One production caller; both upstream paths unchanged |
| Was any test lost? | Full-corpus test-symbol inventory, worktree at `31a7562` vs HEAD | 10,713 → 10,721; **zero lost** |
| Were the 17 CHAOS-61 gates preserved? | Gate-name set comparison | 17 preserved, 1 added |
| Did any structural wall go vacuous? | Audit of every source-scanning / reflection wall in the moved tests | None; new wall carries a not-vacuous check *and* a control |
| Did the exported API open an invariant bypass? | Full exported-surface enumeration (`go doc`) | No; one surface *narrowed* (§4.1) |
| Were timing gates loosened to pass? | Bound and fixture comparison on both bulk-load ratio gates | Bounds, sizes and measured operation unchanged |
| Did SAST / gate coverage follow the move? | Path filters, classifiers and tagged selectors in all seven workflows | Complete |
| Does it build, vet and pass under race + shuffle? | `go build ./...`, `go vet`, `go test -race -count=1 -shuffle=on`, benchgate tag | All green |

---

## 3. Equivalence evidence

### 3.1 The decision logic is byte-identical

Normalising the four renames (`newIPFilter`→`NewIPFilter`,
`newRateLimiter`→`NewRateLimiter`, `prefixFromIPNet`→`PrefixFromIPNet`,
`RateLimitDelta`→`HotCount`) reduces the 1,244→1,193-line rewrite to a 197-line
diff whose every hunk is one of: the package clause; removal of the
SSRF/hostutil wrapper block; `var ipf`/`var rl` becoming `NewIPFilter()`/
`NewRateLimiter()`; the three wire DTOs moving to `cluster_ratelimit_wire.go`;
`hotThresholdPct`→`HotThresholdPercent`; and eleven added or corrected doc
comments.

This matters more than a sampled differential test would: a byte-identical
function body cannot behave differently, so the normalisation result is a proof
rather than evidence. The functions it covers are exactly the ones a regression
would have to live in — the prefix-set membership probe and its
`PrefixFromIPNet` family normalisation (whose 4-in-6 handling is a documented
fail-open hazard for blocklist mode), the exempt-view probe with its
deliberately **non**-canonicalised single-IP keying (canonicalising it would
*widen* an exemption), and the ring-buffer sliding window with its
clamp-up ordering invariant.

### 3.2 `security.go` was reduced, not deleted

The diffstat reads `security.go | 1194 -`, which looks like a deletion. It is
not: the file retains the eight declarations that are not admission logic —
`normalizeHost`, `stripHostPort`, `normalizeHostStrict` (the RISK-013
fail-closed IDNA gate), `isPrivateIP`, `isPrivateHost`, `ssrfControl`,
`errSSRFBlocked`, `ssrfSafeDialContext`. All eight are byte-identical to their
pre-change form, which preserves the repository's CodeQL inline-guard
convention at every unqualified call site. Had these moved, the SSRF guard's
recognisability to `go/log-injection`-adjacent queries would have been at risk;
they did not.

### 3.3 The CHAOS-61 freshness plane

`noteClusterRateLimitFreshness` was split into `ObserveClusterFreshness()`
(engine: derives the verdict, owns the episode latch, returns a typed
transition) and a main-side renderer that logs it. The verdict function is
unchanged, and specifically retains the three properties that each cost a review
round to establish:

- `Armed: r.ClusterEnabled() && r.Enabled()` — **both** halves. The second was
  missed in the first version of this file and produced a permanent
  un-clearable degradation on the default posture (limit 0).
- `if st.Age < 0 { st.Stale = true }` — a clock rollback fails toward the local
  decision rather than honouring a broadcast for however far back the clock
  moved.
- `MaxAge: clusterRemoteCountMaxAge(r.Window())` — derived from the live
  limiter, never a second constant that could drift permissive.

Freshness remains **evaluated, not latched**, so a wedged gossip loop still
reports the truth. The two log messages are byte-identical to the originals, and
the episode count is re-read after the increment under the same lock, so the
recovery line still carries a current figure.

### 3.4 The snapshot apply path

`applySnapshotTrafficExceptBlocklist` had its admission section extracted into
`applySnapshotAdmission`, which it now calls first. `applySnapshotAdmission` has
exactly one production caller, and that function's two callers — the full
snapshot path (`controlplane_snapshot.go:839`) and the delta path
(`controlplane_delta.go:285`) — are unchanged. The `AddAll` bulk primitive is
retained, so the O(N²) boot-stall trap that `maxSnapIPList` (2,000,000) makes
reachable stays closed, and the `nil`→skip / `[]`→clear / populated→replace
semantics of `RateLimitExempt` are untouched. The CP→DP apply-parity wall was
extended to know the new function rather than relaxed.

### 3.5 A stale doc comment was corrected, and the correction is right

`ExportHotDeltas`' comment changed from "Counts are reset after export (delta,
not absolute)" to "does not reset counts". The body is unchanged, so one of the
two comments was wrong — and it was the old one. The body counts current
in-window bucket occupancy and resets nothing; the CP aggregator **replaces**
each node's map (`a.perNode[nodeID] = counts`) rather than accumulating, so
absolute in-window counts are exactly what it needs. Had the CP accumulated,
non-resetting export would have inflated cluster totals into spurious 429s.
It does not. The semantics are coherent end to end, ADR-0039 records them
explicitly, and the `Count` wire field carries a comment marking the name as
historical.

---

## 4. Where the extraction improved the posture

### 4.1 One invariant is now structural rather than conventional

CHAOS-61's recorded rule is that `FreshCount(ip, now, maxAge)` is the **only**
read accessor on `clusterCountStore` — "there is deliberately no unconditional
`Get`" — so that the frozen-count path cannot be reintroduced by a future
caller. In package `main` that was a convention held up by review. In
`internal/admission` the store and all four of its methods are unexported, so no
caller outside the engine can reach a raw, unexpired remote count at all. The
full exported surface (§2) carries no per-IP count getter; `RemoteIPCount()`
returns a map length, which cannot be used to bypass the expiry gate.

### 4.2 The new boundary wall is correctly constructed

`TestAdmissionBoundary_NoApplicationDependenciesOrSharedState` reads every
non-test `.go` file in the package directory (so it covers `freshness.go` and
any future file, not just `engine.go`), rejects any import outside the six
stdlib packages, any `init()`, and any package-level mutable state except the
two documented immutable empty views. It carries a **not-vacuous check**
(`if checked == 0 { t.Fatal }`) and a **control**
(`TestAdmissionBoundary_RejectsRegressions`) that feeds it five known-bad
sources and requires each to be rejected. This is the standard the repository
sets for structural walls, met.

### 4.3 The CI-plumbing risks are walled, not just fixed

`admission_contract_test.go` pins the four regression vectors a reviewer would
otherwise have to re-check by hand on every future change:
`BenchgateSelectors` (all three workflows must select **both** packages —
otherwise the moved gates are "a successful `go test` of the wrong package"),
`CoverageRejectsOmittedEngine` (drives the real floor script against real
statement locations), `DeepClassifier` (engine changes must classify as
security), and `TransitionLoggingUsesEngineObservation` (the main-side renderer
must consume the engine's transition rather than recompute freshness).

### 4.4 The timing gates were stabilised, not loosened

Both bulk-load linearity ratio gates changed sampling strategy (best-of-3 →
best-of-9 with alternating size order) because the package now runs alongside
the root suite and grouped samples compared different load phases — CI measured
10.81x for an unchanged *linear* implementation. The bound (8.0x), the sizes
(2,000/8,000), the GC settling and the measured operation are all retained. This
is the right direction: the repository's standing rule is that a gate which can
flake gets muted, so a flaky gate must be made robust rather than given a looser
bound.

---

## 5. Observations

### 5.1 O-1 — unsynchronised swap of the IP-filter handle (PRE-EXISTING, Low)

**Not a regression.** `ipf = newIPF` sat at `controlplane_snapshot.go:875`
before this change and sits at line 873 after it; the refactor moved the
surrounding function and changed nothing about the assignment.

`ipf` is a package-level `*IPFilter` read on the request path without
synchronisation (`ipf.Allowed(clientIP)` — `proxy.go:1477`, `socks5.go:430`) and
written by `applySnapshotAdmission`, which is reached from `fetchAndApply` on
the DP config-loop goroutine (`controlplane_client.go:221`/`227`) while the
proxy is serving. That is a data race on the handle to a security gate under the
Go memory model.

- **Exploitability:** none identified. An aligned pointer-word store is atomic
  in hardware on every architecture Culvert ships for, so a request observes
  either the previous filter or the new one, never a torn value — and observing
  the previous filter for a brief window is also what a correctly synchronised
  implementation would permit, since no ordering is promised between a snapshot
  apply and an in-flight request.
- **Why it still matters:** it is undefined behaviour per the spec, and it means
  the project's own `-race` CI cannot *prove* the snapshot-apply path race-free —
  any future test that exercises snapshot apply concurrently with request
  serving would report it. It is also inconsistent with how this codebase
  handles precisely this pattern elsewhere: `internal/threatfeed` and
  `internal/rewrite` publish read views through `atomic.Pointer`, and
  `IPFilter` itself publishes its *internal* view that way. The handle to the
  filter is the one link in that chain still using a plain assignment.
- **Recommended fix (deferred, not applied here):** hold `ipf` in an
  `atomic.Pointer[IPFilter]` with a `currentIPFilter()` accessor, mirroring
  `getUpstreamTransport()`. This is behaviour-preserving but touches ten call
  sites across six files; changing a security control's publication mechanism is
  not something a review should land unilaterally, and this review's mandate is
  to avoid altering security behaviour unless required.
- **Required tests if taken:** a `-race` gate exercising `applySnapshotAdmission`
  concurrently with `ipf.Allowed` (which fails today), plus a control that an
  allowlist swap is visible to a subsequent request.
- **CWE-362** (race condition) / OWASP **A04:2021**. Severity **Low**;
  regression risk of leaving it: unchanged from before this window.

### 5.2 O-2 — the gossip end-to-end assertion was narrowed (Informational)

`TestDistributedAdmission_ProductionWiring` previously asserted
`r.remoteCounts.FreshCount(ip, …) == 2` — proving both that the CP excluded the
reporting node's own six requests **and** that the DP applied the broadcast it
received. The assertion moved into the RPC hook and now checks the CP's wire
response (`broadcast.RemoteCounts[ip] == 2`), which is a legitimate and in one
respect stronger check. But the remaining DP-side wait,
`awaitAdmissionBroadcast`, only blocks until `ClusterFreshness().Applied` is
true. A defect that applied an *empty* map would still set `Applied` and still
pass.

The product behaviour is not uncovered — `ApplyRemoteCounts`→`FreshCount` is
pinned by `TestClusterCountStore_FreshCountApply` and
`TestAllowClusterAware_CombinesRemote` in `internal/admission`. What is no
longer covered is the wire→engine seam *in the production gossip loop*
specifically. The cheap repair is to have `awaitAdmissionBroadcast` wait on the
applied count rather than on `Applied` alone. No action taken; recorded so the
next change in this area knows the assertion is thinner than it reads.

---

## 6. Supply chain

Four transitive dependencies advanced; nothing else changed in either lock file.

| Package | From | To |
|---|---|---|
| `brace-expansion` | 2.1.4 | 2.1.7 |
| `brace-expansion` | 5.0.9 | 5.0.12 |
| `undici` | 6.28.0 | 6.28.1 |
| `undici` | 8.10.0 | 8.10.2 |

All four are forward patch bumps (no downgrade, which is the direction a
"vulnerability fix" commit can get wrong). The diff adds and removes **no**
`node_modules/` key, so no package entered or left the tree, and every
`resolved` URL in both lock files still points at `registry.npmjs.org` — no
substituted registry, no git or tarball source. These are devDependency /
build-tooling paths; `frontend/dist` is the only frontend artifact embedded in
the binary, and it is a committed deterministic build guarded by the
`frontend-verify.yml` porcelain-drift gate, so a tooling bump cannot reach the
shipped bundle without that gate observing the change.

---

## 7. CI and gate configuration

| Change | Assessment |
|---|---|
| `codeql.yml` +`admission.go`, +`cluster_ratelimit*.go` | Additive. `internal/**` was already present, so the engine was never outside PR-time SAST. |
| `pr-deep-gate.yml` security classifier, same two globs | Additive. `internal/*` already matched (bash `case` `*` spans `/`, as the inline comment notes). |
| `pr-fast-gate.yml`, `qa-gate.yml`, `proxy-weekly-stress.yml` benchgate | Extended to `./internal/admission` in all three — the moved structural gates still run. Walled by `TestAdmissionMigration_BenchgateSelectors`. |
| `coverage-floor.sh` | `internal/admission/engine.go` 70, `internal/admission/freshness.go` 70 added; `security.go` 70 retained. `freshness.go` previously had **no** floor, so this is net stronger. Walled by `qa_gate_coverage_test.go`. |
| `fast_gate_race_shards_test.go` | New case pinning that `internal/admission/**` classifies as `code`, so engine changes run the full race+coverage suite. |
| `frontend-verify.yml`, `pr-deep-gate.yml` failure annotations | New steps that echo tail-of-log into a GitHub annotation. Both escape `%`, `\r` and `\n` before interpolation, which is the correct and sufficient mitigation for workflow-command injection (a command must begin a line, and newlines are escaped). Heredocs are quoted (`<<'JS'`, `<<'PY'`), so log content never reaches the shell. Annotations have the same audience as the logs they quote — no new exposure. |

---

## 8. Residual risk

1. **O-1** stands, unchanged from before this window: the IP-filter handle swap
   is an unsynchronised write to a security-gate pointer, benign in practice on
   shipped architectures but not provable under `-race`.
2. **O-2** stands: the production gossip loop's wire→engine application seam is
   covered at unit level but no longer asserted end to end.
3. `security.go`'s 70% per-file coverage floor now applies to a five-function
   wrapper file, where the floor is an unweighted mean over few functions and is
   therefore coarse — a single uncovered wrapper moves it ~17 points. Not a
   security risk; a CI-brittleness note. All five wrappers have call sites
   throughout the tree and the gate passed on main.
4. This review re-examined the *moved* code against its pre-move form. It did
   not re-derive the correctness of the underlying algorithms, which were
   reviewed in their own windows (the `ipFilterView` publication contract, the
   ring-buffer window's clamp-up invariant, the `prefixSet` family
   normalisation, CHAOS-61). Byte-equivalence is what carries their conclusions
   forward.

---

## 9. Conclusion

No regression. The two gates that sit ahead of authentication on every proxied
request were relocated without a single change to any function that reaches a
verdict, the restructured freshness plane preserves every invariant two prior
review rounds established, the test corpus lost nothing, every structural wall
remains non-vacuous, and the CI follow-through covers the moved code in SAST,
the deep-gate classifier, all three benchgate workflows, the race-shard
classifier and the coverage floors — each of those four plumbing risks now
pinned by its own test. One reachability surface was narrowed: the cluster
remote-count store is unexported, so CHAOS-61's "no unconditional accessor"
rule is enforced by the compiler rather than by review.
