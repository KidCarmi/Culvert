# Security review — the admission engine extraction window (ADR-0037/0038/0039)

**Date:** 2026-10-09
**Reviewer role:** Security Regression Engineer (scheduled run)
**Scope reviewed:** `origin/main` at `3fcc07e`, review window `1f7f42c..3fcc07e`
(the package-isolation epic). Principally:

| Commit | Change |
|---|---|
| `0c7c950` | ADR-0039 — extract `IPFilter` + `RateLimiter` into `internal/admission` (48 files, +2,644/−1,920) |
| `fb2cf33` | ADR-0038 — move distributed admission state from package globals to per-limiter fields |
| `228be80` | split `applySnapshotAdmission` out of `applySnapshotTrafficExceptBlocklist` |
| `4df4397` | ADR-0037 — extract ordered shutdown execution into `internal/shutdown` |
| `ddd031c` | refresh vulnerable frontend transitive dependency locks |
| `6a83a2b`, `dac3dde` | stabilise relocated timing gates |

The branch `claude/epic-bardeen-4tfkby` is identical to `origin/main`
(0 ahead / 0 behind), so there was no pending diff; the reviewable surface is
what recently landed.

---

## 1. Executive summary

**No security regressions were found in this window.**

The window is dominated by a refactor of the two gates that run on *every*
proxied request on *every* protocol — the IP filter and the per-IP rate
limiter (`proxy.go:1477`, `socks5.go:430`). That is the highest-consequence
code in the product to move, so the review treated "this is a pure move" as a
claim to falsify rather than a premise. It held up: after normalising the
package header, the two singleton declarations and three renames, the moved
bodies are **line-for-line identical** to what they replaced. No validation was
loosened, no fail-closed branch inverted, no decision reordered.

The extraction also *improved* the security posture in one respect worth
recording: `internal/admission` exports **no mutable package-level state** and
**no exported struct fields** on `IPFilter`/`RateLimiter`, so package `main` can
no longer reach decision state except through the publishing mutators. The
"never mutate a published view in place" contract that previously rested on
convention is now enforced by the package boundary.

**One finding, and it is pre-existing rather than introduced here**
(§3, registered as **RISK-030**): `applySnapshotAdmission` publishes a freshly
built IP filter by **reassigning the package-global pointer**
(`controlplane_snapshot.go:873`, `ipf = newIPF`) while request goroutines read
that same global unsynchronised. On a weakly-ordered architecture the plain
pointer store can become visible before the release store that publishes the
filter's view, in which case `Allowed` reads `emptyIPFilterView`, resolves mode
`""` and **returns `true` for every address** — a transient IP-filter bypass on
both the HTTP and SOCKS5 data paths, recurring at every Control-Plane config
sync on every Data-Plane node. Culvert ships and qualifies arm64 images.

It is **not** fixed in this change, deliberately — see §4. The reviewed commits
only changed the spelling of that line (`&IPFilter{single: …}` → `newIPFilter()`);
the swap itself long predates them, and the fix belongs in its own measured
change with its own gate.

---

## 2. What was verified, and how

Evidence-first; every claim below is a command that was run, not a reading.

### 2.1 The move is semantically identical

Normalised both sides (strip comments/blank lines, collapse whitespace, apply
the three renames `prefixFromIPNet→PrefixFromIPNet`, `newRateLimiter→NewRateLimiter`,
`RateLimitDelta→HotCount`) and diffed the 1,194 deleted lines of `security.go`
against the 1,193 added lines of `internal/admission/engine.go`.

The **entire** residual diff is:

* `package admission` + its import block;
* `var ipf = &IPFilter{…}` → `func NewIPFilter()`, and `var rl = NewRateLimiter()`
  deleted — both singletons moved to `admission.go` in `main`;
* `hotThresholdPct` → `HotThresholdPercent` (export);
* the JSON wire tags and the `RateLimitGossip`/`RateLimitBroadcast` DTOs removed
  from the engine (moved to `cluster_ratelimit_wire.go`).

Nothing else. The function/type inventory maps 1:1 (62 before, 62 after).

### 2.2 The decision paths still fail the same way

Re-read rather than assumed, because these are the branches that decide admission:

* `IPFilter.Allowed` — `"allow"` → membership, `"block"` → negated membership,
  `""` → disabled, **`default` → deny all**. The fail-closed corrupt-mode branch
  and its rationale (coercing a corrupt mode to `"block"` would turn an
  allowlist deployment into a permissive blocklist) are intact.
* `AllowClusterAware` — `localCount + remoteCount >= limit` → deny, with the
  remote half consulted only through `FreshCount`. Unchanged.
* `FreshCount` — `applied == 0` → 0; `age < 0 || age >= maxAge` → 0. The
  CHAOS-61 rule that a **negative** age (clock rollback) is *stale*, not fresh,
  survived the move verbatim.

### 2.3 The CHAOS-61 freshness invariants survived

All four, in `internal/admission/freshness.go`:

1. `MaxAge: clusterRemoteCountMaxAge(r.Window())` — derived from the live
   limiter, not a second drifting constant.
2. `if st.Age < 0 { st.Stale = true }` — fails toward the local decision.
3. Freshness is **derived at read time**, never latched, so recovery needs no
   clearing path.
4. `Armed: r.ClusterEnabled() && r.Enabled()` — **both** halves, so an un-armed
   node is never reported stale (the PR #1346 defect did not return).

`FreshCount` remains the **only** per-IP read accessor; no unconditional `Get`
was reintroduced, so the frozen-count path cannot come back through a new caller.

### 2.4 Cluster gossip stayed wire-compatible

`HotCount` lost its JSON tags, which would silently degrade cluster-wide rate
limiting to a per-node limit if the field names moved. They did not:
`cluster_ratelimit_wire.go` re-declares `ip`, `count`, `node_id`, `deltas`,
`remote_counts` exactly, and `rateLimitWireDeltas` preserves `nil` as JSON
`null` rather than emitting `[]`.

### 2.5 Instance ownership is consistent (ADR-0038)

The risk in a global→instance conversion is a *split brain*: the gossip loop
configuring one limiter while the request path consults another. Every call site
resolves to the single `rl` in `admission.go`:
`rateLimitGossipLoop(ctx, 5*time.Second, rl)`, `rl.ClusterFreshness()` in
`metrics.go`, `limiter := rl` in `ui_cluster.go`. The only non-test construction
besides the two singletons is the snapshot path's `newIPFilter()` (§3).

The old `clusterCounts` global was initialised with a non-nil map; the new
`remoteCounts clusterCountStore` field is a zero value with a **nil** map. That
is safe and was checked rather than assumed: reads of a nil map return 0,
`Count()` returns 0, `FreshCount` short-circuits on `applied == 0`, and `Apply`
replaces the map wholesale.

### 2.6 `semAlwaysReplace` is safe on the delta path

`applySnapshotAdmission` applies `IPFilterMode`/`IPList` unconditionally while
`RateLimitExempt` immediately beneath carries a `!= nil` guard. The asymmetry is
**declared**, not an oversight — `config_surfaces.go` rows 211–236 mark the first
two `semAlwaysReplace` and the third `semNilSkipEmptyWipe`, and the registry
parity tests enforce the match.

Since the function is shared by the full *and* delta paths, an unconditional
replace would be a fail-open if the delta carried a sparse snapshot. It does
not: `controlplane_delta.go:327` builds the remainder as a full snapshot copy
with `snap.BlockedHosts = nil` only, so the admission fields are always fully
populated. No fail-open.

### 2.7 No test was lost in the migration

A package extraction that silently drops a defect gate is itself a regression,
and this commit deleted ~525 lines of root security tests. Compared the
**whole-repo** `Test*`/`Fuzz*`/`Benchmark*` inventory across the commit:

```
old total: 10713   new total: 10721
tests present before, absent after: (none)
```

Zero lost, net +8. The 21 CHAOS-61 gates, the republish-contract walls, the
differential tests against the pre-view implementations and the benchgates all
moved intact.

### 2.8 The new package boundary cannot be misused

* No exported package-level `var` — the main accidental-bypass vector is absent.
* `IPFilter` fields (`mu`, `mode`, `nets`, `single`, `view`, `publishHook`) and
  `RateLimiter` fields (`shards`, `limit`, `window`, `enabled`, `exemptMu`,
  `exemptNets`, `exemptIPs`, `exemptView`, `remoteCounts`, `clusterEnabled`,
  `clusterObservation`) are **all unexported**. `main` cannot mutate decision
  state without going through a mutator that publishes a view.
* `publishHook` moved from a test-only package global to an instance field with
  **no exported setter**, so it remains unreachable from `main` (one atomic load
  per publish, at admin rate).
* Exported surface is the operational API plus read-only DTOs
  (`InvalidIPEntry`, `HotCount`, `ClusterRateLimitStatus`, `FreshnessObservation`).
* `TestAdmissionBoundary_NoApplicationDependenciesOrSharedState` and
  `TestAdmissionBoundary_RejectsRegressions` wall the boundary.

### 2.9 Dependency locks moved forward

`ddd031c` upgrades only: `brace-expansion` 5.0.9→5.0.12 and 2.1.4→2.1.7 (ReDoS
class), `undici` 6.28.0→6.28.1 and 8.10.0→8.10.2. No downgrades, no `resolved`
host changes. These are frontend build-chain dependencies — `frontend/dist` is
what is embedded — so runtime exposure is nil and this is build hygiene.

### 2.10 Suites executed

| Command | Result |
|---|---|
| `go build -o … .` | clean |
| `go test -race -shuffle=on -count=2 ./internal/admission` (the ADR-0039 contract) | `ok 3.698s` |
| `go test -race -count=1 -run 'Admission\|IPFilter\|RateLimit\|Chaos61\|Chaos69\|ClusterRateLimit\|Exempt' .` | `ok 72.301s` |
| `go test -run 'TestC1\|TestC2\|TestC4\|TestD0\|TestWall\|TestRole\|Boundary\|FailClosed\|TestChaos70\|TestSecReqID1\|TestSecTOTP\|TestChaos63' .` | `ok 11.249s` |

---

## 3. Finding — RISK-030 (pre-existing): unsynchronised publication of the IP filter can transiently disable it

**Severity:** LOW (timing-bound, architecture-dependent) — but see *Impact*,
which escalates with deployment posture.
**Status:** OPEN. Reported, not fixed (§4).
**CWE:** CWE-362 (race condition) → CWE-636 (failure to handle exceptional
conditions / fail-open). **OWASP:** A01:2021 Broken Access Control.
**Not a regression from this window.**

### Mechanism

```go
// controlplane_snapshot.go:862
func applySnapshotAdmission(snap ConfigSnapshot) {
        newIPF := newIPFilter()
        newIPF.SetMode(snap.IPFilterMode)   // publishView() → view.Store(v)  [release]
        for _, bad := range newIPF.AddAll(snap.IPList) { … }  // publishView()
        ipf = newIPF                        // PLAIN pointer store, unsynchronised
        …
}
```

`ipf` is a plain package-global. It is written here, from the Control-Plane sync
goroutine, and read on the request path with no synchronisation:

* `proxy.go:1477` — `if !ipf.Allowed(clientIP) {`
* `socks5.go:430` — `if !ipf.Allowed(clientIP) {`

`IPFilter.loadView()` returns `&emptyIPFilterView` when `view` is nil, and
`emptyIPFilterView` has mode `""`, which `Allowed` resolves as *filter
disabled → allow*. That behaviour is intentional and pinned
(`TestIPFilterView_UnpublishedFilterAllowsAll`) — it is correct for a freshly
constructed filter and becomes a hazard only because a *partially visible*
filter is indistinguishable from an unpublished one.

`publishView`'s `f.view.Store(v)` is a **release** store: it stops prior writes
from sinking below it. It does **not** stop the subsequent plain store
`ipf = newIPF` from being hoisted above it. So on a weakly-ordered architecture
another core can observe the new `ipf` pointer while `newIPF.view` is still nil.

### Attack scenario

1. A DP node runs an IP allowlist (`IPFilterMode: "allow"`).
2. The CP pushes any config snapshot — routine, and operator-triggerable by any
   admin-plane config change.
3. `applySnapshotAdmission` stores the new `ipf` pointer.
4. On another core, a request lands inside the reordering window, loads the new
   pointer, loads a nil `view`, and is evaluated against `emptyIPFilterView`.
5. `Allowed` returns `true`. The address is admitted regardless of the allowlist.

### Preconditions

Weakly-ordered memory model (arm64 — Culvert builds, signs and QEMU-qualifies
arm64 images; see the `qualify-candidate` job); a DP node receiving CP
snapshots; a request arriving within the store-reordering window.

### Exploitability and likelihood

**LOW.** Not directly attacker-triggerable: an attacker cannot schedule the
window, only retry against it. The window is the reordering distance between two
adjacent stores — nanoseconds — but it recurs on every config sync on every DP
node, so over a fleet's lifetime the aggregate probability is not negligible. On
amd64 (TSO) store order is preserved and the defect is effectively unreachable,
which is also why CI cannot observe it (§4).

### Impact and affected assets

A **single-request bypass of one defense-in-depth layer**. Downstream controls
(authentication, default-deny policy, rate limiting, blocklist) still apply, so
this is not a full compromise — which is why it is rated LOW rather than MEDIUM.

**Impact escalates with posture:** in a deployment where the IP allowlist *is*
the primary control — `defaultAuthOutcome = Exempt` with an allowlist fronting
it, which RISK-021 notes is reachable on a fresh/unconfigured proxy — the
bypassed layer is the only layer, and impact becomes HIGH for the affected
request.

Assets: the proxy data path (HTTP + SOCKS5 ingress admission).

### Regression risk of the current state

The hazard is latent and will get *worse* under maintenance, which is the
stronger argument for closing it. `Allowed`'s correctness currently depends on
an undocumented coincidence — that every field a reader needs happens to be
published by an atomic store before the pointer is written. Any future change
that adds initialisation to `IPFilter` after `publishView` (a second view, a
cached predicate, a counter) widens the window silently, and no test will fail.

### Why only `ipf`

`rl` is never reassigned — the snapshot path mutates it in place via `Configure`
and `ReplaceExemptions`, both internally synchronised. Every other `ipf` mutator
(`admin_settings.go:426`, `ui_security.go:208-217`, `configversion.go:731`) also
mutates in place. `controlplane_snapshot.go:873` is the **only** pointer swap in
the tree, which is what makes this a narrow, specific fix rather than a pattern.

---

## 4. Recommended fix, and why it is not in this change

### Safe implementation — remove the pointer write, do not guard it

The obvious fix (make `ipf` an `atomic.Pointer[IPFilter]`) works but touches
~15 read sites including the two hottest lines in the product. The better fix
**mirrors a precedent already inside the same function**: `applySnapshotBlocklist`
deliberately stopped swapping its global (`bl = newBL`) in favour of in-place
`bl.ReplaceFeedEntries`, for an analogous reason.

Add one engine method:

```go
// ReplaceAll atomically replaces mode and the entry set, publishing exactly
// ONE view. Callers must not reassign a shared *IPFilter: the pointer store is
// unsynchronised against the request path, and a reader that observes a new
// pointer before the view it points to is published resolves mode "" and
// allows every address (RISK-030).
func (f *IPFilter) ReplaceAll(mode string, entries []string) []InvalidIPEntry
```

holding `mu` across the mode set, the entry rebuild and a single `publishView`.
`applySnapshotAdmission` then becomes `ipf.ReplaceAll(snap.IPFilterMode, snap.IPList)`
and never reassigns the global.

This is strictly preferable:

* It removes the race **entirely** — there is no pointer write left to order.
* **Zero hot-path change.** `Allowed` and its benchgates are untouched, so no
  re-measurement of the per-request gate is required.
* It preserves the `AddAll` bulk-load property (one pass, one publish) that
  exists because an `Add` loop is quadratic against the 2,000,000-entry
  `maxSnapIPList` cap.
* It closes the maintenance hazard above, since no caller holds a half-built
  filter.
* Both CP→DP paths (full and delta) share `applySnapshotAdmission`, so one edit
  covers both.

### Required tests

Deterministic, no race detector needed — which is the point:

1. **Structural wall** — AST-walk `controlplane_snapshot.go` and fail on any
   assignment to `ipf`. This is the repo's established pattern where behavioural
   coverage cannot reach the defect (`sanitizeLog` scan-count,
   `TestBenchGate_IsExemptTakesNoLock`, the `SaveUIUsersFile` wall), with a
   not-vacuous check so a selector typo cannot pass forever.
2. **Positive** — `ReplaceAll("allow", […])` yields exactly the allowlist
   verdicts; `ReplaceAll("block", […])` the negation.
3. **Negative / boundary** — invalid entries are returned, not silently
   dropped; an empty list under `"allow"` denies all; a corrupt mode still
   denies all (fail-closed preserved).
4. **Single-publish** — via the existing `publishHook`, assert `ReplaceAll`
   publishes **once** (pins the bulk-load property).
5. **No intermediate allow-all** — a `publishHook` observer asserts no
   published view during `ReplaceAll` ever has mode `""` while entries are
   configured, i.e. the old two-step `SetMode`+`AddAll` window is gone.
6. **Concurrency** — `-race`, concurrent `Allowed` readers against repeated
   `ReplaceAll` writers, asserting every observed verdict matches either the
   pre- or post-state and never allow-all.
7. **Snapshot integration** — a CP→DP apply (full *and* delta) leaves the
   filter enforcing the snapshot's mode and list.

### Why this run reports rather than patches

Three reasons, in order of weight:

1. **I cannot meet this repository's own evidentiary bar for the fix here.**
   The standing convention is that every defect gate is *verified failing
   against the pre-fix shape*. This defect is unobservable on amd64, which is
   what the CI runners and this container are, so no gate I could write would
   demonstrate the bug it claims to prevent. Shipping an unprovable change to
   the per-request admission gate is a worse trade than recording it precisely.
2. **It is pre-existing and outside the stated scope** of a regression sweep
   (`1f7f42c..3fcc07e` only re-spelled the line). The precedent for this is
   RISK-021 and RISK-022, both HIGH and recorded OPEN rather than patched.
3. **One concern per change.** The fix adds an engine method, re-points two
   snapshot paths and adds a structural wall; it deserves its own PR and its
   own review, not an unattended drive-by inside a review commit.

---

## 5. Residual risk

| Item | State |
|---|---|
| **RISK-030** — unsynchronised `ipf` publication can transiently disable the IP filter (§3) | OPEN, reported this run, fix + gates specified in §4 |
| `applySnapshotAdmission` discards DP-local admin-settings IP entries on every CP sync | **By design** — `semAlwaysReplace`, CP is authoritative. Verified consistent with `config_surfaces.go` and its parity tests. Not a finding. |
| RISK-021 — fresh/unconfigured proxy runs default-allow + no-auth | Unchanged by this window; it is the posture that escalates RISK-030's impact |
| Timing-ratio gates relocated into `internal/admission` (`6a83a2b`, `dac3dde`) | Re-stabilised by pairing samples under load. Timing gates remain flake-prone by nature; the repo's own preference for *structural* gates applies |

---

## 6. Conclusion

The admission extraction is a clean, behaviour-preserving move of the most
security-critical code in the product: identical logic, identical fail-closed
branches, zero lost tests, wire compatibility preserved, consistent instance
ownership, and a package boundary that now makes the "never mutate a published
view" contract structural rather than conventional. **No regression.**

The one real finding is older than the window and was surfaced by reading the
snapshot path that the refactor happened to touch: publishing a security gate by
reassigning a shared pointer is unsound, and the failure direction is open, not
closed. It is registered as RISK-030 with a fix that removes the race rather
than guarding it, and with gates that do not depend on reproducing a memory
reordering.
