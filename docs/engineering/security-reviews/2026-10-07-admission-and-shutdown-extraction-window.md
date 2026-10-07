# Security regression review — admission + shutdown package-extraction window

**Date:** 2026-10-07
**Scope:** every change merged to `main` between `1f7f42c` (PR #1490, *oversize
admin usernames on the operator contract* — the commit the previous review
closed at) and `3fcc07e` (PR #1525, *refresh vulnerable frontend transitive
dependency locks*) — 14 commits, 71 files, +4 754 / −2 612.
**Branch:** `claude/epic-bardeen-p7maoj`
**Predecessor:** `2026-09-24-ci-evidence-and-reporter-window.md`
**Method:** the window is a refactor, so the governing question is not "what new
logic was added" but "is the relocated logic the SAME logic". Every
security-critical function was extracted from both trees and diffed body-for-body;
every security gate in the repository was inventoried by name before and after;
each surviving timing gate was mutation-verified by reinjecting the defect it
exists to catch and requiring it to fail.

---

## 1. Executive summary

This window contains no new security logic. It is four PRs of **package
isolation** (ADR-0037/0038/0039) plus one dependency bump:

| PR | Change | Security surface |
|----|--------|------------------|
| #1522 | `internal/shutdown` extracted from `runtime_shutdown.go` | audit/request-log flush durability (CHAOS-56) |
| #1523 | distributed admission state moved from package globals onto the limiter | cluster rate limiting (CHAOS-61) |
| #1524 | `internal/admission` extracted from `security.go` | IP filter + rate limiter — two per-request gates |
| #1525 | `brace-expansion`, `undici` lockfile refresh | build chain |

**No security regression was found.** The extraction is semantically exact on
every path that decides admission: of the 49 functions moved out of
`security.go`, **44 are byte-identical** and the remaining 5 differ only by an
identifier rename (`prefixFromIPNet`→`PrefixFromIPNet`, `hotThresholdPct`→
`HotThresholdPercent`, `RateLimitDelta`→`HotCount`) or by the
package-global→instance-field substitution that is the whole point of ADR-0038
(`clusterRateLimitEnabled.Load()`→`r.ClusterEnabled()`,
`clusterCounts.FreshCount`→`r.remoteCounts.FreshCount`). Every struct is
identical apart from the three new instance-owned fields. The CHAOS-61
freshness engine kept all four of its load-bearing invariants, including the
`Armed = ClusterEnabled() && Enabled()` both-halves rule that a prior review
round (PR #1346) had to fix once already.

One **latent robustness defect** was found and is closed here (§3). It is not a
vulnerability and was not reachable in production; it is a consequence of
ADR-0039 making two security-critical types *exported* and therefore
constructible without their constructors.

The window's net effect on posture is **neutral-to-positive**: the three
engines now carry import-boundary walls that forbid application dependencies,
package state and implicit initialization, which is a structural improvement
over the pre-extraction globals.

---

## 2. What was verified, and how

### 2.1 Semantic equivalence of the relocated gates

`security.go` (1 248 lines) was deleted; `internal/admission/engine.go` (1 193)
+ `freshness.go` (135) replace it. Each function was extracted from both trees
and diffed:

| Surface | Functions | Result |
|---|---|---|
| IP filter hot path | `Allowed`, `ipFilterView.contains`, `prefixSet.contains`, `buildPrefixSet`, `sortedPrefixLens`, `empty` | identical |
| IP filter family normalization | `PrefixFromIPNet` | identical (rename only) |
| IP filter mutators | `Add`, `AddAll`, `addLocked`, `Remove`, `ClearAll`, `SetMode`, `List`, `loadView`, `publishView` | identical (hook global→field) |
| Rate-limit window | `Allow`, `clientBucket.add/expire/grow`, `shard`, `Configure`, `Enabled`, `Cleanup` | identical |
| Exemptions | `IsExempt`, `AddExemption(s)`, `addExemptionLocked`, `RemoveExemption`, `ReplaceExemptions`, `ListExemptions`, `loadExemptView`, `publishExemptViewLocked` | identical |
| Cluster admission | `FreshCount`, `Apply`, `AppliedAt`, `Count`, `clusterRemoteCountMaxAge`, `AllowAuto`, `AllowClusterAware`, `ExportHotDeltas` | identical (global→instance) |

The properties that most needed confirming, because getting any of them wrong
is silent:

- **`IsExempt` still keys single-IP exemptions on the RAW string**, not a
  canonicalized `netip.Addr`. Canonicalizing both sides would make an
  IPv4-mapped probe *hit* a plain-v4 exemption and so **widen** an exemption
  into a rate-limit bypass. The deliberate non-canonicalization survived.
- **`PrefixFromIPNet` still mirrors `net.networkNumberAndMask`**, so
  `::ffff:10.0.0.0/104` behaves exactly like `10.0.0.0/8`. A naive
  "16 bytes means IPv6" reading fails **open** for a blocklist; the
  differential tests that catch it moved with the code.
- **`FreshCount` remains the ONLY read accessor** on `clusterCountStore`.
  There is still no unconditional `Get`, so the CHAOS-61 frozen-count path
  (a stale broadcast blackholing a client forever) cannot be reintroduced by a
  future caller. `Count()` returns the map *size*, not a per-IP count.
- **A negative broadcast age is still STALE, not fresh** — both in
  `FreshCount` and in `ClusterFreshness`, which is what keeps the two from
  giving different answers to one question.

### 2.2 Instance identity of the relocated cluster state

ADR-0038 moved `clusterRateLimitEnabled` and `clusterCounts` from package
globals onto the `RateLimiter`. That substitution introduces a failure mode the
globals could not have: if the gossip loop applies remote counts to a
*different* limiter than the request path consults, cluster-wide rate limiting
silently degrades to per-node (a client may use the full limit on every node)
while every surface still reports healthy.

Every consumer was traced to the `rl` singleton that `handleRequest` and
`handleSOCKS5` consult:

- `controlplane_client.go:212` — `go c.rateLimitGossipLoop(ctx, 5*time.Second, rl)`
- `metrics.go:1270` — `rl.ClusterFreshness()`
- `ui_cluster.go:385` — `limiter := rl`
- `cluster_ratelimit_freshness.go` — takes the limiter from its caller (the loop above)

No second instance exists in production; `admission.go` is the only construction
site. `controlplane_admission_ownership_test.go` (new, 184 lines) pins this.

### 2.3 Shutdown engine — the audit-durability reserve

The CHAOS-56 three-phase envelope is what guarantees the audit log, request log
and process-log sink are *flushed* rather than abandoned on SIGTERM; abandoning
a flush hook costs compliance evidence (CWE-778) or leaves a store the next
boot must quarantine. `RunAll`, `hookBudget`, `runHook` and `PartitionAt` are
all identical, and the ordering constants (`shutdownFlushBoundary = 105`, hooks
110–140) are untouched.

The material change is that `shutdownHookGrace` / `shutdownHookMinSlice` became
per-registry `Options`. **This was the window's sharpest risk**: a zero grace
and zero min-slice would collapse the flush reserve into the exact P1 defect
CHAOS-56 documents ("a ZERO-length window for flush hooks 4–6"). It is handled
correctly — `timing()` maps zero to `DefaultGrace`/`DefaultMinSlice`, negatives
panic at construction, and `PartitionAt` propagates the parent's options to
both sub-registries so drain and flush cannot disagree. `main` is the only
production construction site and wires `Logf` to `logger.Printf`, so the
abandonment diagnostic still reaches the log before the sink closes.

### 2.4 Gate inventory — nothing was dropped

The highest-value check for a refactor of this size: a security gate deleted
during a move leaves its invariant unpinned, and nothing fails.

Every `Test*`/`Fuzz*`/`Benchmark*` name in the repository was inventoried at
`1f7f42c` and at `HEAD`:

```
before: 10 699    after: 10 721
tests present before, absent after:  (none)
```

**Zero gates dropped repo-wide, +22 net new.**

### 2.5 Moved gates are not vacuous

Name preservation is not enough: a relocated structural wall can keep passing
while scanning a file that no longer holds the code.

- The **republish-contract walls** (`TestIPFilterView_EveryMutatorRepublishes`,
  `TestRLExemptView_EveryMutatorRepublishes`) are *runtime attribution* walls —
  they hook `publishView` and stack-walk to the nearest exported method — so a
  file move cannot make them vacuous. The hook moving from a package global to
  an instance field removed a cross-test recorder lookup and is a test-isolation
  improvement.
- The **completeness walls** (`*_MutatorInventoryIsComplete`) enumerate the
  type's exported methods by **reflection**, so they still fail when a new
  mutator is added unfiled, and the IPFilter one carries its own not-vacuous
  guard (`rt.NumMethod() < len(mutators)+len(readers)`).
- The two **timing gates** that PRs #1524/#1525 restabilized
  (`TestBenchGate_IPFilterBulkLoadIsLinear`,
  `TestBenchGate_RateLimitExemptBulkLoadIsLinear`) keep their sizes, measured
  operation and **8× bound** unchanged; only the sampling changed (paired sizes,
  alternating order, best-of-nine) to stop comparing different CI load phases.
  Verified rather than trusted: reinjecting the per-entry publish they exist to
  catch produced **22.93×** against the 8× bound.

  These gates matter because `AddAll`/`AddExemptions` are the bulk primitives
  behind the boot `admin_settings` restore, config import and the CP→DP
  snapshot apply, whose caps are 2 000 000 IP entries and 10 000 exemptions —
  a quadratic bulk load there is a boot-stall DoS, not a micro-optimization.
- The new **ADR-0039 boundary wall** sweeps every non-test file in the package
  (so a new file cannot escape), has a not-vacuous guard, and carries a control
  test proving it rejects all five regression shapes it claims to reject.

### 2.6 CP→DP snapshot apply and the config-surface registry

`applySnapshotAdmission` is a pure extraction: it is called as the first
statement of `applySnapshotTrafficExceptBlocklist`, so apply ordering is
unchanged, and `&IPFilter{single: …}` became `newIPFilter()`. The DEBT-006
apply-parity wall was correctly extended (`snapshotApplyFuncs`), which is
self-enforcing — omitting it fails the parity test.

### 2.7 Dependency bump

`brace-expansion` 5.0.9→5.0.12 (ReDoS) and `undici` 6.28.0→6.28.1 / 8.10.0→8.10.2.
All three move **forward**; no downgrade. Both lockfiles are build-chain only —
per the frontend contract, `node_modules` never ships and only the committed
`frontend/dist` is embedded.

### 2.8 Test evidence

```
go test -race ./internal/admission/... ./internal/shutdown/...          ok
go test -race -run 'RateLimit|IPFilter|Admission|Exempt|Chaos61|
                    ConfigSnapshot|ClusterRateLimit|Security' .          ok (71.6s)
go test -tags benchgate -run TestBenchGate_ ./internal/admission/        ok
  IPFilterBulkLoadIsLinear        4.57x (bound 8.0x)
  RateLimitExemptBulkLoadIsLinear 4.64x (bound 8.0x)
  IPFilterAllowedIsFlatInCIDRCount 1.09x (bound 4.0x)
  IsExemptIsFlatInCIDRCount        1.05x (bound 4.0x)
go test -run 'TestC1|TestC2|TestD0|TestConfigSurface|TestCSR|TestSnapshot|
              TestRoleMetadata|TestWall' .            ok (258 wall tests)
```

---

## 3. Finding — zero-value admission engines were constructible and unsafe

**Severity:** Low (robustness / availability hardening; not a bypass)
**CWE:** CWE-476 (NULL pointer dereference) → CWE-248 (uncaught exception)
**OWASP:** A04:2021 Insecure Design
**Regression risk introduced by:** ADR-0039 (PR #1524)
**Exploitability:** Not reachable from an external actor in the shipped binary.
**Status:** fixed in this PR.

### Attack scenario and preconditions

ADR-0039 made `IPFilter` and `RateLimiter` **exported** types in a reusable
package, so any caller in the module can build one as a composite literal. The
constructors are what initialize the maps the write paths assign into:
`NewIPFilter` sets `single`, `NewRateLimiter` sets `exemptIPs` and all 64 shard
`clients` maps. Nothing in the type system, and nothing in the ADR-0039
boundary wall, requires a caller to use them.

`Configure` is the sharp edge: it sets only the three atomics — limit, window,
enabled — and initializes no map. So a zero-value limiter is **one ordinary
call** from reporting `Enabled()` and reaching a write into a nil map:

```go
r := &RateLimiter{}           // all 64 shard maps nil
r.Configure(100, time.Minute) // enabled = true
r.Allow("198.51.100.7")       // s.clients[ip] = b → panic: assignment to entry in nil map
```

Reproduced; the panic is exactly as predicted. The IPFilter half is the same
shape via `addLocked` (`f.single[…] = true`).

### Impact

Honestly bounded, and it is **not** a bypass:

- On the **request paths** the panic is contained — `handleSOCKS5` opens with
  `defer recoverGoroutine("socks5")`, and `net/http` recovers per request — so
  it fails **closed**: the session is dropped, no traffic is admitted. The cost
  is the session plus a recorded crash where a rate-limit verdict belonged.
- The **IPFilter** half is worse in principle: `addLocked` is reached from
  `applySnapshotAdmission` on the DP config-apply path, and
  `controlplane_client.go` carries **no** panic guard, so a nil-map panic there
  would terminate the whole appliance — proxy, admin UI and health endpoints
  together — the outcome CHAOS-57 and CHAOS-66 exist to prevent.
- **Neither is reachable in the shipped binary**: `admission.go` is the only
  production construction site and uses both constructors. The risk is a future
  caller, or a test that leaks an uninitialized engine into the shared
  singleton. Two tests already assign a zero-value limiter to the production
  `rl` and then enable it (`controlplane_extra_test.go:378,419`); both restore
  it and neither calls `Allow`, so the shape exists in-tree today one call away
  from panicking.

### Why fix it rather than document it

`internal/shutdown.Registry`, extracted in the same window, deliberately made
its zero value work ("Its zero value also works with the default timing"), and
`internal/admission`'s own tests already treat a zero-value `RateLimiter` as a
legitimate shape when asserting pre-publish view behaviour. The zero value was
therefore *partially* safe — the exempt view handles nil correctly — but not
safe for admission. That inconsistency is the trap.

### Fix

One shared guarded helper, and one guard on the filter write:

- `rlShard.bucketFor(ip)` — both admission entry points (`Allow` and
  `AllowClusterAware`) now create buckets through a single helper. They
  previously duplicated the identical cold branch, which is the divergence class
  CHAOS-69 round 5 and SEC-SOCKS5-LOG-1 each had to close after the copies
  drifted; a guard added to one copy would have left the other panicking.
- `IPFilter.addLocked` — nil-guards `f.single`, off the request path entirely.

**Cost:** one nil compare on the cold branch, under a lock already held.
`go build -gcflags=-m` confirms `bucketFor` is **inlined at both call sites**
(engine.go:959, :1207), so the refactor is structurally zero-cost, and the
allocation benchgates still measure 0 allocs/op. Timing is below this box's
measurement resolution (±20 % run-to-run spread on `BenchmarkRateLimitAllow_*`),
so no timing claim is made — per the repo's own rule, the deterministic
evidence (inlining + allocation count) is quoted instead.

**Behaviour is unchanged for every properly constructed engine**, which is what
the controls below prove.

### Required tests — `internal/admission/zero_value_safety_test.go`

Each gate asserts the **admission verdict**, never merely the absence of a
panic: "did not panic" is satisfied by an engine that admits everything, which
would be a rate limiter that does not limit.

| Gate | Pins |
|---|---|
| `TestZeroValueRateLimiter_EnforcesLimitWithoutPanicking` | zero-value `Allow` enforces the limit (`true,true,false,false`) |
| `TestZeroValueRateLimiter_ClusterAwareEnforcesLimitWithoutPanicking` | the SECOND entry point — required, or a one-copy guard passes |
| `TestZeroValueIPFilter_EnforcesModeWithoutPanicking` | `Add` **and** `AddAll`, asserting both admit and refuse directions |
| `TestGuardedZeroValueMatchesConstructed` | **control**: zero-value and constructed limiters produce identical verdicts over a mixed workload, with an internal not-vacuous check that the workload actually reaches a refusal |
| `TestZeroValueIPFilterMatchesConstructed` | **control**: same for the filter, in block mode |

Mutation-verified, which is the point of the table:

- All five **FAIL** against the unguarded pre-fix shape (`panic: assignment to
  entry in nil map`), each verified individually — the first panic aborts the
  run, so a single combined run would have proved only one of them.
- The defect gate and the control both **FAIL** against a permissive mutation
  (`Allow` never refuses), so neither can be satisfied by an engine that stops
  limiting.
- The controls are what forbid the cheapest wrong fix in the other direction:
  changing what a *constructed* engine does.

---

## 4. Residual risk

1. **`RateLimiter`/`IPFilter` zero values are now safe for admission, but not
   by construction.** The guards are defence in depth; a future field added to
   either type with a nil-unsafe write path would need its own guard. Closing
   this structurally (an unexported marker requiring the constructor) was
   considered and rejected as disproportionate — it would break the in-tree
   tests that legitimately use the zero value, and the boundary wall already
   forbids the package-state shapes that matter most.
2. **`TestRLExemptView_MutatorInventoryIsComplete` classifies only methods
   whose NAME contains `Exempt`** (`containsExemptToken`). A future exempt-list
   mutator named otherwise escapes the completeness check. Pre-existing, not a
   regression from this window; the IPFilter wall has no such name filter.
3. **Two tests construct a zero-value limiter against the production `rl`
   singleton** (`controlplane_extra_test.go:378,419`) while the adjacent line
   correctly uses `newIPFilter()`. Both restore the global and neither calls
   `Allow`, and the guards added here make the shape safe, so this is left as a
   hygiene observation rather than widening the diff.
4. **Three stale `security.go` references** survive in comments and a failure
   message inside `internal/admission` (`security_ratelimit_benchgate_test.go:68`,
   `security_ratelimit_window_bench_test.go:11`) now that the file holds only
   the hostutil/SSRF wrappers. Cosmetic; it will misdirect whoever reads the
   next failure of that gate.
5. **`controlplane_client.go` carries no panic guard** on the DP loops, so any
   future panic on the config-apply path terminates the appliance. Out of scope
   here (the admission half is now guarded), but it is the same class CHAOS-57
   and CHAOS-66 closed for the listeners and is worth a register row.
6. The window's **test-only** surfaces (`docs/engineering/admission-test-migration.tsv`
   and the ADR set) were read for claims but are not enforcement.

---

## 5. Verdict

**No security regression.** The admission and shutdown extractions are
semantically exact on every path that decides authentication, authorization,
admission, or flush durability; no security gate was lost; the surviving timing
gates were proven non-vacuous by reinjecting their defects. The one finding is a
latent robustness hazard created by exporting two security-critical types, not
reachable in the shipped binary, failing closed where it was reachable at all,
and closed here with mutation-verified gates and controls.
