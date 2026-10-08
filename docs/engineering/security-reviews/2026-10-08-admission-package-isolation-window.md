# Security regression review — admission/shutdown package isolation (SEC-ADMISSION-OWNER-1)

- Reviewer role: Security Regression Engineer (regression prevention only).
- Window reviewed: `1f7f42c..3fcc07e` — PRs #1522, #1523, #1524, #1525.
- Design authority: ADR-0037 (shutdown registry), ADR-0038 (instance-owned
  admission state), ADR-0039 (admission engine package).
- Verdict: **no security regression found in the extraction itself.** One
  newly reachable silent-degradation mode was found and closed with a
  structural wall. Three residuals recorded, all pre-existing.

## 1. Executive summary

This window moved two security-critical subsystems out of `package main`:

- `internal/shutdown` — the ordered hook registry whose FLUSH reserve is what
  guarantees the audit log, request log and process log are flushed before
  exit (CHAOS-56). A regression here is audit loss (CWE-778).
- `internal/admission` — IPFilter (allow/deny), RateLimiter (DoS control),
  shared CIDR matching, and the distributed remote-count/freshness state
  (CHAOS-61). These are the proxy's front door, evaluated on 100% of traffic
  ahead of authentication.

Both moves are faithful. The enforcement algorithms, the CHAOS-61 freshness
arithmetic, the fail-closed postures and every production call site are
unchanged, and the extraction *strengthened* encapsulation: the remote-count
store and `FreshCount` are no longer reachable outside the engine, so
CHAOS-61's "there is deliberately no unconditional `Get`" invariant is now
enforced by the package boundary instead of by convention.

The one real finding is a consequence of instance ownership rather than of any
changed line: the limiter the request path enforces with and the limiter the
gossip loop feeds are now two objects that must be the same object, and nothing
structural held them together.

## 2. Finding SEC-ADMISSION-OWNER-1 — a split admission owner degrades fleet-wide rate limiting to per-node, silently

- Severity: **Medium regression risk; not an exploitable finding today.**
- Status: production wiring is correct at this commit; closed by a structural wall.
- CWE-770 (throttling not enforced as designed) as the impact; CWE-778
  (insufficient logging/monitoring) for the absent signal.
- OWASP A04:2021 (Insecure Design — missing invariant enforcement) and
  A09:2021 (Security Logging and Monitoring Failures).

### What changed

Before ADR-0038, the distributed admission state lived in process globals
(`clusterCounts`, `clusterRateLimitEnabled`), so the request path and the
gossip loop could not disagree about which state they used — there was only
one. ADR-0038 moved that state onto each `RateLimiter`, and ADR-0039 made the
constructors exported. `DataPlaneClient.Run` now passes the limiter explicitly:

```go
go c.rateLimitGossipLoop(ctx, 5*time.Second, rl)   // controlplane_client.go
```

`rl` is the same handle `proxy.go:1486` and `socks5.go:436` enforce with, so
the wiring is correct. But the correctness is now positional, not structural.

### Attack scenario and preconditions

No attacker action is needed to *create* the condition — it is a composition
error, and the attacker merely benefits from it:

1. A future change passes any other limiter to `rateLimitGossipLoop` — a fresh
   `newRateLimiter()`, a second limiter composed for a test adapter, a client
   field. Exported constructors and instance ownership make this easy and
   natural to write.
2. The enforcing limiter's `ClusterEnabled()` is then never set, so
   `AllowAuto` dispatches to local-only `Allow` and never consults a remote
   count.
3. A client distributes requests across an N-node fleet and consumes the full
   per-node limit on **every** node — N× its intended fleet-wide budget —
   which is exactly the degradation CHAOS-61 was written to surface.

The same scenario is reachable from a one-word edit on the enforcing side
(`rl.AllowAuto` → `rl.Allow`), which local rate-limit tests cannot detect
because local limiting keeps working.

### Why nothing detects it (measured, not reasoned)

Run against the real engine, with the fleet's whole budget already spent
remotely:

```
enforcing limiter: Armed=false Stale=false Applied=false Episodes=0
10th request admitted despite 10 remote counts fleet-wide: true
transition observed by the loop: 0 (Unchanged)
```

Every operator surface reports health, and this is CHAOS-61 behaving
*correctly*: an un-armed node is deliberately never "stale", because there is
no enforcement for an expired broadcast to degrade — the alternative pins every
standalone proxy at "degraded", which is the defect Codex found on PR #1346.
Because `/metrics` gates the whole family on `Armed`,
`culvert_cluster_ratelimit_remote_stale`, the broadcast age, the episode
counter and the transition log line are **absent rather than alarming**, and
`/api/cluster/rate-limits` reports `enabled: false` — indistinguishable from a
standalone node.

So detection is the wrong control here: making a split owner observable would
require re-opening the un-armed-is-never-stale rule. The right control is
structural, which is what the existing test suite was missing.

### Why the existing suite does not cover it

`TestDistributedAdmission_ProductionWiring` is a thorough end-to-end test, but
it calls `c.rateLimitGossipLoop(ctx, time.Millisecond, r)` **directly** with
its own limiter. It therefore cannot observe what `DataPlaneClient.Run` passes,
and stays green if `Run` starts feeding a different owner. No test in the tree
exercises `Run`'s limiter argument.

### Fix — a structural wall, no behaviour change

`admission_owner_wall_test.go` (test-only):

- `TestAdmissionOwner_Wall_GossipLoopIsFedTheEnforcingLimiter` AST-parses
  `controlplane_client.go` and requires `DataPlaneClient.Run` to start the
  gossip loop on the identifier `rl`.
- `TestAdmissionOwner_Wall_RequestPathUsesClusterAwareEntryPoint` requires
  every `rl.Allow*` call in `proxy.go` and `socks5.go` to be `AllowAuto`
  (`Allow` is local-only; `AllowClusterAware` bypasses the enable check).
- `TestAdmissionOwner_SplitOwnerDegradesSilently` pins the invisibility as a
  **documented residual**, so the reason the wall exists is recorded. If a
  future change ever makes a split owner observable, that assertion is the one
  to invert — deliberately, not by accident.

Both walls assert the mechanism and carry their own CONTROLS — the same
predicate run against the broken shapes they exist to reject (fresh limiter,
other identifier, client field; local-only and enable-bypassing calls) — so a
selector that matches nothing cannot pass forever. This follows the
`sanitizeLog` scan-count and CHAOS-70 rate-gate precedent, and the walls are
deterministic on any hardware, at any load, with or without `-race`.

### Mutation proof (each verified failing)

| Mutation | Gate | Result |
|---|---|---|
| `Run` passes `newRateLimiter()` | GossipLoopIsFedTheEnforcingLimiter | FAIL (as required) |
| `proxy.go` uses `rl.Allow` | RequestPathUsesClusterAwareEntryPoint | FAIL (as required) |
| `socks5.go` uses `rl.Allow` | RequestPathUsesClusterAwareEntryPoint | FAIL (as required) |

## 3. Reviewed and found safe

**Engine equivalence.** Function-level body diff of the 1,248-line former
`security.go` against `internal/admission/engine.go`: 43 functions in common,
**38 byte-identical** modulo comments. The 5 that differ are mechanical and
were each read in full:

| Function | Change | Assessment |
|---|---|---|
| `AllowAuto` | `clusterRateLimitEnabled.Load()` → `r.ClusterEnabled()` | global → instance owner, same predicate |
| `AllowClusterAware` | `clusterCounts.FreshCount` → `r.remoteCounts.FreshCount` | same accessor, maxAge still derived from the live window |
| `publishView` | `ipFilterPublishHook` → `f.publishHook` | per-filter observer slot |
| `ExportHotDeltas` | `RateLimitDelta` → `HotCount`, `hotThresholdPct` → `HotThresholdPercent` | DTO/constant rename; threshold arithmetic unchanged |
| `buildPrefixSet` | `prefixFromIPNet` → `PrefixFromIPNet` | export only |

**CHAOS-61 invariants, all preserved:** `FreshCount` is still the only read
accessor and is now unexported; a negative age is STALE (fail toward the local
decision); `MaxAge` is derived from `r.Window()`, never a second constant;
freshness is evaluated per read, never latched; `Armed` requires **both**
`ClusterEnabled()` and `Enabled()`; metrics emit only when `Armed`
(`metrics.go:1270`).

**IPFilter view-republish contract:** every mutator (`SetMode`, `Add`,
`AddAll`, `Remove`, `ClearAll`) publishes under the writer lock. Fail-closed
mode semantics intact — any mode other than `allow`/`block`/`""` denies all
traffic, and the rationale against coercing to `"block"` survives verbatim.

**Enforcement wiring is byte-identical to baseline**, same files and same line
numbers, including gate order (connlimit → IP filter → rate limit → auth →
policy) and the 5-minute `rl.Cleanup()` loop that bounds limiter memory:

```
proxy.go:1477  ipf.Allowed      socks5.go:430  ipf.Allowed
proxy.go:1486  rl.AllowAuto     socks5.go:436  rl.AllowAuto
```

**Bulk-load primitives retained.** The CP→DP snapshot path uses `newIPFilter()`
(so the writer map is initialised) and `AddAll`, preserving the linear bulk
load; publishing per entry is O(N²) against a `maxSnapIPList` cap of 2,000,000.

**Shared CIDR converter — one implementation.** `PrefixFromIPNet` has a single
body; `policy.go` consumes it through the root alias. The 4-in-6 family
normalisation that mirrors `net.networkNumberAndMask` (whose naive reading
fails *open* for a blocklist) is not duplicated.

**Rate-limit exemptions.** `IsExempt` keeps raw-string single-IP keying; the
deliberate non-canonicalisation (canonicalising would *widen* an exemption into
a rate-limit bypass) is unchanged, and
`TestRLExemptView_MappedProbeStaysNonExempt` moved with it.

**Shutdown envelope.** `hookBudget` and `RunAll` are algorithmically identical:
phase horizon `phaseEnd + grace`, recursive reserve `behind × minSlice`, slack
clamped to `slice/2`. The former `var` constants became injected `Options`
whose defaults equal them exactly (`DefaultGrace` 3s, `DefaultMinSlice` 1s);
production passes only a logger, so behaviour is unchanged — now with
*immutable* configuration. `PartitionAt` propagates options to both partitions,
so the FLUSH reserve protecting the audit closers is not lost at the split. The
cross-artifact `stop_grace_period` gate survives.

**API surface.** `IPFilter` and `RateLimiter` expose no mutable fields; ADR-0039's
"no mutable engine internals are exported for tests" holds.

**Safety net.** Across the whole window, **zero** test/benchmark/fuzz entries
disappeared (10,699 → 10,721); the ADR's "keep every existing test
name/assertion" commitment is met.

**CI gates follow the code.** Coverage floors added for
`internal/admission/engine.go` and `freshness.go` at 70% (matching
`security.go`'s); benchgate extended to `./internal/admission` in Fast, QA and
weekly; CodeQL and the Deep Gate security classifier both already match the new
home (`internal/**` and the shell `case` pattern `internal/*`, which matches
across `/`), and the new root shims `admission.go` / `cluster_ratelimit*.go`
were added to both. `TestAdmissionMigration_BenchgateSelectors` and
`TestAdmissionMigration_CoverageRejectsOmittedEngine` carry their own negative
controls and drive the real floor script.

**Frontend dependency bumps** (`ddd031c`) are all upgrades, no downgrades:
`brace-expansion` 5.0.9→5.0.12 and 2.1.4→2.1.7, `undici` 6.28.0→6.28.1 and
8.10.0→8.10.2.

**Config-surface registry.** `applySnapshotAdmission` was added to
`snapshotApplyFuncs`, which is required for DEBT-006 apply-parity to stay
complete — not a weakening of the wall.

## 4. Residual risk (all pre-existing; none introduced by this window)

1. **Constructor-dependent invariant on exported types.** Confirmed by probe:
   `(&admission.IPFilter{}).Add(...)` and `(&admission.RateLimiter{}).Allow(...)`
   both panic with `assignment to entry in nil map`. Production constructs both
   through `NewIPFilter`/`NewRateLimiter` everywhere (verified across the tree),
   so this is unreachable today, and ADR-0038 records it as a deliberately
   preserved limitation rather than adding lazy initialisation to the hot path.
   Extraction widened *who can write the misuse* (any module-internal package)
   without changing the behaviour. Hardening options, for a separate change:
   make the zero value safe, or make the types unusable without a constructor.
2. **`ipf` is swapped unsynchronised.** `controlplane_snapshot.go:873` assigns
   the package-level `ipf` pointer, which request goroutines read at
   `proxy.go:1477` and `socks5.go:430` with no synchronisation. Identical at
   baseline (`1f7f42c:controlplane_snapshot.go:875`); the engine's own internal
   state is atomic, it is the handle swap that is not. Out of scope here —
   closing it means an `atomic.Pointer` handle, a behavioural change to the
   composition root.
3. **`ExportHotDeltas` is misnamed**, exporting absolute in-window counts rather
   than deltas. ADR-0038 records this as a documentation defect deliberately
   left alone, because changing it would change cluster accounting. The new
   `HotCount` type name and the `cluster_ratelimit_wire.go` comment make the
   wire meaning explicit, which improves matters without touching behaviour.

## 5. Files

- `admission_owner_wall_test.go` — new, test-only: two structural walls with
  controls, plus the documented-residual behavioural test.
- `policy.go` — comment-only: two references to `prefixFromIPNet` /
  `ipFilterView.contains` in `security.go` repointed to their new home; a stale
  pointer in a security-relevant comment sends the next reviewer to the wrong
  file.
- `internal/admission/security_ratelimit_benchgate_test.go`,
  `internal/admission/security_ratelimit_window_bench_test.go` — comment-only:
  `clientBucket in security.go` → `engine.go`.
- `docs/engineering/security-reviews/2026-10-08-admission-package-isolation-window.md` — this review.

No production behaviour is changed by this review.

## 6. Verification

| Check | Result |
|---|---|
| `go build ./...`, `go vet` | pass |
| `go test -race -shuffle=on -count=2 ./internal/admission ./internal/shutdown` | pass |
| `go test -count=1 .` (full root suite) | pass (375s) |
| `go test -count=1 -shuffle=on .` (determinism emulation) | pass (304s) |
| `go test -tags benchgate -run TestBenchGate_ . ./internal/admission` | pass |
| Mutation proofs (3) | each verified failing its gate |
