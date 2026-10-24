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
  (`Allow` is local-only; `AllowClusterAware` skips the cluster-enabled dispatch).
- `TestAdmissionOwner_SplitOwnerDegradesSilently` pins the invisibility as a
  **documented residual**, so the reason the wall exists is recorded. If a
  future change ever makes a split owner observable, that assertion is the one
  to invert — deliberately, not by accident.

Both walls assert the mechanism and carry their own CONTROLS — the same
predicate run against the broken shapes they exist to reject (fresh limiter,
other identifier, client field; local-only and dispatch-bypassing calls) — so a
selector that matches nothing cannot pass forever. This follows the
`sanitizeLog` scan-count and CHAOS-70 rate-gate precedent, and the walls are
deterministic on any hardware, at any load, with or without `-race`.

### Mutation proof (each verified failing)

Re-verified against the wall as it now stands (all five run on the real files,
tree restored after each):

| Mutation | Gate | Result |
|---|---|---|
| `Run` passes `newRateLimiter()` | GossipLoopIsFedTheEnforcingLimiter | FAIL (as required) |
| `Run` shadows `rl := newRateLimiter()` | GossipLoopIsFedTheEnforcingLimiter | FAIL — **green before round 1** |
| `rateLimitGossipLoop` reassigns its `limiter` | GossipLoopIsFedTheEnforcingLimiter | FAIL — **green before round 2** |
| `proxy.go` shadows `rl := newRateLimiter()` | RequestPathUsesClusterAwareEntryPoint | FAIL — **green before round 1** |
| `socks5.go` uses `rl.Allow` | RequestPathUsesClusterAwareEntryPoint | FAIL (as required) |
| a helper reassigns `rl = newRateLimiter()` | TestRISK030_Wall_NoProductionReassignmentOfAdmissionHandles (main) | FAIL — **green before round 3** |
| the same reassignment in a separate file | TestRISK030_Wall_NoProductionReassignmentOfAdmissionHandles (main) | FAIL — **green before round 3** |
| §4 reinstates "Allow panics" | ZeroValueResidual_DocumentMatchesTheEngine | FAIL — **green before round 4** |
| §4 adds a row the gate cannot run | ZeroValueResidual_DocumentMatchesTheEngine | FAIL (no silent skip) |
| §4 deletes a row the gate knows | ZeroValueResidual_DocumentMatchesTheEngine | FAIL (as required) |
| §4's table header renamed | ZeroValueResidual_DocumentMatchesTheEngine | FAIL (parser cannot match nothing and pass) |
| global write beside an inner shadow | TestRISK030_Wall_NoProductionReassignmentOfAdmissionHandles (main) | FAIL — **green before round 5** |
| owner walls run from another CWD | GossipLoopIsFedTheEnforcingLimiter, RequestPathUsesClusterAwareEntryPoint | FAIL — **green before round 5** (parse error, not a verdict) |

### Review rounds — the wall checked the SPELLING, not the BINDING

Two independent reviewers (Codex P2, CodeRabbit) found the same hole in the
wall this review introduced, and they were right: it compared the limiter
argument's identifier NAME against `"rl"` and nothing more. A local
`rl := newRateLimiter()` inside `DataPlaneClient.Run` is spelled `rl`, so it
passed — while gossip fed an independent limiter, the enforcing one was never
armed, and fleet-wide limiting silently became per-node. **Reproduced against
the shipped wall: the mutation left the gate GREEN**, which is the one outcome
this review's own standard calls worse than having no gate. The same hole sat
in the request-path wall, which no reviewer mentioned — the right method on the
wrong object consults no remote count.

A second round then found that resolving the CALLER was not enough: the wall
stopped at `Run`, so `rateLimitGossipLoop` reassigning its own `limiter`
parameter would pass while `SetClusterEnabled` and `ApplyRemoteCounts` updated
an independent object.

**The contract the wall now pins is two syntactic hops** — `Run` must pass the
package-level `rl`, and the loop must keep the parameter it was handed — plus
the request path's own binding. What a helper does with a limiter it is handed
belongs to that helper's tests, not to this wall; the scope is stated in the
wall itself, so the boundary is a decision rather than an omission.

**This is the repo's own recorded lesson arriving a second time, which is the
part worth keeping.** CHAOS-69 round 5 rejected a wall that "compared the
argument's identifier NAME against a blessed set" precisely because it passed
against the shape re-spelled `lookupHost := host`, and replaced it with a check
on the ASSIGNMENT. A name is not a binding: a structural wall that reads
identifiers must resolve what they refer to, or it proves only that somebody
typed the right word. The resolution is deliberately CONSERVATIVE — a rebinding
anywhere in the function counts, even on a branch the call cannot reach —
because for a security wall the safe direction is refusing a shape it cannot
prove.

A third round found the gap the first two left by construction: both reason
INSIDE `Run` and the handlers, so the package HANDLE itself was unguarded.
`Run` captures the pointer when it starts the gossip loop while the request
path reads the global per request, so `rl = newRateLimiter()` in any other
production function splits the owner after the fact — requests enforce with the
new limiter, gossip keeps feeding the old one, and the live budget is
discarded. Reproduced: adding such a function left every `TestAdmissionOwner_`
test passing. ADR-0038's boundary map already said "No production reassignment
of `rl`", so this was a recorded invariant with nothing enforcing it —
`admission_owner_reassign_wall_test.go` was added to scan every non-test file
in the package for an assignment to the handle, with controls in both
directions and two mutations verified failing. That file has since been
deleted: main gained
`TestRISK030_Wall_NoProductionReassignmentOfAdmissionHandles` with RISK-030,
which flags every assignment to `ipf` or `rl` in package main's non-test files
(stricter — it does not exempt a local of the same name), and the three
reassignment mutations in the table above were re-run against it.

**The shape of these three rounds is the lesson, not any one of them.** Each
fix was correct and each left the next hop unguarded: resolve the caller's
binding, then the callee's, then the handle both of them name. A wall over a
composition invariant has to state WHICH hops it covers — this one now does,
and the third round is what turned "the wall checks the owner" into a claim
with a boundary.

Known and deliberately NOT closed here: the request-path wall is scoped per
FILE, so it requires one `AllowAuto` somewhere in `proxy.go`/`socks5.go` rather
than inside each named handler, and a future handler could lose its call while
an unrelated helper satisfies the check. That is a coverage gap in a regression
test, not a production bypass — both handlers call it today — and it is
recorded here rather than left silent.

### Round 4 — the document itself carried an unmeasured claim

The fourth finding was not in the wall but in **this record**. Residual 1
stated, under the words *"Confirmed by probe"*, that
`(&admission.RateLimiter{}).Allow(...)` panics on a zero value. It does not:
`Allow` returns `true` at `!r.enabled.Load()` before it reaches the
uninitialised shard maps, so only a limiter already configured with a positive
limit can get there. Raised as Codex P2 on `026ab8d`, re-measured, and
corrected — §4 now carries the full probe matrix, including two facts the
original sentence hid: `IPFilter`'s zero value is safe on its **read** path and
only panics on its **write** path, and the limiter is safe on every admission
method until `Configure` arms it.

Two things make this worth recording rather than quietly editing. First, the
claim was **asserted as verified** — the failure was not reasoning, it was
reporting a measurement that had not been taken in the form the sentence
described, which is the one error a security record cannot absorb. Second, the
overstatement had a direction: an exaggerated residual invites hardening the
request path against a fault it cannot have, and it contradicted the contract
recorded one file over (`internal/admission/AGENTS.md`: *"a zero limiter is
supported for disabled admission/diagnostics, while active local admission
requires its constructor"*), which was right all along.

So the correction is pinned rather than trusted.
`TestZeroValueResidual_DocumentMatchesTheEngine`
(`internal/admission/zero_value_doc_test.go`) parses the §4 table out of this
file and drives every row against the shipped engine — the CHAOS-69
runbook-example precedent, applied to a security review instead of a log line.
It pins the CONTRACT, not the layout: the wording and the row count stay the
author's call, but a row the gate cannot run **fails** rather than skipping,
because a skip is exactly how the wrong claim would return. Four mutations
verified failing: the original wrong claim reinstated, a row naming an
unrunnable call, a known row deleted, and a renamed table header (so a parser
that silently matched nothing cannot pass). Two controls: the table must carry
both outcomes, and the parsed row count must cover every call the gate knows.

**The cross-round lesson extends.** Rounds 1–3 were about a wall that proved
less than it claimed; round 4 is the same defect one layer up — *the document*
proved less than it claimed, and nothing checked it. Where a security record
states a behavioural fact, bind the fact to the code that decides it.

### Round 5 — the predicate resolved bindings at the wrong granularity, and the walls read files by bare name

Two findings on `fad9ca6`, both Codex P2, both this PR's.

**(a) The reassignment wall could accept the regression it exists to prevent** —
strictly worse than rounds 1–3, where a wall merely proved less than it
claimed. `assignsPackageHandle` computed ONE `local` flag over the whole
function and used it as a blanket skip, so a helper that both wrote the global
and separately declared an unrelated inner local of the same name
(`rl = newRateLimiter()` beside `if b { rl := newRateLimiter(); _ = rl }`) was
skipped entirely and reported nothing. Shadowing is now resolved PER
ASSIGNMENT: a write reaches the global unless a declaration of that name is
visible at that assignment — in an enclosing scope, and lexically before it.
Receiver, parameters, named results, `var` declarations and range clauses
shadow; closures deliberately do not, since a closure can still write the
global. Codex's repro is a control, with five more pinning the scope rule in
both directions (inner shadow written while the global is untouched; a write
before its local comes into scope; a `var`-declared shadow; a parameter shadow;
a closure writing the global). Verified RED against the pre-fix predicate.

**(b) Every on-disk parse in the owner walls was CWD-relative** — the same
defect round 4's commit had just fixed one file over. Reproduced with Codex's
own method, the compiled root test binary run from `/tmp`: two of the four
walls failed with `open controlplane_client.go: no such file or directory` and
`open proxy.go: …`. All three on-disk parses now go through `pkgSourcePath()`
over the `runtime.Caller`-anchored `pkgSourceDir()`; the two in-memory parses
are untouched, since their filename is only a label. The failure mode is a
`t.Fatalf`, so these walls failed loudly rather than passing vacuously — a
flake risk rather than a silent hole, but a wall that errors out is not
checking its invariant, and the sharded race runner compiles the root binary
once and runs it as shards, which is exactly the shape that can move the
working directory.

**A recorded misjudgement, because the reasoning was the problem and not the
conclusion.** (b) had been examined a few commits earlier and set aside as
"pre-existing, and not mine to widen here". The supporting argument — that the
repo's `static_read_wall_test.go` regex matches only
`os.ReadFile/Open/Stat`, so the sibling wall sits in a tolerated gap — was
correct and irrelevant, because `admission_owner_wall_test.go` is ADDED BY THIS
PR and nothing about it was pre-existing. One command settles it
(`git cat-file -e origin/main:admission_owner_wall_test.go`); it was not run,
and a recollection was trusted instead. **Verify the premise of a
scope decision against the repository, not against memory of it.**

**THE CROSS-ROUND PATTERN NOW HAS FIVE INSTANCES AND ONE CAUSE.** Round 1
compared the identifier's SPELLING instead of its binding; round 2 missed the
CALLEE's rebinding; round 3 missed the HANDLE both of them name; round 4 was
the DOCUMENT reporting on all three; round 5(a) is the PREDICATE resolving
bindings at FUNCTION granularity when the question is per-assignment. Every one
is the same error at a different altitude: reasoning about a binding at the
wrong granularity, and each fix was correct at its own level while leaving the
next level unexamined. Round 5(b) is its verification twin — having just fixed
a CWD-relative read, the question to ask was *where else does this change read
a file by bare name*, and it was answered for the file being edited rather than
for the primitive. That is the same "enumerate from the primitive" rule this
record already states for contracts, which evidently has to be applied to
verification and to review scope as well.

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

1. **Constructor-dependent invariant on exported types.** The zero value of
   each engine is safe until it is *used actively*, and the boundary is not the
   type — it is the individual method. Measured against the shipped code:

   | zero-value call | result |
   |---|---|
   | `(&admission.IPFilter{}).Allowed(ip)` | no panic |
   | `(&admission.IPFilter{}).Add(ip)` | **panic**, `assignment to entry in nil map` |
   | `(&admission.RateLimiter{}).Allow(ip)` | no panic |
   | `(&admission.RateLimiter{}).AllowAuto(ip)` | no panic |
   | `(&admission.RateLimiter{}).AllowClusterAware(ip)` | no panic |
   | `(&admission.RateLimiter{}).AddExemption(ip)` | no panic |
   | `Configure(10, time.Minute)` **then** `Allow(ip)` | **panic**, `assignment to entry in nil map` |

   So the limiter's admission methods short-circuit on `!enabled` *before* they
   reach the uninitialised shard maps, and only a limiter that has been
   configured with a positive limit can reach them. **An earlier draft of this
   section claimed `(&admission.RateLimiter{}).Allow(...)` panics as written.
   It does not** — the claim was raised in review (Codex P2 on `026ab8d`) and
   re-measured; the table above is the probe output. The correction matters
   beyond accuracy: an overstated residual invites zero-value hardening on the
   request path that the code does not need, and it contradicted the contract
   already recorded one file over
   (`internal/admission/AGENTS.md`: *"a zero limiter is supported for disabled
   admission/diagnostics, while active local admission requires its
   constructor"*), which is the authority here.

   The residual that survives is narrower and still real: the two **write**
   paths (`IPFilter.Add`, and the limiter's bucket insertion once configured)
   depend on their constructor. Production builds both through
   `NewIPFilter`/`NewRateLimiter` everywhere (verified across the tree), so it
   is unreachable today, and ADR-0038 records it as a deliberately preserved
   limitation rather than adding lazy initialisation to the hot path.
   Extraction widened *who can write the misuse* (any module-internal package)
   without changing the behaviour. Hardening options, for a separate change:
   make the zero value safe, or make the types unusable without a constructor.
2. **`ipf` is swapped unsynchronised.** `controlplane_snapshot.go:873` assigns
   the package-level `ipf` pointer, which request goroutines read at
   `proxy.go:1477` and `socks5.go:430` with no synchronisation. Identical at
   baseline (`1f7f42c:controlplane_snapshot.go:875`); the engine's own internal
   state is atomic, it is the handle swap that is not. Out of scope here.
   **Since closed on main as RISK-030** (PR #1635): the snapshot apply now
   replaces the filter in place (`IPFilter.Replace`), and
   `TestRISK030_Wall_NoProductionReassignmentOfAdmissionHandles` forbids
   reassigning either handle.
3. **`ExportHotDeltas` is misnamed**, exporting absolute in-window counts rather
   than deltas. ADR-0038 records this as a documentation defect deliberately
   left alone, because changing it would change cluster accounting. The new
   `HotCount` type name and the `cluster_ratelimit_wire.go` comment make the
   wire meaning explicit, which improves matters without touching behaviour.

## 5. Files

- `admission_owner_wall_test.go` — new, test-only: two structural walls with
  controls, plus the documented-residual behavioural test.
- `admission_owner_reassign_wall_test.go` — added in round 3 and **deleted
  when main was merged in**, per its recorded merge disposition: PR #1635
  merged first with `TestRISK030_Wall_NoProductionReassignmentOfAdmissionHandles`, a strict superset (it covers `ipf` *and* `rl`, and
  does not exempt locals). The package-handle half of the one-owner contract
  is now that wall's; the round-3 mutations were re-run against it.
- `internal/admission/zero_value_doc_test.go` — new, test-only (round 4): binds
  §4's zero-value table to the engine, so this document cannot drift from the
  behaviour it reports.
- `docs/agent-context/domains/admission.md` — the one-owner invariant in prose:
  what the contract is, why a split owner is silent, and why detection is
  deliberately NOT the control. This is the only prose home of the rule, so a
  reader who finds the walls and wants the reasoning is sent here. It was first
  written on CLAUDE.md's "Admission engine" bullet and moved when main's
  agent-context decomposition (#1592) reduced CLAUDE.md to a pointer stub;
  `internal/admission/AGENTS.md` names this file as the current contract.
- `docs/engineering/TECHNICAL-RISK-REGISTER.md` — RISK-031 (MEDIUM, CLOSED).
  Drafted as RISK-030; renumbered because a different finding merged first
  under that number.
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
| `go test ./internal/admission -run TestZeroValueResidual` | pass |
| Mutation proofs (11 across rounds 1–4) | each verified failing its gate |
