# Performance Guardian Review — 2026-11-11

**Scope.** `04aa647` (`origin/main`). Measured, not read: every number below
came from a benchmark, an allocation profile or a `benchstat` comparison run on
this revision, on this machine (Go 1.27.4, linux/amd64, 4 vCPU Xeon @ 2.10 GHz).

**Question asked.** The 2026-11-10 pass inventoried benchmark coverage per
package to find hot-path owners with no measurements at all, and listed six:
`internal/audit`, `internal/bandwidth`, `internal/catdb`,
`internal/clientclass`, `internal/geoip`, `internal/identcache`. It took
`catdb`. This pass took the one remaining on that list that sits on a
per-request path with a process-wide lock in front of it: **`internal/identcache`,
the identity-result cache shared by every identity backend on the proxy
credential path** (the LDAP directory bind, the legacy OIDC introspection
backend and the IdP-registry introspection provider).

**Method.** The request hot paths were measured first, to confirm the previous
passes had in fact closed them, and they had: of `BenchmarkPolicyEvaluate_*`'s
50 sub-benchmarks, 33 are fully allocation-free (0 B/op, 0 allocs/op), 13 make
one allocation and 4 make two, and an allocation profile of
`BenchmarkHTTPForward_HandleHTTP`
attributes 95 allocs/op almost entirely to stdlib `net/http` transport, context
and `textproto` machinery plus the `httptest` harness itself — `handleHTTP`'s own
flat contribution is one allocation, and the single largest named site,
`net/http.Header.Clone` at 9.9%, is `httptest.ResponseRecorder.WriteHeader`, not
production code. So the question moved to cost reached through a dependency,
which is where `identcache` was.

**Outcome: one optimization, measured, shipped, and gated.** One concern. The
production change is confined to `internal/identcache/identcache.go`; no
behaviour, wire, persistence or API change, and `BetterVictim` — shared with
`store.go`'s local credential cache — is untouched.

---

## Executive Summary

**Victim selection in the identity-result cache was a scan over every bucket,
and the bucket key is the client's own address.** `evictOneLocked` answered both
of its questions by iterating `c.buckets`:

```go
for client, b := range c.buckets {
    k, e, okFront := c.frontLocked(client, b)   // ← a hashed map lookup per client
    ...
}
```

`frontLocked`'s cost is a `c.entries[k]` lookup on a string key, so the
selection paid one such lookup per distinct fairness key. The fairness key is
`clientFairnessKey` — an IPv4 address or an IPv6 /64 — so that is one lookup per
active client, under `c.mu`, once per insertion, for as long as the cache sits
at its cap.

One insertion at the cap, swept over client count at the real
`maxAuthCacheSize` of 5,000:

| clients | before | after | |
|---|---|---|---|
| 1 | 451 ns | 572 ns | ~ (p=0.394) |
| 10 | 770 ns | 707 ns | ~ (p=0.394) |
| 100 | 4,252 ns | 579 ns | **−86.4%** |
| 1,000 | 44,512 ns | 733 ns | **−98.4%** |
| 5,000 | 275,919 ns | 1,095 ns | **−99.6%** |

The pre-change shape is linear in a number the cache does not control, with a
**612× spread** across the sweep. (A separate coarser run — `-benchtime=2000x`,
the measurement that first exposed this — put the same sweep at 364 ns to
271,017 ns, 744×. The table above is the `benchstat` figure and is the one
quoted throughout.)

Three things make this worth a PR rather than a note:

1. **It is lock-held work on the credential path.** 276 µs under `c.mu` is not
   only CPU — it is a latency floor for every concurrent `Get` queued behind the
   same mutex. Measured directly on the concurrent shape, with one store in
   four: **85.6 µs → 659 ns** per operation at 5,000 clients (−99.2%).
2. **`clients=5000` is the ordinary case, not the adversarial one.** At a 5,000
   cap it is one cached verdict per client — the shape of any deployment with a
   few thousand active addresses — and it is the worst case for the scan,
   because every bucket then ties on live count so none can be skipped.
3. **The term it is linear in is attacker-influenced.** The package
   documentation is explicit that these caches are populated by *unauthenticated*
   requests over a caller-supplied key space (ADR-0041/CHAOS-76): an
   authoritative denial is cached deliberately. So the cost of the fairness
   policy grew with the very flood the policy exists to survive. The skewed
   shape — one client holding most of the cache while others hold one verdict
   each — measured **253,456 ns → 686 ns (−99.7%)**.

---

## Finding 1 — eviction selection was linear in the active client count

### Root cause

`evictOneLocked` needs two answers: *is any bucket front already expired?* (such
an entry is free to drop and is always the better victim) and *which front is the
fairness victim?* (most live entries first, then oldest entry, then
lexicographically smaller client, per the exported `BetterVictim`). It derived
both by visiting every bucket on every call.

Nothing was cached between calls, so the work was repeated per insertion even
though a bucket's front changes only when that bucket is mutated.

### Why no existing benchmark could see it

`internal/identcache` had **zero** benchmarks — it was on the previous pass's
list of un-measured hot-path owners. Its callers could not see the cost either:
the backends' own paths are dominated by the directory bind or introspection
round trip the cache exists to avoid, so in a miss-path benchmark a 276 µs
eviction hides inside a millisecond-scale network call, and in a hit-path
benchmark eviction never runs at all. The cost only appears when the cache is
*full* and *inserting*, which is the steady state in production and the state no
benchmark constructed.

### The fix

Two binary heaps over the buckets that hold a live entry, maintained
incrementally, replacing the scan with two root reads:

- `victims`, ordered by `victimLess` = the same exported `BetterVictim`
  predicate the scan applied, to the buckets' memoised fronts. Its root is the
  fairness victim.
- `expiries`, ordered by front deadline. Its root answers "is any front
  expired?" in O(1).

`bucket` gains a memoised front (`frontKey`/`frontAdded`/`frontExpiry`) and one
index slot per heap. `syncBucketLocked` is the single writer of that memo and
repositions the bucket in both heaps; `bumpLiveLocked` is the cheap path for the
common case where only the live count moved — appending to a bucket that already
had a front, or removing a key that was not the front — which keeps
`frontLocked`'s map lookup off the hot path. Insertion at the cap becomes
O(log clients).

The heaps are hand-rolled rather than `container/heap` because this package is a
stdlib leaf whose import surface is `sync` and `time` only, pinned by
`TestIdentcacheBoundary_NoApplicationDependenciesOrSharedState` (ADR-0041).

### Measurements

`benchstat`, `-count=6`, `-benchtime=3000x`, at the real 5,000 cap:

| benchmark | before | after | |
|---|---|---|---|
| `StoreAtCap/clients=100` | 4,252 ns | 579 ns | −86.4% |
| `StoreAtCap/clients=1000` | 44,512 ns | 733 ns | −98.4% |
| `StoreAtCap/clients=5000` | 275,919 ns | 1,095 ns | **−99.6%** |
| `StoreAtCapSkewed/clients=100` | 3,429 ns | 413 ns | −88.0% |
| `StoreAtCapSkewed/clients=1000` | 39,960 ns | 467 ns | −98.8% |
| `StoreAtCapSkewed/clients=5000` | 253,456 ns | 686 ns | **−99.7%** |
| geomean (all `StoreAtCap*` / `CredentialPathParallel` shapes) | 3.229 µs | 563 ns | **−82.6%** |

The concurrent credential path was re-measured separately at `-benchtime=1s`,
`-count=8` (every row `p=0.000`), after the benchmark was reworked to give each
goroutine a local counter — a shared atomic incremented inside the measured
loop adds its own contention to a benchmark whose subject is contention:

| benchmark | before | after | |
|---|---|---|---|
| `CredentialPathParallel/clients=5000/store=1in4` | 85,621 ns | 659 ns | **−99.2%** |
| `CredentialPathParallel/clients=5000/store=1in64` | 5,737 ns | 290 ns | **−94.9%** |
| `CredentialPathParallel/clients=100/store=1in4` | 1,500 ns | 543 ns | −63.8% |
| `CredentialPathParallel/clients=100/store=1in64` | 324 ns | 273 ns | −15.7% |
| geomean | 3.931 µs | 411 ns | **−89.6%** |

A second, higher-precision run (`-benchtime=1s`, `-count=10`) for the shapes the
3000x run reported with wide variance:

| benchmark | before | after | |
|---|---|---|---|
| `StoreAtCapExpiring/clients=100` | 5,024 ns | 840 ns | −83.3% |
| `StoreAtCapExpiring/clients=5000` | 154,376 ns | 1,460 ns | −99.1% |
| `GetHit` | 123.1 ns | 122.4 ns | **~ (p=0.781)** |
| `RefreshAtCap/clients=1` | 451.5 ns | 486.9 ns | +7.8% |
| `RefreshAtCap/clients=1000` | 438.8 ns | 801.1 ns | **+82.6%** |

The `StoreAtCapExpiring` figures matter twice: the `-benchtime=3000x` run had
reported them as +16% and +26% regressions, and the 1-second run shows those
were noise over an 83–99% improvement. The same caution applies in the other
direction, which is why `RefreshAtCap` below is treated as real: it reproduces
at `p=0.000` with ±5% spread.

Allocations per insertion are unchanged (`~` or `all samples are equal` on every
shape except `StoreAtCap/clients=5000`, where B/op moves 191 → 287 from the heap
backing arrays; allocs/op is identical at 6). The read path is untouched, and
measured so rather than asserted: `GetHit` is unchanged.

Total wall time of the benchmark suite itself fell from 13.094 s to 0.775 s.

### Trade-offs

**One path is deliberately left slower.** Re-verifying a credential the cache
already holds (`Set` on an existing key) removes the old record and appends the
key again, so the bucket's live count goes down one and straight back up; each
move repositions it in the fairness heap, and the two usually cancel. That costs
**+362 ns** (439 → 801 ns at 1,000 clients), where the old code did almost
nothing because removing the existing key takes the entry count below the cap
and the eviction loop then never runs.

It is not optimised away. Collapsing the two moves means deferring the first
bucket's index fixup past the eviction loop on the strength of "removing an
existing key means the loop cannot run" — a cross-function invariant inside an
eviction policy that is a security control — bought for 362 ns on a path that
runs once per cached credential per TTL (≈17/s at the 5,000 cap and a
five-minute TTL) and exists to avoid a millisecond-scale directory bind. The
insertion path it pays for is three orders of magnitude better off. The reasoning
is recorded on `store` so the next reader does not have to rediscover it.

**Memory.** Two `[]*bucket` plus 56 bytes of per-bucket memo and index. Both
slice lengths track the live bucket count exactly, so the backing arrays peak at
the cap and do not grow with request count — the trap `compactLocked` already
documents for `bucket.keys`. At the 5,000 cap that is ~80 KB of pointers worst
case.

### Risk

The selection is behaviour, so equivalence is asserted, not argued.

**One deliberate refinement.** The scan evicted whichever expired front Go's
randomised map iteration reached first; the index takes the earliest-expiring
one. Both satisfy the documented policy ("an already-expired one if a bucket
front holds one") and the new choice is *reproducible*, which is the property
`BetterVictim` exists to give the live path. Pinned by
`TestChaos76_EvictionPrefersTheEarliestExpiredFront`.

### Guards added, and how each was validated

| guard | kind | validation |
|---|---|---|
| `TestChaos76_EvictionIndexSelectsTheSameVictimAsTheFullScan` | differential oracle: the old scan kept as an executable reference, 6 randomised workloads × 4,000 steps | inverting `victimLess` fails it; dropping the live-count fixup in `store` fails it at step 40 |
| `checkEvictionIndex` (called every step of the oracle and of the refresh test) | structural: heap order, recorded positions, one-bucket-one-slot, index covers exactly `c.buckets`, and each memo still describes its bucket's real front | the dropped-fixup mutation above is caught here as well as by the oracle |
| `TestChaos76_EvictionPrefersTheEarliestExpiredFront` | pins the one refinement, over 32 attempts so map order cannot hide a failure | fails if selection falls back to an arbitrary expired front |
| `TestChaos76_EvictionIndexSurvivesRefreshAndCompaction` | 3,000 steps over a small key and client space, forcing refreshes and re-attribution through `compactLocked`'s renumbering | — |
| `TestChaos76_WallNoBucketScanSurvivesInEviction` | **load-independent** AST wall: fails the build if `evictOneLocked` iterates `c.buckets` again, with a not-vacuous check that it still reads both heap roots | — |
| `TestBenchGate_EvictionAtCapIsFlatInClientCount` | `benchgate`-tagged wall-clock **ratio** gate, 25 vs 2,500 clients, bound 10× | **81.73× against the pre-change scan (FAIL) vs 1.59× after (PASS)** |

The ratio gate is tagged for the reason `internal/catgroup`'s equivalent is: a
wall-clock comparison is not a property an ordinary, race or determinism run can
decide, and a gate that red-lights a correct tree under load is worse than no
gate. It carries an **embedded control** — it asserts `Len() == cap` both before
and after the measured churn, because the cheapest way to make eviction flat is
to stop evicting. `./internal/identcache` is registered in all three `benchgate`
commands (`pr-fast-gate.yml`, `qa-gate.yml`, `proxy-weekly-stress.yml`) and in
the package list `verification.md` enumerates: a gate CI does not run is not a
gate.

The deterministic AST wall exists because the ratio gate cannot run everywhere.
Together they mean the regression fails the build on a loaded runner and fails
the gate on a quiet one.

---

## Finding 2 — the same scan exists in two sibling caches (NOT fixed here)

The identical pattern, with the identical `better`/`BetterVictim` ordering, is in
two other owners:

| owner | cap | exposure |
|---|---|---|
| `store.go:604` — `authCacheStore.evictOneLocked` (the LOCAL credential cache) | `maxAuthCacheSize` = 5,000 | the same proxy credential path; its own comment calls the cost "cheap (O(active clients), not O(cache))", which is the framing this review's measurement contradicts at enterprise client counts |
| `internal/authstate/authstate.go:269` — `Store[T].evictOneLocked` | 1,000 (`pkceStoreMax`, `samlStateStoreMax`) | OIDC PKCE and SAML relay state — login-flow volume, and a 5× smaller cap, so materially less exposed |

**Deliberately out of scope for this PR**, under the standing one-optimization-
per-PR rule: `store.go` is a different owner in package main with its own test
surface and its own bcrypt-governor interactions (CHAOS-57), and folding it in
would roughly triple the diff in a security control. It is a measured-by-analogy
follow-up, not a speculative one — the loop is the same shape over the same key
space at the same cap — and the `BetterVictim` definition this PR leaves
untouched is what a follow-up would reuse.

`internal/authstate` is the weakest of the three: a 1,000 cap bounds the scan to
~1/5 of the measured worst case, and login-flow insertions are far rarer than
credential verifications.

---

## What was measured and found already appropriate

- **Policy evaluation.** `BenchmarkPolicyEvaluate_*` across 28 shapes: 0 B/op
  and 0 allocs/op on 20 of them, 16 B/op / 1 alloc on the category-group
  by-ID/by-name arms, 640 B/op / 1 alloc on `FirstMatch` (the returned match).
  Flat in rule count from 10 to 10,000 (288 → 337 ns). Nothing to take.
- **Plain-HTTP forward.** `BenchmarkHTTPForward_HandleHTTP`: 95 allocs/op, of
  which `handleHTTP`'s own flat share is **one** (`readErrTracker`). The profile
  is stdlib transport/context/`textproto` plus the `httptest` harness; the
  largest named site is `httptest`'s own `Header.Clone`. Already closed by
  earlier passes — `setupRequestTracing` carries their measurements in-line.
- **Regexp compilation.** Swept every non-test `regexp.Compile`/`MustCompile`
  outside `vendor/` and `third_party/`. All are package-level `var` or
  construction-time; the one inside a function body
  (`parseYARAHexPattern`, `internal/yara/yara.go:1152`) is on the YARA
  *rule-parsing* path, not the scan path, so it runs at rule load. Noted, not
  worth a PR.

## Benchmark plan — what this review could not measure

- **A real multi-thousand-client deployment.** Every figure here is a synthetic
  sweep on one 4-vCPU box. The shape (linear vs logarithmic in client count) is
  the claim; the absolute nanoseconds are this machine's.
- **Mutex-profile evidence for the credential path end to end.** The
  `CredentialPathParallel` benchmark shows the contention indirectly, through
  per-operation cost at 4-way parallelism (where even the 100-client,
  mostly-read shape improved 15.7%, which is lock-hold time the readers were
  previously waiting out). A `-mutexprofile` over a live proxy
  run with real LDAP latency would attribute the saved lock-hold time to the
  waiting `Get`s directly; the 2026-11-10 pass did exactly this for `catdb` and
  it is the right follow-up here.
- **The two sibling caches, measured rather than reasoned.** Finding 2 asserts
  the same shape from the same source structure and the same cap. It should be
  measured in the PR that fixes it, with the same before/after discipline.

## Residual risk

- **The index is now invariant-bearing state.** Before, selection was derived
  from scratch on every call and could not be stale. Now `bucket`'s memo and
  both heap positions must be re-established after every mutation of `keys`,
  `head`, `live` or the entry map. The oracle plus `checkEvictionIndex` run that
  invariant on every step of 27,000 randomised operations, and two mutations
  confirm they fail when it breaks — but a future change that mutates a bucket
  without routing through `syncBucketLocked`/`bumpLiveLocked` is a new class of
  bug this code did not previously admit. `syncBucketLocked` is documented as
  the only writer of the memo for that reason.
- **The expired-front choice changed identity** (earliest-deadline rather than
  map-order). Any out-of-tree test asserting *which* expired entry went would
  see a difference; no in-tree test did.
- **`RefreshAtCap` is slower by 362 ns** and knowingly so (see Trade-offs). If a
  deployment is ever found where refresh dominates insertion, the deferral
  described there is the fix, and it should arrive with its own measurement.
- **The ratio gate is a ratio, not a budget.** It catches the asymptotic
  regression — the one that actually happened — and would not catch a uniform
  constant-factor slowdown. `BenchmarkStoreAtCap` and the figures above are the
  record for that.
