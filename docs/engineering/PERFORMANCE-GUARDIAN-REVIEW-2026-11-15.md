# Performance Guardian Review — 2026-11-15

**Scope.** `0b11474` (`origin/main`), 116 commits after the 2026-11-11 pass's
`04aa647`. Measured, not read: every number below came from a benchmark, an
allocation profile or a `benchstat` comparison run on this revision, on this
machine (Go 1.27.4, linux/amd64, 4 vCPU Xeon @ 2.10 GHz).

**Question asked.** The 2026-11-11 pass closed the eviction scan in
`internal/identcache` and left, as its *Finding 2*, the same scan in two sibling
caches — explicitly flagged as **"a measured-by-analogy follow-up, not a
speculative one"** and deferred under the one-optimization-per-PR rule. This
pass took the more exposed of the two: `authCacheStore.evictOneLocked` in
`store.go`, the LOCAL credential cache on the proxy bcrypt path, at the same
5,000 cap and keyed on the same client address.

The point of this pass was therefore not to find a new suspicion but to **hold
an inherited one to the evidence standard** — to measure the analogy rather than
trust it. Two of the three things that got measured came out differently from
what the analogy predicted (see *Finding 2* and *What was measured and found
already appropriate*), which is the reason the standard exists.

**Outcome: one optimization, measured, shipped and gated. One correctness
defect found while measuring, reported for its own change. One predicted defect
that did NOT reproduce, withdrawn on measurement.**

---

## Executive Summary

**Victim selection in the local credential cache was a scan over every active
client, and it ran under the mutex every credential verification needs.**
`evictOneLocked` answered both of its questions — "is any bucket front
expired?" and "which front is the fairness victim?" — by iterating `a.buckets`
and calling `frontLocked` on each, whose cost is a hashed map lookup on a string
key. The fairness key is `clientFairnessKey` (an IPv4 address or an IPv6 /64),
so that is **one map lookup per active client, per insertion, for as long as the
cache sits at its cap** — and at a 5,000 cap with a 5-minute TTL, at the cap is
the steady state of any deployment with a few thousand active addresses.

Measured, one insertion at the cap, swept over active-client count:

| clients | before | after | |
|---|---|---|---|
| 1 | 1.352 µs | 1.426 µs | ~ (p=0.083) |
| 10 | 1.881 µs | 1.737 µs | ~ (p=0.878) |
| 100 | 5.522 µs | 1.760 µs | **−68.12%** |
| 1,000 | 58.802 µs | 1.596 µs | **−97.29%** |
| 5,000 | 328.280 µs | 2.007 µs | **−99.39%** |

`benchstat`, n=8, geomean **−71.59%**. The curve was linear in the client count
and is now flat.

**328 µs of lock-held work per cached credential** is both a throughput ceiling
on the credential path and a latency floor for every concurrent `get()` waiting
on the same mutex. What makes it a product defect rather than an inefficiency is
*whose* number it is linear in: this cache is populated by **UNAUTHENTICATED**
requests — any client presenting the configured username with any password
writes an entry, because negative results are cached deliberately (CHAOS-57) —
so the cost of the fairness policy grew with the very flood the policy exists to
survive.

The effect on the path the product actually sells, at a realistic 31:1
read:write mix (a credential is read every request for its whole TTL and written
once per TTL), 4-way parallel:

| clients | before | after | |
|---|---|---|---|
| 100 | 1.553 µs | 1.395 µs | −10.17% |
| 1,000 | 3.061 µs | 1.319 µs | **−56.91%** |
| 5,000 | 13.984 µs | 1.496 µs | **−89.30%** |

Geomean **−65.40%**. Thirty-one of every thirty-two operations in that mix are
pure reads, so an 89% fall in *average* operation cost at 5,000 clients is
almost entirely **lock-hold time the readers were previously waiting out**.

---

## Finding 1 — eviction selection was linear in the active client count (FIXED)

**Severity.** Throughput ceiling and latency floor on the credential path,
proportional to a quantity an unauthenticated client contributes to.

**Root cause.** `evictOneLocked` (`store.go`) selected by scanning:

```go
for client, b := range a.buckets {
    k, e, okFront := a.frontLocked(client, b)   // ← a hashed map lookup per client
    ...
}
```

**The fix** is `internal/identcache`'s, because this cache's eviction policy is
already deliberately identcache's policy: two binary heaps over the buckets that
hold a live entry, ordered by `authVictimLess` and `authExpiryLess`, maintained
incrementally by `syncBucketLocked`, with each bucket memoising its own front.
Both of the selection's questions become heap roots, so an insertion at the cap
is O(log clients) and the client-count term leaves the measurement entirely.

`betterAuthCacheVictim` — which already delegates to `identcache.BetterVictim`
so the caches cannot drift apart on what "better victim" means — is untouched,
and `a.victims` is ordered by it, so **the selection is unchanged**.

**One deliberate refinement.** The scan dropped whichever expired front Go's
randomised map iteration reached first; the index drops the earliest-expiring
one. Both satisfy the policy and the new choice is deterministic — the property
the rest of this policy is built on.
`TestPerfAuthCache1_EvictionPrefersTheEarliestExpiredFront` pins it.

### Trade-offs, measured rather than asserted

- **The expired-front path, corrected.** It now reads a heap root and pays
  O(log clients) of heap maintenance in `removeLocked`. The first measurement
  of `BenchmarkAuthCacheSetAtCapExpired` reported **+42.70%** at 5,000 clients
  (1.377 → 1.965 µs), but that control did not hold its premise: aging entries
  in place left the index's memoised front expiries stale, and each timed
  insertion replaced an expired entry with a live one, so most iterations
  measured live-entry eviction (Codex review on #1910). With the benchmark
  fixed (it resyncs every bucket after aging and re-ages, timer stopped,
  before the expired supply runs out), median of 5 at 20,000 insertions:
  1 client 1.56 → 1.58 µs (flat), 1,000 clients 4.18 → 2.08 µs, 5,000 clients
  8.62 → 2.55 µs. The scan was not O(1) here after all, so the trade-off this
  section first described does not exist: the expired arm is faster too.
- **The flood shape at a small client count.** `Skewed/others=10` measured
  **+45.40%** (1.581 → 2.298 µs, p=0.041, and ±38% spread on the after arm —
  the weakest signal in this review). The same shape at 100 and 1,000 others is
  −71.06% and −97.48%.
- **Memory.** `authCacheBucket` grew from **40 to 136 bytes** (the memoised
  front plus two heap positions), confirmed by `unsafe.Sizeof`, plus 16 B of
  heap slots per bucket. That is exactly the measured B/op delta at 5,000
  clients — 830 → 926 B/op, +96 B — where every insertion creates a bucket.
  Worst case at the cap (one credential per client) is **~560 KB** additional
  resident. `allocs/op` is unchanged everywhere except the `Expired/5000` arm
  (+1); an allocation profile attributes `set`'s own allocations to `cacheKey`'s
  HMAC, the entry and the bucket, and **none to the heap operations**, which
  reach steady state at the cap and stop growing.

### How the change is held

Four guards, and **all four were mutation-tested** — the 2026-11-11 pass found
two of its three guards vacuous on first attempt, so this was checked rather
than assumed:

| guard | mutation | caught |
|---|---|---|
| differential oracle vs. the full scan | `bumpLiveLocked` made a no-op | ✓ |
| differential oracle vs. the full scan | `authVictimLess` arguments flipped | ✓ |
| index invariant checker | `authHeapRemove` dropped on bucket delete | ✓ |
| earliest-expired pin | `authExpiryLess` reversed | ✓ |
| AST wall (`range a.buckets`) | selection reverted to the scan | ✓ |
| `TestBenchGate_` ratio gate | selection reverted to the scan | ✓ (62.31x vs the 10x bound) |

The scan is kept in the test file as an **executable oracle**
(`referenceAuthVictim`, verbatim apart from not mutating the store — including
its `now.After(e.expiry)` test rather than `!now.Before(...)`, because the two
differ at the instant `now == expiry` and copying the original keeps the oracle
an oracle). Over six seeds × 1,500 randomised steps the heap-indexed selection
must drop exactly what the scan would, with the index's structural invariants
re-checked at every step and after every eviction.

The ratio gate is machine-independent by construction — insertion at the cap
against ITSELF at 25 and 2,500 clients, bound 10x — and carries an **embedded
control**: it asserts the cache holds exactly its cap both before and after the
measured churn, because the cheapest way to make eviction flat is to stop
evicting. Measured 1.00x indexed, 62.31x with the scan reverted. The root
package `.` is already named in all three `benchgate` commands
(`pr-fast-gate.yml`, `qa-gate.yml`, `proxy-weekly-stress.yml`), so this gate
runs where it has to; a gate CI does not run is not a gate.

### Why the heaps are duplicated and not imported

`identcache`'s heaps are duplicated here rather than shared, and that is a
measured decision, not laziness. Its `bucket` is an unexported type coupled to
its generic `entry`, so sharing would mean re-expressing the heaps over an
interface or a method-bearing type constraint — which makes **every comparison
an indirect call, in identcache's hot path as well as this one**, and
identcache's insertion cost is held by its own wall-clock ratio gate. Slowing a
gated owner to de-duplicate 90 lines is the wrong trade. Sharing the index
behind an exported, non-dispatching seam is a follow-up with its own
measurement; the shared *policy* (`BetterVictim`) already spans both.

---

## Finding 2 — `frontLocked` has no generation marker, so a refreshed entry can be reported as its client's oldest (NOT fixed here)

Found while building the memo, because the memo has to describe the bucket's
real front. **This is a correctness defect in a security control, not a
performance one**, and it is reported for its own change under the
one-concern-per-PR rule — the same disposition the 2026-11-09 pass gave the
defect it found while measuring.

`set` on a key the bucket already lists removes the old record and appends the
key again, so a bucket can read `[A, B, A]` while `live` counts 2.
`frontLocked`'s presence-and-client test cannot reject the leading `A`, because
the NEW record answers "present" for every historical position of that key.
Confirmed by probe on this revision:

```
keys=3 live=2 head=0   keys[0]=A  keys[1]=B  keys[2]=A
front is A (refreshed) — but B is older
```

**Impact.** Eviction can take a client's freshly re-verified credential in
preference to its genuinely older one; and because `betterAuthCacheVictim`
breaks live-count ties on the oldest entry, a bucket whose front is reported
artificially new looks like a *worse* victim than it is, so a different client
with the same live count is displaced instead. Second-order — it needs tie-ing
live counts — but it is a fairness error in the control CHAOS-57 exists to
provide.

`internal/identcache` fixed exactly this in PR #1633 by giving each entry a
`pos` generation marker naming the one slot its record is authoritative for
(`e.pos == b.head`). `authCacheEntry` has no such field. **That fix is the
shape this one should take**, and it is a behavioural change to a security
control, which is why it is not folded into a performance PR.

This PR preserves the defect exactly: the memo records what `frontLocked`
returns, `syncBucketLocked` re-runs after every mutation, and the differential
oracle proves the index selects what the scan selected — including where the
scan was wrong.

---

## What was measured and found already appropriate

- **The duplicate-slice memory leak did NOT reproduce — predicted, then
  withdrawn.** `identcache`'s `compactLocked` documents duplicates as "the
  SECOND route to that same leak" and dedups for it; `store.go`'s does not, so
  by analogy the NAT'd-office shape (one bucket, several credentials, each
  re-verified every TTL) should grow a bucket's key slice with request count.
  Measured, it does not:

  | sets on one bucket | live | len(keys) |
  |---|---|---|
  | 200 | 5 | 5 |
  | 1,000 | 5 | 10 |
  | 5,000 | 5 | 5 |

  `removeLocked` deletes `entries[k]` *before* the key is re-appended, so the
  stale leading copy stops matching, `head` advances past it, and compaction —
  which filters from `b.keys[b.head:]` — drops it. Bounded, with no dedup
  needed. **This is the analogy this pass was sent to confirm, and it was
  wrong**; it is recorded here so a later pass does not re-derive it from the
  same structural similarity.
- **`internal/authstate`**, Finding 2's other sibling (`Store[T]`, OIDC PKCE and
  SAML relay state). Left alone deliberately and for the reason the 2026-11-11
  pass gave: a 1,000 cap bounds the scan to ~1/5 of the measured worst case, and
  login-flow insertions are orders of magnitude rarer than credential
  verifications. It is the weakest of the three, and it should arrive with its
  own measurement rather than this one's.
- **`identcache`'s own gates.** Re-run in full after the change to confirm this
  pass did not regress the owner it borrowed from; all pass.

## Benchmark plan — what this review could not measure

- **A real multi-thousand-client deployment.** Every figure here is a synthetic
  sweep on one 4-vCPU box. The *shape* (linear vs flat in client count) is the
  claim; the absolute nanoseconds are this machine's.
- **A mutex profile over a live proxy with real bcrypt latency.** The parallel
  benchmark shows the contention indirectly, through per-operation cost at 4-way
  parallelism. A `-mutexprofile` over a live run would attribute the saved
  lock-hold time to the waiting `get()`s directly; the 2026-11-10 pass did this
  for `catdb` and it remains the right follow-up here.
- **The `Skewed/others=10` regression.** +45.40% at p=0.041 with a ±38% spread
  is the weakest number in this review. It is bounded (both arms ~2 µs) and the
  same shape improves 71% and 97% at larger client counts, but it deserves a
  dedicated run before anyone treats it as settled.

## Residual risk

- **The index is now invariant-bearing state.** Before, selection was derived
  from scratch on every call and could not be stale. Now each bucket's memo and
  both heap positions must be re-established after every mutation of `keys`,
  `head`, `live` or the entry map. `syncBucketLocked` is documented as the only
  writer of the memo for that reason, and the oracle plus the invariant checker
  run on every step of 9,000 randomised operations — but a future change that
  mutates a bucket without routing through
  `syncBucketLocked`/`bumpLiveLocked` is a new class of bug this code did not
  previously admit. A test that reaches past `set()` to rewrite an expiry must
  re-run `syncBucketLocked`; the oracle does, and says why.
- **The expired-front choice changed identity** (earliest-deadline rather than
  map order). Any out-of-tree test asserting *which* expired entry went would
  see a difference; no in-tree test did.
- **+96 B per bucket and ~560 KB at the cap** is a real if small trade of
  resident memory for lock-held time. It is the memo; it cannot be given back
  without giving back the fix.
- **The ratio gate is a ratio, not a budget.** It catches the asymptotic
  regression — the one that actually happened — and would not catch a uniform
  constant-factor slowdown. The tables above are the record for that.
- **Finding 2 is still open.** The fairness policy remains slightly wrong in the
  refresh case, exactly as it was before this change.
