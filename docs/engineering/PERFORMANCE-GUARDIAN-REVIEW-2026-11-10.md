# Performance Guardian Review — 2026-11-10

**Scope.** `ac4e223` (`origin/main`). Measured, not read: every number below came
from a benchmark, an allocation profile, a mutex profile or a block profile run
on this revision, on this machine (Go 1.27.3, linux/amd64, 4 vCPU Xeon
@ 2.10 GHz).

**Question asked.** The request hot paths this product is sold on — plain-HTTP
forward, CONNECT establishment, policy evaluation, the tunnel relay, the request
log — carry 512 in-tree benchmarks and 123 `TestBenchGate_` contracts between
them. The previous passes worked those paths. So this pass asked a different
question: **which per-request work is reached through a DEPENDENCY whose cost is
not local to the caller, and therefore cannot be seen in the caller's own
benchmark?** A cost that lands on a process-wide lock or a single goroutine does
not merely add latency — it caps concurrency, and it gets worse exactly when the
appliance is busy.

**Method.** Benchmark coverage was inventoried per package to find hot-path
owners with no measurements at all (`internal/audit`, `internal/bandwidth`,
`internal/catdb`, `internal/clientclass`, `internal/geoip`,
`internal/identcache`). Each was then read for work on the request path.
`internal/bandwidth` was eliminated immediately — `AllowBytes`/`FindPolicy` have
no data-path caller, as `bandwidth_health.go` already records. `internal/catdb`
was the hit: Layer-2 category resolution, reached once per request from the
policy scan's `hostCatScratch`, and backed by BadgerDB.

**Outcome: one optimization, measured, shipped, and gated.** One concern, ~20
lines of changed production code. An independent adversarial review found the
production change correct and **two of the three guards vacuous**; both are
fixed and both fixes are validated by the mutation that exposed them. See
*The guards were validated by mutation* below.

---

## Executive Summary

**The Layer-2 community-category domain walk opened a separate BadgerDB read
transaction for every label of the destination authority.** `Lookup` walks the
host most-specific-first — `a.b.c.cdn.example.com`, then `b.c.cdn.example.com`,
and so on, stopping before a bare TLD — and each of those probes called
`db.View`, which means each probe paid, inside badger:

- a heap-allocated `*badger.Txn`;
- `oracle.readTs()`, which takes badger's **process-wide oracle mutex** and then
  calls `readMark.Begin`, a **send on the watermark goroutine's single channel**;
- `txn.Discard()` → `doneRead` → `readMark.Done`, a **second send on that same
  single channel**.

Those two channel sends are the load-bearing term, and they are the reason this
cost is not visible in the policy benchmark that drives it: every concurrent
lookup in the process funnels through one watermark goroutine, so the walk was
multiplying a **process-wide serialization point** by the destination's label
count. An uncategorised host — the overwhelmingly common outcome, since the feed
covers a small slice of the namespace — always runs the walk to completion, so
the multiplier was paid in full on the common case, not the rare one.

The signature was unmistakable once measured. On a 5-label uncategorised host
the per-label shape got **slower** as goroutines were added: 4,214 ns at
`-cpu 1`, 6,334 ns at `-cpu 4`, **+50%**. That is negative scaling, not cache
pressure.

**The walk now runs on ONE transaction**, armed by `Lookup` for exactly the
reason the CHAOS-74 fault containment is already armed once for the whole walk,
and the key is now built once and re-sliced per label instead of converted per
label. Measured on the 5-label uncategorised host:

All wall-clock figures are medians of `-count=6` with the observed range in
parentheses; the frozen per-label shape and the shipped shape were measured in
the SAME run, so they share the machine's noise.

| | per-label (frozen) | one transaction | delta |
|---|---|---|---|
| wall clock, 1 goroutine | 4,214 ns (3,511–4,578) | 2,912 ns (2,672–3,223) | **−31%** |
| wall clock, 4 goroutines | 6,334 ns (5,471–7,073) | 3,342 ns (3,218–3,519) | **−47%** |
| scaling penalty 1→4 goroutines | +50% | +15% | — |
| allocations | 35/op | 27/op | **−23%** |
| bytes | 2,048 B/op | 1,456 B/op | **−29%** |
| mutex delay (300k lookups, 4-way) | 1,763 ms | 675 ms | **−62%** |
| block delay in the lookup path | 1.67 s | 0.606 s | **−64%** |
| block delay in `oracle.readTs` | 1.54 s | 0.579 s | **−62%** |

The single-goroutine `b.N` loop over the same host, which isolates the
allocation and key-conversion saving from the contention saving, moves
4,095 ns → 2,280 ns at `-cpu 1` (**−44%**) and 5,416 ns → 3,544 ns at `-cpu 4`
(**−35%**). The shallower shapes scale with their read count: `HitAtParent`
(2 reads) 1,554 → 1,132 ns with 17 → 15 allocs, `MissShallow` (2 reads)
1,719 → 1,332 ns with 14 → 12 allocs.

Behaviour is unchanged and asserted to be unchanged: a differential oracle runs
every host shape through the shipped walk and through a frozen in-tree copy of
the per-label walk and requires identical answers, including the error
classifications.

Collapsing the transaction is also a small **consistency** improvement of the
same kind the policy scan's effective-view and clock hoists already make: every
label of one categorisation decision is now read at one read timestamp, so a
feed `BulkWrite` landing mid-walk can no longer be half-visible to a single
answer.

---

## Finding 1 — one badger transaction per domain label, on the request path

### Root cause

`internal/catdb/catdb.go`. `Lookup` armed fault containment once for the whole
walk and then called `walk`, which called `getExact` once per label — and
`getExact` opened its own `c.db.View`:

```go
func (c *CommunityDB) getExact(domain string) (string, bool, error) {
	var cat string
	viewErr := c.db.View(func(txn *badger.Txn) error {
		item, getErr := txn.Get([]byte(domain))
		...
	})
```

The containment decision was already recorded, in the function's own comment:

> *CHAOS-74: containment is armed ONCE for the whole walk rather than per point
> lookup. The walk issues up to four or five badger reads for a deep hostname,
> and this runs on the proxy data path, so a guard per read would pay the
> defer/recover cost several times per request…*

The same argument applies verbatim to the transaction, and the transaction's
version of it is the **stronger** one, because a `defer/recover` costs the
calling goroutine and nobody else, whereas a `db.View` costs a lock and a
goroutine that every other request in the process is also waiting on. The
reasoning had been applied to one of the two per-read costs and not the other.

### Where the cost actually lands

Confirmed by reading badger v4.9.6, the pinned version:

- `DB.View` → `NewTransaction(false)` → `newTransaction` → `&Txn{...}` (one heap
  allocation) and `db.orc.readTs()`.
- `oracle.readTs()` (`txn.go:78`) takes `o.Lock()`, calls
  `o.readMark.Begin(readTs)`, unlocks, then `txnMark.WaitForMark`.
- `WaterMark.Begin` (`y/watermark.go:65`) is `w.markCh <- mark{...}` — a send to
  the single `WaterMark.process` goroutine.
- `Txn.Discard` (`txn.go:508`) → `orc.doneRead(txn)` → `readMark.Done` →
  `w.markCh <- mark{...}` — a second send to that same goroutine.

So a 5-label host cost **5 transactions, 5 oracle-mutex acquisitions and 10
sends on one channel**, where one answer needs one of each.

### Why no existing benchmark could see it

`policy_hostcat.go` memoizes this lookup once per rule scan, so the policy
benchmarks correctly show one `Lookup` per request and attribute its cost as a
single opaque call. The cost is *inside* that call, in a dependency, and it is
paid on a resource shared with every other goroutine in the process — which is
precisely the class of cost a single-threaded benchmark of the caller reports as
a flat per-op number. It took a parallel benchmark of the callee to make it
visible, and that is the general lesson this pass records: **a per-op number
that does not get worse with concurrency has not been tested for contention.**

### The allocation attribution

Allocation profile, 200,000 iterations of the 5-label walk (1,000,000 point
reads), `alloc_objects`, per point read:

| site | allocs/read | removed? |
|---|---|---|
| `badger.(*DB).getMemTables` | 2.00 | no — per read, badger's |
| `catdb.getExact` — `[]byte(domain)` | 1.25 | **yes** |
| `badger.(*levelHandler).getTableForKey` | 1.16 | no — per read, badger's |
| `badger.y.KeyWithTs` | 1.00 | no — per read, badger's |
| `badger.(*Txn).Get` — `new(Item)` | 1.00 | no — per read, badger's |
| `badger.(*DB).newTransaction` | 1.00 | **yes** |

Two of the ~7.4 allocations per read were ours to remove, and the measured
result matches the prediction exactly: a 5-label walk drops 8 allocations
(4 surplus transactions + 4 surplus key conversions), 35 → 27; a 2-label walk
drops 2, 14 → 12.

### The fix

49 lines of production change in one file, no new types, no new state, no
behaviour change.

`Lookup` opens one `db.View` inside the containment closure and hands the
transaction down. `walk` takes the transaction, builds the key **once**, and
strips a label by re-slicing that one backing array — every parent domain is a
suffix of the normalized host, so the per-label `[]byte(string)` conversion was
pure waste. `getExact` reads on the transaction it is given and no longer
reaches `c.db` at all.

The key reuse is safe against badger retaining it: `Txn.Get` copies the key into
a fresh allocation (`y.KeyWithTs`) before the read, the returned `Item` never
outlives the loop iteration that produced it, and the walk only ever **narrows**
the slice — it never writes a byte of the array. That is asserted, not asserted
to be obvious: see the key-reuse test below.

### Trade-offs

**Transaction lifetime.** One transaction is now open for the duration of the
walk (microseconds) instead of five sequential ones over the same span. A
badger read transaction holds a read mark, which gates how far
`readMark.DoneUntil` can advance and therefore what compaction may discard. The
total mark-held duration is unchanged — it is the same walk — while the number
of mark transitions drops from ten to two, so this is strictly less churn on the
watermark goroutine, not a longer hold.

**`db.IsClosed()` is now checked once per walk instead of once per label.**
Badger's `Close` does not wait for open read transactions, so a `Close` landing
mid-walk is an exposure window — but it is the same *kind* of window the old
code already had, since a single `View` already spanned `txn.Get` plus
`item.Value`. In the shipped shutdown order it is not reachable:
`community-db-close` (`main_shutdown.go`) runs after `proxy-server-shutdown` and
`tunnel-drain`, so no request-path walk is open when the store closes. And the
whole walk sits inside `storeguard.ContainFault`, so a fault during it latches
the store rather than killing the process — containment coverage is slightly
**wider** than before, because transaction creation is now inside the guard too.

**Readability.** `getExact` gained a parameter and lost a closure; `walk` works
on `[]byte` instead of `string` and uses `bytes.IndexByte` where it used
`strings.Index`/`strings.Contains`. Net production line count is roughly flat and
the control flow is unchanged.

### Risk

Low. The exported API is untouched (`Lookup(string) (string, bool)`), the only
caller is `policy_hostcat.go:186` through the unchanged signature, the walk
order and stop condition are byte-identical, and every error classification is
asserted against a frozen copy of the old code. The CHAOS-74 guard wall
(`TestCommunityDB_EveryBadgerAccessIsGuarded`) passes unmodified — the change
moves `c.db` access *into* `Lookup`'s containment closure and removes it from
the two helpers entirely.

### Gates added

Three guards, because the optimization can be undone three ways and only one of
them shows up in an allocation count.

| guard | file | suite |
|---|---|---|
| `TestCommunityLookup_MatchesPerLabelTxnWalk` — differential oracle over 20 host shapes (hits at every depth, misses, bare TLD, case/trailing-dot/port normalisation, A-label and U-label IDN, IP literals, empty label, empty host) against the frozen per-label walk, comparing the `LookupFaults` delta as well as the answer | `catdb_lookup_txn_test.go` | default |
| `TestCommunityLookup_DepthPrecedenceSurvivesKeyReuse` — a distinct category stored at every depth of one chain, so an answer taken from the wrong label is detectable rather than merely plausible | `catdb_lookup_txn_test.go` | default |
| `TestCommunityLookup_OpensOneTransactionPerWalk` — structural wall, in the CHAOS-74 guard-wall idiom: exactly one transaction opened in `Lookup`, zero in `walk` and `getExact`, counting every badger constructor and not just `View` | `catdb_lookup_txn_test.go` | default |
| `TestCommunityLookup_WalkIsNotTornByAConcurrentFeedWrite` — 2,000 lookups against 200 concurrent `BulkWrite`s under `-race`: every answer must be one of the two consistent states, and the store must report no fault | `catdb_lookup_txn_test.go` | default |
| `TestCommunityLookup_DeepAuthorityWalksEveryLabel` — a 12-label authority strips ten times before the stored label, past the shapes the benchmarks use | `catdb_lookup_txn_test.go` | default |
| `TestBenchGate_CommunityLookupAllocs` — 27 allocs/op measured, bound 31, **and** required to stay strictly below the frozen shape's | `catdb_lookup_txn_benchgate_test.go` | `-tags benchgate` |

The allocation gate is `benchgate`-tagged like every other gate in this
repository, and `./internal/catdb` was registered in the **three** workflows
that run the tagged command — `pr-fast-gate.yml` (the required path),
`qa-gate.yml` and `proxy-weekly-stress.yml` — plus the package list in
`docs/agent-context/workflows/verification.md`, in this same change. A gate CI
does not run is not a gate.

The correctness guards deliberately sit in the **default** suite rather than
behind the tag: they are cheap and load-independent, and the hazard this change
introduces is a correctness hazard (a shared key array, a shared read
timestamp), not a throughput one.

### The guards were validated by mutation, and two of them failed that test

A guard that passes proves nothing until it has been shown to fail. An
independent adversarial review of this change found that **two of the three
guards as first written passed against the very regressions they were named
for**, and both findings reproduced:

| guard, as first written | regression it missed | why |
|---|---|---|
| the structural wall | `c.db.NewTransaction(false)` + `defer txn.Discard()` per label inside `getExact` | it counted only call expressions whose selector was literally `View`. The CHAOS-74 guard wall does not catch it either, because `getExact` is a `guardedOnlyHelper` and its `c.db` reference is therefore exempt from the containment check |
| the differential oracle | a store error collapsed back into a clean miss — the pre-CHAOS-74 `if err != nil { return "", false }` that `getExact`'s own doc says must never return | `Lookup` answers `("", false)` from **all three** of its error arms *and* from a clean miss, so the answer alone cannot distinguish "not in the feed" from "the store failed to answer". Both shapes stayed at `("", false)` and the oracle stayed green |

Both are fixed and both fixes are now validated by the mutation that exposed
them. The wall counts every badger transaction constructor
(`View`/`Update`/`NewTransaction`/`NewTransactionAt`/`NewWriteBatch`/
`NewWriteBatchAt`/`NewStreamWriter`) and fails the `NewTransaction` mutation
with `getExact opens 1 badger transactions`. The oracle captures `LookupFaults`
around both calls and fails the collapse mutation with `Lookup("") counted 0
store fault(s); the frozen per-label walk counted 1 — the single-transaction
walk reclassified an error`. The oracle also now asserts that **at least one**
input in the matrix reaches the fault arm, so the fault comparison cannot
quietly become vacuous if that input is ever removed.

The third guard holds up:

| mutation | what fired |
|---|---|
| corrupt a byte of the shared key array that every later suffix contains (`key[len(key)-1] = 'x'`) | differential oracle, depth-precedence test, **and** the pre-existing `TestCommunityDB_Lookup_DomainWalking` |

Two further mutations were tried and discarded as invalid, which is itself worth
recording:

- `key[dot] = 'x'` is a **no-op**: the byte written is the dot, and every later
  probe is a suffix starting after it. An aliasing test has to corrupt a byte
  the later probes actually read, or it proves nothing.
- `key[dot:]` instead of `key[dot+1:]` **hangs** rather than answering wrongly —
  the slice stops shrinking, so the walk never terminates. The shipped code is
  safe from this by construction (`dot+1` advances at least one byte every
  iteration, so the key strictly shrinks and termination is guaranteed), and the
  pre-change code had the identical property, so this is not a new risk. It is
  noted because it is the one failure mode in this function that an answer-
  comparing oracle cannot express.

The review also corrected this change's own safety ARGUMENT without changing its
conclusion, and that correction is now in the code: `y.KeyWithTs` copies only
the **seek** key, while `Txn.Get` separately retains the caller's slice as
`item.key` — so the Item *does* alias the walk's array. The reuse is safe
because the Item never outlives its iteration and the walk only ever narrows the
slice, never writes into it. Citing `KeyWithTs` alone would have left a future
reader with a justification that does not support writing into the key in place.

### Review findings accepted but out of scope

- **A corrupt value-log entry reads as a hit with an empty category.**
  `yieldItemValue` deliberately swallows value-log read failures
  (badger `iterator.go`: *"Don't return error if we cannot read the value"*), so
  such an entry yields `("", true)` with the fault counter unmoved, contradicting
  `getExact`'s claim that `ErrKeyNotFound` is the only error treated as a miss.
  This is **pre-existing and identical before and after this change**, and it is
  unreachable for this store: `Open` leaves `ValueThreshold` at badger's 1 MB
  default, so a category string is always stored inline and the value-log path is
  never taken. Recorded, not fixed here — it is a different concern with a
  different blast radius.
- **`getExact` returns badger's errors unwrapped**, where `conventions.md` asks
  for `fmt.Errorf("context: %w", err)`. The pre-change code did the same, so
  wrapping would be a behaviour-neutral improvement to a log line and not part
  of this concern. Deliberately left.
- **The CHAOS-74 guard wall cannot see a transaction held in a non-`db` field.**
  It matches `recv.<field>` selectors, so a future method that stashed a `*Txn`
  on the struct and read on it outside a guard would pass. Containment is still
  enforced for the current shape (transitively, via `guardedOnlyHelpers`), and
  the new structural wall closes it for this walk specifically. Widening the
  guard wall itself belongs to that wall's owner.

`catdb_lookup_txn_bench_test.go` carries the frozen `lookupPerLabelTxn` /
`walkPerLabelTxn` / `getExactOwnTxn` copies and the before/after benchmarks. The
frozen copies are verbatim pre-change code, are not called by production, and
must not be "kept in sync" with `Lookup` — their whole value is that they do not
move. Their fidelity was checked rather than assumed: the pre-change production
run measured 5,616–5,797 ns on the 5-label walk and the frozen copy measured
5,367–5,694 ns in the same run, agreeing within one spread.

---

## Non-finding 1 — `internal/bandwidth` has no data-path caller

`internal/bandwidth` carries a token bucket (`tokenBucket.consume`), a policy
selector (`FindPolicy`, which allocates a label map walk) and `AllowBytes` — all
of which look like per-byte relay work and none of which is reached from the
relay. `bandwidth_health.go` already records that `AllowBytes` and `FindPolicy`
have no caller on the data path, and a grep confirms it at this revision.
Optimizing it would have been work on dead weight. Recorded so the next pass
does not re-derive it.

## Non-finding 2 — the per-read badger machinery that remains

Five of the ~7.4 allocations per point read are badger's own per-read cost:
`getMemTables` (2), `getTableForKey` (1.16), `y.KeyWithTs` (1) and the `Item`
(1). None of them is removable from outside badger without changing the access
pattern from point reads to a seeking iterator, which for a 2–5 probe walk would
trade five cheap `Get`s for one iterator allocation plus `Seek` — not obviously
cheaper, and a much larger change to a fault-contained data path. Not attempted,
and the gate's bound of 31 is set with that floor in mind.

## What was measured and found already appropriate

- **The hot paths with existing coverage.** 512 in-tree benchmarks and 123
  `TestBenchGate_` contracts across root and eight packages; the full gate
  command passes at this revision with 0 failures. The per-request shapes the
  previous passes tuned — canonical header keys, the policy decision line, the
  matched-conditions summary, the SSL_INNER line, the leaf-cert cache hit path,
  the scan-path gzip/deflate pools, the logstore flush, the relay and inspect
  buffers — are all still gated.
- **`policy_hostcat.go`'s memoization.** The per-request hoist of the category
  fusion, the normalized host, the effective view and the catSet key is correct
  and complete; the Layer-2 lookup it wraps is called once per request, which is
  why the cost found above had to be fixed inside the callee rather than by
  another hoist.
- **`catdb`'s walk order and stop condition.** Most-specific-first with a
  bare-TLD stop is the right shape: it is O(labels) point reads with an early
  exit on the first hit, and the common uncategorised case is bounded by the
  label count, which the destination-authority pre-caps in `handleRequest`
  already bound.

---

## Benchmark plan — what this review could not measure

1. **A real community feed.** Every number here comes from a store holding
   ~2,000 entries in a fresh LSM tree. A production feed is orders of magnitude
   larger with a deeper level structure, which changes the per-read term
   (`getTableForKey`, block cache hit rate) but not the per-transaction term the
   change removes. The transaction saving should therefore hold or improve; the
   *percentage* will shift. Worth re-measuring against a real feed snapshot.
2. **End-to-end, through `handleRequest`.** The gain was measured at the
   `catdb.Lookup` boundary. `BenchmarkPerfQual_ProxyHTTPForward` with a
   feed-backed store and category-group rules armed would show what fraction of
   a whole proxied request this is. It was not run because the perfqual harness
   does not currently wire a community store.
3. **A categorisation cache in front of Layer 2.** The walk is now as cheap as
   point reads allow, but repeated requests to the same destination still pay it
   in full, and real traffic is extremely top-heavy by host. A small bounded
   host→category memo with feed-generation invalidation is the next order-of-
   magnitude move, and it is a genuinely separate concern — cache invalidation
   against `BulkWrite` and the signed-feed activation path — so it was
   deliberately not bundled here.
4. **Contention at realistic concurrency.** `-cpu 4` on 4 vCPUs is the ceiling
   this machine can show. The watermark goroutine is a single serialization
   point, so the per-label shape's penalty should grow with core count; a
   32-core measurement would quantify how much of the appliance's concurrency
   this was capping.

---

## Residual risk

- **`db.IsClosed()` once per walk instead of once per label.** Analysed under
  *Trade-offs* above: unreachable in the shipped shutdown order, same kind of
  window as the pre-change code, and inside `ContainFault` either way.
- **The frozen baseline copies can rot in the other direction.** They are
  pinned by comment and by the differential oracle that consumes them; if a
  future change to `Lookup` is *meant* to alter an answer, the oracle will fail
  and the frozen copy must be retired deliberately rather than edited to match.
- **The 31-allocation bound is badger-version-coupled.** Five of the remaining
  27 allocations per read are badger's; a badger upgrade can move the number in
  either direction. The structural wall
  (`TestCommunityLookup_OpensOneTransactionPerWalk`) exists precisely so the
  property survives a bound that has to be re-baselined.
- **Measurement environment.** 4 vCPU shared Xeon. Wall-clock numbers carry
  normal noise and are quoted as medians of 5 with ranges available in the
  verification record; the allocation, mutex-delay and block-delay numbers are
  the stable signals and are the ones gated.
