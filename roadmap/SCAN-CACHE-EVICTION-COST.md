# Scan-cache eviction cost — measurement and a rejected optimization

> Status: **MEASURED, NO IMPLEMENTATION CHANGE (2026-10-11).** Verdict: the scan
> cache's eviction stall is real, grows linearly with the operator's
> `cache_size`, and reaches 123 ms at `cache_size: 1000000` — but at the shipped
> 10 000 default it amortizes to ~152 ns per Set against a scan that costs
> milliseconds, so it is not a bottleneck. The obvious layout fix (holding
> entries by value rather than behind a pointer) was implemented, measured
> against an interleaved baseline, and **not shipped** — because the result is
> mixed and immaterial (tens of nanoseconds either way against a millisecond
> scan), not because it is harmful. An earlier revision of this note claimed it
> "loses it again on the far more frequent Get and Set paths"; that framing did
> not survive re-measurement and is retracted below. This change
> therefore ships the missing benchmarks and this record, and leaves
> `internal/hashcache` as it was.

## Question

`internal/hashcache` is the SHA-256 scan-result cache consulted once per scanned
object and written once per scan miss, so its `Set` path sits behind every
ClamAV/YARA verdict. It had **zero benchmark coverage**. `evictLocked` sweeps the
whole map for expired entries, synchronously, on the `Set` path, holding the
cache's **exclusive write lock** — the same shape the auth cache was fixed for
under CHAOS-57 ("the expired-entry scan is O(cache) whenever nothing has
expired … and it runs holding the process-wide auth mutex. Measured at 64 µs per
insertion at capacity", `store.go`). Is the scan cache's instance a live
problem?

## Method

- **Benchmarks:** `internal/hashcache/hashcache_evict_bench_test.go`, added by
  this change. In-package, because the stall is a property of `evictLocked` and
  the unexported `entries` map. Caches are seeded by writing `entries` directly;
  an already-evicted cache is no longer at capacity, so each iteration rebuilds
  one with the timer stopped. Exactly one fixture is live at a time — building
  all `b.N` of them up front retains `b.N x maxSize` entries, which at
  `-benchtime 1s` is ~2 GB for the 10 000 case, enough to distort the figures
  through GC pressure and to exhaust a constrained runner (CodeRabbit, PR #1604;
  the absolute figures above are post-fix and ~30 % lower than the first
  revision's).
- **Before/after:** the shipped pointer layout vs the by-value candidate,
  compiled as separate test binaries from a `git worktree`, with byte-identical
  benchmark sources except the one line that constructs an entry
  (`&hashCacheEntry{…}` vs `hashCacheEntry{…}`). `hashcache.go`'s logic is
  identical to `fbf6a37`'s on both sides — only the map's value type differs.
  The table below is the **post-fix** run, with the corrected fixture harness
  compiled into both sides; the pre-fix run it replaces is kept only in the
  retraction, for the comparison. Binaries alternated round-by-round (A,B,A,B…) over 8
  rounds at `-benchtime 300ms`, compared with `benchstat`.
- **Decomposition:** the sweep and the 25 % delete batch were timed separately
  to attribute the cost before changing anything.

## Results — the cost that exists

`evictLocked`, one call, cache full, nothing expired (the state a busy gateway
holds):

| `cache_size` | one `evictLocked` | recurs every | amortized per Set |
|---|---|---|---|
| 10 000 | 0.38 ms | 2 500 inserts | **152 ns** |
| 100 000 | 7.39 ms | 25 000 inserts | **296 ns** |
| 1 000 000 | **122.57 ms** | 250 000 inserts | **490 ns** |

The amortized column is one call's cost divided by the `maxSize/4` inserts it
makes room for. It is this implementation's own per-Set cost and is **not** the
same quantity as the base-vs-candidate *saving* in the rejection table below;
an earlier revision of this note conflated the two and understated the column
by roughly 9x (CodeRabbit, PR #1604).

Decomposed at `cache_size: 10000`: the **expiry sweep is ~71 % of the call**,
the 25 % delete batch the rest. The sweep is O(maxSize) because proving that
nothing is expired means looking at everything; it is dominated not by the
comparison but by one random-access dereference of `*hashCacheEntry` per entry.

Two further properties worth having pinned:

- Eviction gets **slower the more reclaimable the cache is** — 0.68 ms at 10 000
  fully expired against 0.38 ms with none expired — because a sweep that finds
  expired entries also deletes them. This is the opposite of the intuitive
  direction.
- The stall is **system-wide, not local**: `BenchmarkGet_ParallelDuringEviction`
  shows concurrent reads at ~641 ns/op against ~205 ns/op uncontended, i.e. the
  write lock makes every other scanner's lookup pay. Read the `%hit` metric
  before drawing a ratio from that pair: the contended run reads only **a few
  percent hits** against the uncontended run's **100 %** (4.7 % at
  `-benchtime 500ms`, 1.4 % at `1s`, falling as the writer displaces more),
  because the continuously-writing goroutine evicts the seeded keys. The pair
  therefore *indicates* contention rather than isolating it. It does not flatter the contended side —
  a miss costs ~24 ns against a hit's ~75 ns, so the changed mix pushes the
  contended figure DOWN, and it is still 3x slower while doing the cheaper work
  — but the raw ratio is not attributable to lock contention alone.
  A `writes` metric reports how many Sets landed *inside* the timed window, so
  a run that never actually contended is visible rather than silent: at
  `-benchtime 1x` the window is short enough that `%hit` is still 100 % and the
  figure means nothing. Read both metrics before quoting the ns/op.

`cache_size` is an operator YAML knob (`config.go`) that validation only
**floors** (non-positive → 10 000, `scanning_startup_config.go`) and never caps.
An operator who raises it buys a proportionally larger stall with nothing
warning them.

## Results — why no change ships

Holding entries in the map **by value** instead of behind a pointer removes the
per-entry dereference from the sweep and the per-`Set` heap allocation of the
entry. It does what it was meant to do. Nothing ships anyway, but **not for the
reason an earlier revision of this note gave** — see the retraction below.

Measured post-fix (corrected fixture harness compiled identically into both
sides), separate binaries from a `git worktree`, 8 alternating rounds,
`benchstat`:

| benchmark | base | candidate | delta |
|---|---|---|---|
| `EvictLocked_NothingExpired_10k` | 356.2 µs | 316.0 µs | **−11.30 %** (p=0.000) |
| `EvictLocked_NothingExpired_100k` | 7.060 ms | 4.821 ms | **−31.72 %** (p=0.000) |
| `EvictLocked_HalfExpired_10k` | 461.0 µs | 337.5 µs | **−26.80 %** (p=0.000) |
| `EvictLocked_AllExpired_10k` | 590.0 µs | 461.4 µs | **−21.80 %** (p=0.000) |
| `SetChurn_AtCapacity_10k` | 558.8 ns | 533.4 ns | **−4.55 %** (p=0.010) |
| `SetChurn_AtCapacity_100k` | 760.6 ns | 837.9 ns | **+10.17 %** (p=0.028) |
| `Get_Hit` | 84.60 ns | 93.19 ns | ~ (p=0.279) |
| `Get_Miss` | 25.39 ns | 33.92 ns | **+33.60 %** (p=0.002) |
| `Get_Parallel` | 217.9 ns | 192.1 ns | ~ (p=0.161) |
| `Get_ParallelDuringEviction` | 598.6 ns | 627.8 ns | ~ (p=0.083) |
| `SetChurn` allocs/op | 3 | 2 | −33 % (p=0.000) |
| `SetChurn_10k` B/op | 115.5 | 35.0 | −69.70 % (p=0.000) |

### Retraction: "correcting the harness can only shrink the candidate's wins"

An earlier revision of this note carried the pre-fix deltas plus that claim, on
the reasoning that both sides compiled the same faulty harness so its distortion
cancelled. **That was wrong, and CodeRabbit was right to refuse it** (PR #1604):
the two layouts respond differently to retained fixtures, because the pointer
build allocates one 88-byte entry per element while the value build stores them
inline, so `b.N × maxSize` retention gives them materially different GC
profiles. Same harness is not the same distortion.

Re-measuring moved the wins in **both** directions and changed two conclusions:

| | pre-fix | post-fix |
|---|---|---|
| `EvictLocked_NothingExpired_10k` | −9.50 % | −11.30 % (win **grew**) |
| `EvictLocked_NothingExpired_100k` | −27.97 % | −31.72 % (win **grew**) |
| `EvictLocked_HalfExpired_10k` | −40.18 % | −26.80 % (win shrank) |
| `SetChurn_AtCapacity_10k` | ~ | −4.55 % (now a **win**) |
| `Get_ParallelDuringEviction` | +13.39 % | **~ (n.s.)** — regression gone |

Netting the eviction saving against the per-`Set` delta over the inserts each
eviction makes room for, post-fix:

- `cache_size: 10000` — **+41.5 ns per Set** (favours the candidate)
- `cache_size: 100000` — **+12.3 ns per Set** (favours the candidate)

So the earlier framing — "it makes the frequent operations slower to speed up a
rare one, and nets to zero", with `Get_ParallelDuringEviction` as "the clearest
refutation" — **does not survive the corrected measurement**. The netting is
weakly positive at both sizes and that reader-throughput regression is not
significant. Both of those were load-bearing in the old argument and both are
withdrawn.

### What the numbers actually support

What survives against the candidate is narrower: `Get_Miss` **+33.60 %**
(p=0.002) and `SetChurn_AtCapacity_100k` **+10.17 %** (p=0.028). `hashCacheEntry`
is 88 bytes, so a value map copies 88 bytes where a pointer map copied 8 — on
every `Get`, a miss included, which must zero the destination — and its bucket
array is an order of magnitude larger. What survives for it is the eviction
sweep (11–32 % faster), one fewer allocation per `Set`, and 70 % less `B/op` at
the default size.

That is a **mixed and immaterial result, not a refutation**. In absolute terms
the whole argument is tens of nanoseconds: `Get_Miss` costs +8.5 ns, `Set` at
`cache_size: 100000` costs +77 ns, the eviction saving returns 16–90 ns per
`Set`. Every one of those sits four to five orders of magnitude below the
ClamAV/YARA scan that a `Set` follows and a `Get` precedes.

So the verdict is unchanged and its reasoning is not: there is **no performance
case for the layout change, and none against it either**. Rewriting how a
shared cache stores its entries — touching `Get`, `Set`, `SetTTLUnless`,
`Clear` and a white-box test's mutation semantics — to buy a result this small
and this mixed is churn without a payoff. The allocation reduction is the one
non-noise argument in its favour (GC pressure lands in the heap the proxy's
latency-critical goroutines share, the point
[scanbuffer](../internal/secscan/scanbuffer.go) makes for its own path); it is
not enough on its own, and it is the thing to re-examine first if this is ever
revisited.

### Contention, measured like-for-like

`BenchmarkGet_ParallelDuringEviction` compared against `BenchmarkGet_Parallel`
cannot isolate lock contention, because the writer displaces the seeded keys and
the two sides end up reading different keyspaces (100 % hits against a few
percent). A control pair suggested by CodeRabbit (PR #1604) fixes that by
pinning **both** sides to an `m`-prefixed keyspace nothing ever inserts, so
every lookup is a guaranteed miss and the read workload is identical:

| benchmark | run A | run B | %hit |
|---|---|---|---|
| `Get_ParallelMissOnly` | 190.5 ns | 225.0 ns | 0 |
| `Get_ParallelMissOnlyDuringEviction` | 381.0 ns | 612.3 ns | 0 |
| ratio | 2.0x | 2.7x | |

**2.0–2.7x across runs**, with the workload held fixed — so the slowdown is
attributable to the writer rather than to a shifting hit rate. The spread is
why two runs are quoted rather than one number: the absolute figures move with
how fast the writer trips eviction and with scheduling, so treat the ratio as
an order of magnitude, not a constant. Read the pair as a control, not a
replacement: it measures the cheaper miss path, and the writer's cost here is
eviction plus ordinary `Set` work rather than eviction alone. What it
establishes is that the slowdown survives holding the read workload fixed,
which is more than the confounded original pair could show.

## Verdict and what would actually help

At the shipped `cache_size: 10000` default, **leave `evictLocked` alone**. A Set
happens only on a scan MISS, and a miss then costs a ClamAV/YARA scan measured
in milliseconds; 152 ns of amortized eviction is noise against the work it
guards. Optimizing it would be spending complexity on a path that is not the
bottleneck.

If production telemetry ever shows this stall mattering — the benchmarks added
here make it measurable, and `culvert_scan_cache_size` already exposes the
occupancy that drives it — the fix is **not** a layout change. The two
candidates, both of which change observable behaviour and so need their own
change and their own review:

1. **Bounded eviction** (an examination window and delete batch capped by a
   constant rather than a fraction of `maxSize`), which makes the lock hold O(1)
   in `cache_size`. It gives up the "no expired entry survives an eviction"
   invariant that `TestSet_EvictsExpiredFirst` deliberately pins, because an
   early exit cannot know what it did not look at. Dropping a live entry is not
   free here — it costs a full re-scan — so such a design must still prefer
   expired entries within its window, as `internal/authstate` and the
   CHAOS-57 auth-cache policy do for the same reason.
2. **Sharding** the map, which keeps the invariant per shard and reduces both
   the hold time and the share of traffic it blocks to 1/N, at the cost of a
   real concurrency-contract change.

A cheaper, non-structural mitigation worth considering on its own: **cap or warn
on `cache_size`** at startup, so the 123 ms cliff at 1 000 000 is not reachable
by a config edit alone.

## Scope

Benchmarks and documentation only. `internal/hashcache/hashcache.go` keeps its
existing behaviour; the only edit to it is the measured cost table on
`evictLocked` recording what the numbers above found, so the next reader does not
re-derive them or retry the rejected layout change.
