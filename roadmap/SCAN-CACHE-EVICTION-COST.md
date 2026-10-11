# Scan-cache eviction cost — measurement and a rejected optimization

> Status: **MEASURED, NO IMPLEMENTATION CHANGE (2026-10-11).** Verdict: the scan
> cache's eviction stall is real, grows linearly with the operator's
> `cache_size`, and reaches 115 ms at `cache_size: 1000000` — but at the shipped
> 10 000 default it amortizes to ~25 ns per Set against a scan that costs
> milliseconds, so it is not a bottleneck. The obvious layout fix (holding
> entries by value rather than behind a pointer) was implemented, measured
> against an interleaved baseline, and **rejected**: it buys 9–40 % on the stall
> and loses it again on the far more frequent `Get` and `Set` paths. This change
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
  the unexported `entries` map. Caches are seeded by writing `entries` directly
  and built outside the timed region: an already-evicted cache is no longer at
  capacity, so each iteration needs a fresh full one.
- **Before/after:** parent `fbf6a37` vs the candidate, compiled as separate test
  binaries from a `git worktree`, with byte-identical benchmark sources except
  the one line that constructs an entry (`&hashCacheEntry{…}` vs
  `hashCacheEntry{…}`). Binaries alternated round-by-round (A,B,A,B…) over 8
  rounds at `-benchtime 300ms`, compared with `benchstat`.
- **Decomposition:** the sweep and the 25 % delete batch were timed separately
  to attribute the cost before changing anything.

## Results — the cost that exists

`evictLocked`, one call, cache full, nothing expired (the state a busy gateway
holds):

| `cache_size` | one `evictLocked` | recurs every | amortized per Set |
|---|---|---|---|
| 10 000 | 0.55 ms | 2 500 inserts | ~25 ns |
| 100 000 | 8.51 ms | 25 000 inserts | ~102 ns |
| 1 000 000 | **115 ms** | 250 000 inserts | ~115 ns |

Decomposed at `cache_size: 10000`: the **expiry sweep is 496 µs of the 698 µs
(71 %)**, the 25 % delete batch 235 µs. The sweep is O(maxSize) because proving
that nothing is expired means looking at everything; it is dominated not by the
comparison but by one random-access dereference of `*hashCacheEntry` per entry.

Two further properties worth having pinned:

- Eviction gets **slower the more reclaimable the cache is** — 1.08 ms at 10 000
  fully expired against 0.55 ms with none expired — because a sweep that finds
  expired entries also deletes them. This is the opposite of the intuitive
  direction.
- The stall is **system-wide, not local**: `BenchmarkGet_ParallelDuringEviction`
  shows concurrent reads at ~554 ns/op against ~248 ns/op uncontended, i.e. the
  write lock makes every other scanner's lookup pay.

`cache_size` is an operator YAML knob (`config.go`) that validation only
**floors** (non-positive → 10 000, `scanning_startup_config.go`) and never caps.
An operator who raises it buys a proportionally larger stall with nothing
warning them.

## Results — why no change ships

Holding entries in the map **by value** instead of behind a pointer removes the
per-entry dereference from the sweep and the per-`Set` heap allocation of the
entry. It does what it was meant to do, and is still not worth shipping
(`benchstat`, n=8 interleaved):

| benchmark | base | candidate | delta |
|---|---|---|---|
| `EvictLocked_NothingExpired_10k` | 654.0 µs | 591.9 µs | **−9.50 %** (p=0.028) |
| `EvictLocked_NothingExpired_100k` | 9.110 ms | 6.562 ms | **−27.97 %** (p=0.000) |
| `EvictLocked_HalfExpired_10k` | 920.2 µs | 550.4 µs | **−40.18 %** (p=0.000) |
| `EvictLocked_AllExpired_10k` | 1116.8 µs | 766.5 µs | **−31.37 %** (p=0.000) |
| `SetChurn_AtCapacity_10k` | 568.3 ns | 551.0 ns | ~ (p=0.234) |
| `SetChurn_AtCapacity_100k` | 787.6 ns | 893.1 ns | **+13.40 %** (p=0.000) |
| `Get_Hit` | 84.66 ns | 91.55 ns | ~ (p=0.105) |
| `Get_Miss` | 24.82 ns | 35.73 ns | **+43.98 %** (p=0.000) |
| `Get_Parallel` | 212.1 ns | 190.2 ns | ~ (p=0.195) |
| `Get_ParallelDuringEviction` | 621.1 ns | 704.2 ns | **+13.39 %** (p=0.005) |
| `SetChurn` allocs/op | 3 | 2 | −33 % (p=0.000) |
| `SetChurn_10k` B/op | 115.5 | 36.5 | −68 % (p=0.000) |

The regressions are the reason. `hashCacheEntry` is 88 bytes, so a value map
copies 88 bytes where a pointer map copied 8 — on **every** `Get`, including a
miss, which must zero the destination (hence `Get_Miss` +44 %) — and its bucket
array is an order of magnitude larger, which is what costs `Set` 13 % at
`cache_size: 100000`. Netting the eviction saving against the per-`Set`
regression over the inserts each eviction makes room for:

- `cache_size: 10000` — **+42 ns per Set** (marginally positive)
- `cache_size: 100000` — **−3.6 ns per Set** (a wash, slightly negative)

So the change makes the **frequent** operations slower to speed up a **rare**
one, and nets to zero. `Get_ParallelDuringEviction` is the clearest refutation:
the stall itself got 9–28 % shorter and aggregate reader throughput still got
13 % **worse**, because the per-`Get` copy cost outweighs the shorter block.

It was reverted. The benchmarks that caught it are what this change ships.

## Verdict and what would actually help

At the shipped `cache_size: 10000` default, **leave `evictLocked` alone**. A Set
happens only on a scan MISS, and a miss then costs a ClamAV/YARA scan measured
in milliseconds; 25 ns of amortized eviction is noise against the work it
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
on `cache_size`** at startup, so the 115 ms cliff at 1 000 000 is not reachable
by a config edit alone.

## Scope

Benchmarks and documentation only. `internal/hashcache/hashcache.go` keeps its
existing behaviour; the only edit to it is the measured cost table on
`evictLocked` recording what the numbers above found, so the next reader does not
re-derive them or retry the rejected layout change.
