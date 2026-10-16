# Scan-cache eviction cost — measurement and a rejected optimization

**All absolute figures were measured on a loaded 4-vCPU host (load 12–14);
re-measure on an idle host before using them for a design decision.**

> Status: **MEASURED, NO IMPLEMENTATION CHANGE (2026-10-11; re-measured
> 2026-10-16 with production-shaped keys).** Verdict: the scan cache's eviction
> stall is real and grows linearly with the operator's `cache_size`. It reaches
> roughly 150-300 ms at `cache_size: 1000000`, a case the committed benchmarks
> now cover, in the busy steady state (nothing expired). The all-expired case
> costs more and is not yet bounded at large sizes. At the shipped 10 000
> default the amortized cost is ~218 ns per Set. That is small relative to the
> scan miss it follows **when a ClamAV or YARA engine is active**. With no engine
> configured, a Set follows only a SHA-256 of the body, and that comparison is
> unmeasured. The reader tail-latency impact is **UNMEASURED**,
> pending a contention run on an idle host: hits also wait behind the lock
> hold. The obvious
> layout fix (holding entries by value rather than behind a pointer) was
> implemented, measured against an interleaved baseline, and **not shipped**.
> The reason is that the result is mixed and immaterial, not that it is harmful:
> the eviction sweep gets faster, the per-`Set` cost does not change
> significantly, and a `Get` miss gets slower. An earlier revision of this note
> claimed it "loses it again on the far more frequent Get and Set paths"; that
> framing did not survive re-measurement and is retracted below. This change
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
  the unexported `entries` map. Run with
  `go test ./internal/hashcache/ -run XXX -bench . -benchmem`. The
  `EvictLocked_NothingExpired_1M` case is skipped under `-short`.
- **Production-shaped keys.** Production reaches this cache only through
  `SHA256Hex`, so every real key is 64 hex characters, and map hashing and
  deletion cost grow with key length. The first revision seeded short keys
  (`k0`, `k1`, …) and so measured a cheaper map: on the same host, 64-byte keys
  alone raised `AllExpired_10k` from ~0.67 ms to ~0.84 ms (Codex, PR #1604).
  Fixtures and reader keyspaces now use real `SHA256Hex` digests, built once
  and memoized. Retention is bounded by the largest fixture (1 000 000 keys,
  ~80 MB), not by `b.N`. Keys minted inside a timed loop (churn inserts, the
  contention writer) are 64-hex keys built from a counter, so the timed loop
  pays no SHA-256.
- **Fixture lifetime:** an already-evicted cache is no longer at capacity, so
  each iteration rebuilds one with the timer stopped, and exactly one fixture is
  live at a time. The first revision built all `b.N` up front. That retains
  `b.N x maxSize` entries, ~2 GB for the 10 000 case at `-benchtime 1s`, which
  distorts the figures through GC pressure (CodeRabbit, PR #1604).
- **Before/after:** the shipped pointer layout against the by-value candidate,
  compiled as separate test binaries. The candidate differs only in the map's
  value type (`map[string]hashCacheEntry`, storing `hashCacheEntry{…}` instead of
  `&hashCacheEntry{…}` in `Set`, `SetTTLUnless` and the bench fixture, and the
  one white-box test that mutates entries writing them back). The binaries ran
  alternately, round by round (A,B,A,B…), for 8 rounds of every benchmark at
  `-benchtime 300ms -benchmem`, and were compared with `benchstat`.
- **Host caveat (2026-10-16 run).** The only host available was a shared 4-vCPU
  container with a load average of ~12-14 for the whole run, roughly 3x
  oversubscribed. Spreads are wide (up to ±94 %). The interleaving keeps the A/B
  comparison fair, but treat the absolute figures as upper-biased. The parallel
  benchmarks are the most affected, because they assume idle cores.
- **Harness changes after the 2026-10-16 run (not re-measured).** The
  benchmarks now finish any setup-triggered GC cycle before timing
  (`runtime.GC()` per eviction fixture, and `startTimedAfterGC` everywhere
  else). The contention benchmarks also guarantee and count in-window
  evictions. The figures below predate both changes. The next idle-host run
  must re-measure them.

## Results — the cost that exists

`evictLocked`, one call, cache full, in the busy steady state (nothing
expired). This is **not** the worst case (see below). Taken from a dedicated
10-sample run of the shipped layout
(`-benchtime 300ms -count 10`), with the A/B baseline medians beside it:

| `cache_size` | one `evictLocked` (10 samples) | A/B baseline median | recurs every | amortized per Set |
|---|---|---|---|---|
| 10 000 | 0.54 ms (±16 %) | 0.49 ms | 2 500 inserts | **~218 ns** |
| 100 000 | 10.4 ms (±20 %) | 12.6 ms | 25 000 inserts | **~414 ns** |
| 1 000 000 | **150 ms** (±53 %) | 295 ms (±94 %) | 250 000 inserts | **~600 ns** |

The amortized column is one call's cost (the 10-sample median) divided by the
`maxSize/4` inserts it makes room for. It is this implementation's own per-Set
cost and is **not** the same quantity as the base-vs-candidate difference in the
rejection table below. An earlier revision conflated the two and understated
the column by roughly 9x (CodeRabbit, PR #1604). The 1 000 000 figure is the
noisiest. On this host, read it as "on the order of 150-300 ms" for a single
lock hold.

Two further properties worth having pinned:

- Eviction gets **slower the more reclaimable the cache is**: at 10 000 it takes
  0.54 ms with nothing expired, 0.63 ms with half expired and 0.94 ms with all
  expired (10-sample medians). A sweep that finds expired entries also deletes
  them. This is the opposite of the intuitive direction. It makes the realistic
  worst case, a full cache idle past its TTL and then one Set, HIGHER than the
  table above. That case is not yet bounded at 100 000 or 1 000 000:
  `BenchmarkEvictLocked_AllExpired_100k` and `_1M` exist to bound it on an idle
  host, and no figure from them is quoted here.
- The stall is **system-wide by construction**: `evictLocked` runs under the
  exclusive write lock, so every concurrent `Get` waits for it, which is a
  property of the code, not of a benchmark. *How much* that costs readers is
  what the contention benchmarks try to show. On this oversubscribed host they
  could not show it; see "Contention" below.

`cache_size` is an operator YAML knob (`config.go`) that validation only
**floors** (non-positive → 10 000, `scanning_startup_config.go`) and never caps.
An operator who raises it buys a proportionally larger stall with nothing
warning them.

## Results — why no change ships

Holding entries in the map **by value** instead of behind a pointer removes the
per-entry dereference from the sweep and the per-`Set` heap allocation of the
entry. It does what it was meant to do. Nothing ships anyway, but **not for the
reason an earlier revision of this note gave** — see the retraction below.

Measured 2026-10-16 with 64-byte keys and the corrected fixture harness compiled
identically into both sides. Separate binaries, 8 alternating rounds at
`-benchtime 300ms`, `benchstat` (the host caveat above applies):

| benchmark | base | candidate | delta |
|---|---|---|---|
| `EvictLocked_NothingExpired_10k` | 490.1 µs | 444.8 µs | **−9.24 %** (p=0.010) |
| `EvictLocked_NothingExpired_100k` | 12.589 ms | 5.320 ms | **−57.74 %** (p=0.000) |
| `EvictLocked_NothingExpired_1M` | 295.4 ms | 113.7 ms | **−61.53 %** (p=0.001) |
| `EvictLocked_HalfExpired_10k` | 689.7 µs | 592.1 µs | **−14.15 %** (p=0.015) |
| `EvictLocked_AllExpired_10k` | 863.4 µs | 864.7 µs | ~ (p=0.878) |
| `SetChurn_AtCapacity_10k` | 850.4 ns | 758.8 ns | ~ (p=0.279) |
| `SetChurn_AtCapacity_100k` | 1.232 µs | 1.377 µs | ~ (p=0.382) |
| `Get_Hit` | 124.0 ns | 139.0 ns | ~ (p=0.099) |
| `Get_Miss` | 37.70 ns | 48.05 ns | **+27.44 %** (p=0.028) |
| `Get_Parallel` | 174.4 ns | 235.9 ns | ~ (p=0.130) |
| `Get_ParallelDuringEviction` | 95.46 ns | 108.35 ns | ~ (p=0.328) |
| `Get_ParallelMissOnly` | 67.50 ns | 85.32 ns | ~ (p=0.130) |
| `Get_ParallelMissOnlyDuringEviction` | 85.19 ns | 90.68 ns | ~ (p=0.442) |
| `SetChurn` allocs/op (both sizes) | 2 | 1 | −50 % (p=0.000) |
| `SetChurn_10k` B/op | 164.0 | 83.5 | −49.09 % (p=0.000) |

The net per-`Set` effect is read directly from `SetChurn_AtCapacity_*`. Those
benchmarks Set continuously into a full cache and pay one `evictLocked` every
`maxSize/4` inserts, so their ns/op already includes the amortized eviction
saving. Do not add the standalone `EvictLocked_*` saving on top; an earlier
revision did, counting it twice (Codex, PR #1604). With 64-byte keys neither
size shows a significant per-`Set` difference: −91.6 ns at 10 000 and +145 ns
at 100 000, both n.s.

### What the numbers actually support

What survives against the candidate is `Get_Miss` **+27.44 %** (p=0.002 in the
short-key run, p=0.028 here). `hashCacheEntry` is 88 bytes, so a value map copies
88 bytes where a pointer map copied 8 on every `Get`, a miss included (which
must zero the destination), and its bucket array is an order of magnitude
larger. What survives for it is a faster eviction sweep: 9-62 % faster with
nothing or half expired, which matters most at large `cache_size` and does not
change when everything has expired. It also makes one fewer allocation per
`Set` and uses half the `B/op` at the default size.

That is a **mixed and immaterial result, not a refutation**. In absolute terms,
at the shipped default, `Get_Miss` costs +10 ns and the `Set` difference is not
distinguishable from noise. With a ClamAV or YARA engine active, both sit
four to five orders of magnitude below the scan that a `Set` follows and a
`Get` precedes. With no engine configured, there is no scan to compare against
(see the verdict). The eviction saving
is the only large number, and only at operator-raised sizes: the
`cache_size: 1000000` stall shrinks from roughly 150-300 ms to roughly 115 ms. A
real fix for that case is bounding or sharding the eviction (below), not a
constant-factor layout change.

So the verdict is unchanged and so is its reasoning: there is **no performance
case for the layout change at the default size, and none against it either**.
Rewriting how a shared cache stores its entries — touching `Get`, `Set`,
`SetTTLUnless`, `Clear` and a white-box test's mutation semantics — to buy a
result this small and this mixed is churn without a payoff. The allocation
reduction is the one non-noise argument in its favour at the default (GC
pressure lands in the heap the proxy's latency-critical goroutines share, the
point [scanbuffer](../internal/secscan/scanbuffer.go) makes for its own path).
It is not enough on its own, and it is the thing to re-examine first if this is
ever revisited.

### Contention

`Get_ParallelDuringEviction` compared against `Get_Parallel` cannot isolate lock
contention. The writer displaces the seeded keys, so the two sides read
different keyspaces: 100 % hits against a median 6.6 % here. The miss-only
control pair (suggested by CodeRabbit, PR #1604) pins **both** sides to a
keyspace nothing ever inserts, so the read workload is identical.

On the 64-byte-key run neither pair shows a clear slowdown. The confounded pair
ran *faster* with the writer (95.5 ns against 174.4 ns, base medians), because
the contended run reads almost only cheap misses. The control pair's medians are
85.2 ns against 67.5 ns (1.26x), but its per-round ranges overlap heavily
(41.7-93.4 ns without the writer, 60.2-188.6 ns with it). This run therefore
**does not establish** the reader slowdown. The 2.0-2.7x control ratio recorded
earlier (short keys, a less loaded host; see "Historical measurements") was not
reproduced. On a host whose four cores are already ~3x oversubscribed, four
reader goroutines plus a writer are not a meaningful contention experiment.
Re-run the pair on an idle host before quoting any reader-slowdown ratio. The
stall itself is not in doubt: it is the exclusive lock hold measured above.

## Historical measurements (short keys, superseded)

Kept so the corrections stay traceable. These figures used 2-6 character keys
(`k0`, …) on a less loaded host, so they **understate** production cost. Do not
quote them as current.

- **Cost table (2026-10-11, short keys):** one `evictLocked` took 0.38 ms at
  10 000, 7.39 ms at 100 000 and 122.57 ms at 1 000 000. The 1 000 000 figure
  came from a run that was not committed as a benchmark. That gap is why
  `EvictLocked_NothingExpired_1M` now exists (Codex, PR #1604). Fully expired at
  10 000 took 0.68 ms. Decomposed at 10 000, the expiry sweep was ~71 % of the
  call and the 25 % delete batch the rest.
- **Layout A/B (short keys, corrected harness):** eviction 11.30-31.72 % faster;
  `SetChurn` −4.55 % at 10 000 (558.8 → 533.4 ns) and +10.17 % at 100 000
  (760.6 → 837.9 ns); `Get_Miss` +33.60 % (25.39 → 33.92 ns);
  `Get_ParallelDuringEviction` n.s. (p=0.083).
- **Contention control (short keys):** `Get_ParallelMissOnly` 190.5 / 225.0 ns
  against `Get_ParallelMissOnlyDuringEviction` 381.0 / 612.3 ns, a 2.0-2.7x
  ratio. The contended mixed-hit run read 4.7 % hits at `-benchtime 500ms` and
  1.4 % at `1s`.

### Retraction: "correcting the harness can only shrink the candidate's wins"

An earlier revision carried the pre-fix deltas plus that claim, reasoning that
both sides compiled the same faulty harness, so its distortion cancelled.
**That was wrong, and CodeRabbit was right to refuse it** (PR #1604). The two
layouts respond differently to retained fixtures: the pointer build allocates
one 88-byte entry per element, while the value build stores them inline, so
`b.N × maxSize` retention gives them materially different GC profiles. Same
harness is not the same distortion. Re-measuring moved the wins in **both**
directions: the 10 000 and 100 000 nothing-expired wins grew, the half-expired
win shrank, `SetChurn_10k` became a win, and the `Get_ParallelDuringEviction`
"regression" (+13.39 % pre-fix) was not significant. The old framing, "it makes
the frequent operations slower to speed up a rare one", with that benchmark as
"the clearest refutation", is withdrawn.

## Verdict and what would actually help

At the shipped `cache_size: 10000` default, **leave `evictLocked` alone for
now**. The verdict is narrower than "not a bottleneck". When a ClamAV or YARA
engine is active, a Set happens only after a scan MISS that costs a scan
measured in milliseconds, so ~218 ns of amortized eviction is small relative to
it. With **no engine configured** (YARA disabled and no ClamAV), `ScanBody`
still caches a clean result without scanning
(`TestYARA_DisabledSkipsScanAndDiagnosticsWarn` pins this). There, a Set
follows only a SHA-256 of the body, and the eviction cost relative to that path
is **UNMEASURED**. Cache hits,
however, also wait behind the exclusive lock hold, and that reader tail-latency
impact is **UNMEASURED**, pending a contention run on an idle host (see
"Contention"). Revisit this verdict if that run shows a material hit-path
stall.

If production telemetry ever shows this stall mattering — the benchmarks added
here make it measurable, and `culvert_scan_cache_size` already exposes the
occupancy that drives it — the fix is **not** a layout change. There are two
candidates, and both change observable behaviour, so each needs its own change
and its own review:

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

A cheaper mitigation that needs no structural change: **cap or warn on
`cache_size`** at startup, so the 150-300 ms lock hold at 1 000 000 is not
reachable by a config edit alone.

## Scope

Benchmarks and documentation only. `internal/hashcache/hashcache.go` keeps its
existing behaviour; the only edit to it is the measured cost table on
`evictLocked` recording what the numbers above found, so the next reader does not
re-derive them or retry the rejected layout change.
