package urlcat

// ── The category-membership read lock is SHARDED ──────────────────────────────
//
// MatchesHost / MatchesHostAdmin are the per-RULE half of destination-category
// resolution: package main's hostCatScratch.matchesCategory (policy_hostcat.go)
// calls one of them ONCE PER category-scoped access rule PER proxied request,
// and deliberately does not memoize the result (the memo would cost a map
// allocation to save an O(labels) index probe). LookupHost / LookupHostAdmin are
// the once-per-scan fusion half.
//
// All four took ONE process-wide sync.RWMutex read lock. RWMutex.RLock is an
// atomic read-modify-write on a single shared word, so a category-scoped
// rulebase multiplied read-lock traffic by the RULE COUNT on every core serving
// traffic — the request path writing one cache line N times per request purely
// to read a taxonomy that in steady state never changes. That is not a constant
// cost but a THROUGHPUT CEILING, and it is the finding this repo has already
// closed in internal/threatfeed, internal/connlimit, internal/rewrite,
// internal/blocklist and security.go's IPFilter.
//
// urlcat_matcheshost_bench_test.go named this as the open follow-up and named
// the instrument: "what matters is not ns/op at one core but how ns/op MOVES
// with core count".
//
// ── Measured ─────────────────────────────────────────────────────────────────
//
// 4-core Intel Xeon @ 2.10GHz, linux/amd64, go1.26.8, medians of n=5.
//
// The two SAME-RUN comparisons are the authoritative ones: both arms are timed
// in one binary, so the reading is machine-independent. Cross-run pairs on this
// path have been wrong by an order of magnitude before (the finding recorded on
// categoryKey in CLAUDE.md), so they are labelled as such below and used only to
// bound the end-to-end shape.
//
// STORE LEVEL, same run — BenchmarkMatchesHostScaling against
// BenchmarkMatchesHostScaling_Baseline, which is the VERBATIM pre-fix
// single-RWMutex probe over the SAME index. Shipped default taxonomy,
// uncategorized destination, ns/op:
//
//	  cores            │   1       2       4    │ scaling 1→4
//	  single RWMutex   │ 135.3   117.4   118.1  │  1.15x
//	  sharded          │ 150.7    89.9    50.5  │  2.98x     2.34x faster at 4
//
// ENGINE ONLY, same run — internal/hotlock's BenchmarkRLockSingle against
// BenchmarkRLockHot, which isolates the lock from all surrounding work:
//
//	  cores            │   1       2       4    │ scaling 1→4
//	  single RWMutex   │  15.7    38.8    44.2  │  0.36x  ← cores SUBTRACT
//	  sharded          │  22.9    18.0    14.3  │  1.60x     3.08x faster at 4
//
// That middle row is the finding in its purest form: the pre-fix read lock did
// not merely fail to scale, it INVERTED — 63.5M acquisitions/s on one core
// against 22.6M on four, because every added core only contributed more
// coherence traffic to the one word all of them had to write.
//
// END TO END, cross-run (before measured on the pre-fix tree) — a 50-rule
// DestCategory scan over a 12-category / 480-pattern taxonomy resolving an
// UNCATEGORIZED destination, which is what an ALLOWED request pays because clean
// traffic cannot short-circuit (BenchmarkPolicyEvaluate_CategoryRulesParallel):
//
//	  cores            │   1       2       4    │ scaling 1→4
//	  before           │ 5134    4635    4664   │  1.10x
//	  after            │ 5954    3810    2153   │  2.77x     2.17x faster at 4
//
// Four cores used to deliver 1.10x the throughput of one: the category-scoped
// policy engine was effectively single-threaded. The curve now climbs, which is
// what matters on the 16- and 32-core hardware the appliance ships to, where the
// pre-fix curve is flat and this one is still rising.
//
// The CEILING was measured too, by deleting the lock outright as a throwaway
// probe (unsafe — not a candidate design, only a bound): 5567 / 2785 / 1387
// ns/op, i.e. 4.01x, perfectly linear. So the lock was destroying ~3.6x of
// available parallelism and sharding recovers roughly two thirds of it. The
// residual is the per-rule rand.Uint64 and RWMutex pair — real, but now on a
// PRIVATE cache line, which is why the curve climbs instead of flattening.
//
// Both arms are 0 B/op and 0 allocs/op, before and after. This adds no
// allocation and no GC pressure.
//
// ── The ONE-CORE cost, stated plainly ────────────────────────────────────────
//
// At one core the probe is ~11% dearer (135.3 → 150.7 ns/op, the same-run
// figure), from the single rand.Uint64 per acquisition. That is roughly twice
// the ~5% internal/blocklist recorded, for the structural reason that this lock
// is taken once per RULE rather than once per request, so the shard draw is paid
// N times in one scan.
//
// It is recorded here rather than papered over, and it is still the right side
// of the trade to give up: a single-core gateway is the one shape a forward
// proxy is never in, and the crossover is below two cores.
//
// ── Why a sharded lock and NOT the atomic.Pointer read view ──────────────────
//
// Measured, not assumed — the same question internal/blocklist answered, with
// the same conclusion for the same structural reason.
//
// A view must publish an immutable replacement on every mutation. The hot data
// here is index / adminIndex, map[string]map[string]bool keyed by category, and
// addHostToIndexes mutates the OUTER map in place, once per host, on the SaaS
// feed merge path. So a view would bill every AddHost a copy of the outer map.
// Measured on this machine by allocating and refilling a map of each size (the
// exact work a publish does); no benchmark is carried in-tree for a design that
// was rejected, but the figure reproduces in a dozen lines:
//
//	     27 categories (the shipped taxonomy)     3.0 us         ~0 KB
//	  1,000 categories                           60    us        ~53 KB
//	 10,000 categories                          568    us       ~426 KB
//	200,000 categories (maxSnapURLCategories)     23    ms      ~6,826 KB
//
// The category count is bounded by maxSnapURLCategories = 200,000, so at the cap
// a view would charge 23 ms and 6.8 MB of garbage PER ADDED HOST — the feed
// merge calls AddHost once per host, making the merge quadratic and putting a
// GC-pressure regression on the very path being optimized. That is precisely the
// trap recorded on addHostToIndexes: nothing O(taxonomy) may be added to
// AddHost.
//
// Sharding the read lock costs the writer ~1.5 us, FLAT and allocation-free
// whatever the taxonomy size — four orders of magnitude better at the cap — and
// it has NO write amplification at all: every mutator body in this package is
// byte-identical after this change. That also means this change cannot carry the
// failure class a view carries. There is no view to publish, so there is no such
// thing as a mutator that forgot to publish one — which for a store whose reads
// decide policy MEMBERSHIP would be a silent SECURITY failure, not a perf one: a
// deleted category that keeps matching, or an added host that never does. This
// package has eleven write paths, every one of which would have had to get that
// right forever.
//
// ── What does NOT change ─────────────────────────────────────────────────────
//
// A writer holds EVERY shard, so it still excludes every reader: the
// mutual-exclusion guarantee is identical to the sync.RWMutex it replaces. Same
// maps, same normalization, same exact-then-suffix probe sequence, same
// first-declaration-wins precedence. This is a COST change only — no verdict
// this store can return is different.
//
// The COLD readers (All, GetByName, snapshotEntries, SnapshotWithRevision,
// ContentFingerprint, BuiltInFlag, BuiltInHostMemberships, Path, the persist
// paths) keep the plain RLock, which shares shard 0. They are not on the request
// path and have no reason to pay for shard selection; a writer holds shard 0
// too, so what they get is exactly the RWMutex they had.
//
// The engine itself lives in internal/hotlock, shared with internal/blocklist
// rather than copied — see that package's doc for the mechanism and the
// invariants.
