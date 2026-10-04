package urlcat

import (
	"math/rand/v2"
	"sync"
)

// ── The forward category index is read LOCK-SHARDED ──────────────────────────
//
// MatchesHost / MatchesHostAdmin answer "is this host in category C?". They are
// the per-CATEGORY halves of destination-category resolution, and
// policy_hostcat.go's hostCatScratch.matchesCategory calls one of them ONCE PER
// CATEGORY-SCOPED ACCESS RULE PER PROXIED REQUEST — deliberately not memoized,
// because the answer depends on the rule's category as well as the host.
//
// Both reached their host set under a single process-wide sync.RWMutex read
// lock. RWMutex.RLock is an atomic read-modify-write on ONE shared word
// (readerCount), so every request on every core wrote the same cache line purely
// to read an index that in steady state never changes. That is not a constant
// cost but a THROUGHPUT CEILING, and it is the same finding already closed for
// internal/threatfeed, internal/connlimit, internal/blocklist, internal/rewrite
// and security.go's IPFilter + rate-limit exempt view. CLAUDE.md recorded it as
// the remaining open item on this path and named the instrument.
//
// Measured on a 4-core Intel Xeon @ 2.10GHz, linux/amd64, go1.26.8. Medians of
// n=3, both arms timed in ONE run so the comparison is machine-independent
// (BenchmarkMatchesHostScaling vs _Baseline, which freezes the pre-change body).
//
// A pure-CPU control confirms the box itself scales 3.85x from one core to four,
// so the shape below is contention and not saturation. On the read PRIMITIVE,
// isolated from the rest of a policy scan:
//
//	                                   │ 1 core   4 cores │ scaling
//	  RLock + one map read   (before)  │ 20.0 ns  48.6 ns │  0.41x
//	  one sharded RLock      (after)   │ 22.2 ns   5.3 ns │  4.2x
//
// The "before" row is the finding, and it is not that the probe was slow — it is
// that it was CAPPED: per-op cost ROSE 2.4x as cores were added, so four cores
// delivered 0.41x the throughput of one.
//
// END TO END through the real policy engine on DestCategory rules
// (BenchmarkPolicyEvaluate_CategoryRulesParallel, 12-category/480-pattern
// taxonomy, uncategorized destination — the clean-traffic case that cannot
// short-circuit, which is what every ALLOWED request pays):
//
//	                │      before      │      after       │ 4-core
//	  rules         │ 1 core   4 cores │ 1 core   4 cores │  gain
//	     10         │ 1474 ns  957.7ns │ 1439 ns  533.0ns │  1.80x
//	     50         │ 5182 ns  4568 ns │ 5321 ns  2016 ns │  2.27x
//
// Scaling from one core to four goes 1.13x → 2.64x at 50 rules: before, adding
// hardware bought almost nothing, because every added core only contributed more
// traffic to the one cache line all of them had to write. The gap widens on the
// 16- and 32-core hardware the appliance ships to, where the pre-fix curve is
// flat and the post-fix one is still climbing.
//
// NOTE ON THE INSTRUMENT: that benchmark is NEW
// (policy_category_parallel_bench_test.go) because no existing one could see
// this. BenchmarkPolicyEvaluate_CategoryRules is SERIAL, and a read-lock ceiling
// is invisible at one core by construction, while
// BenchmarkPolicyEvaluate_CategoryGroupRulesParallel is parallel but exercises
// DestCategoryGroup rules — those resolve through internal/catgroup and urlcat's
// REVERSE index (LookupHost, memoized once per scan), and never call MatchesHost
// at all. Do not quote the group benchmark for this change; it is a different
// path and is dominated by a separate contended lock in internal/catgroup
// (GetByName, 90% cumulative there — recorded as the follow-up, NOT fixed here).
//
// ── Why a sharded lock and NOT the atomic.Pointer read view ──────────────────
//
// The other established fix in this repo is an immutable view published through
// an atomic.Pointer. It is ~2.2x better than this on the read primitive
// (2.4 ns vs 5.3 ns at four cores) and it is the WRONG shape here — measured
// before the approach was chosen, not assumed.
//
// A view requires every writer to install a REPLACEMENT map, and this index is
// mutated INCREMENTALLY: addHostToIndexes patches one category in place, and the
// SaaS feed merge calls it ONCE PER HOST. CLAUDE.md's standing rule for that
// function — nothing O(taxonomy) may be added to AddHost under the write lock —
// is exactly what a view would break, because publishing means shallow-copying
// the outer category→set map on every single-host add. Measured on this machine
// by allocating the outer map at each size and re-inserting every key (the exact
// work a publish would do):
//
//	     27 categories (shipped default)      1.29 us
//	    500 categories                       21.7   us
//	200,000 categories (maxSnapURLCategories) 30.7   ms   ← per single-host add
//
// So at the category count the CP→DP snapshot validator already permits, a feed
// merge adding 10k hosts would spend ~307 SECONDS under the write lock. The
// inner-set copy AddHost already pays is O(hosts in THAT category) and tops out
// at ~553 us for the 10k MaxHostsPerCategory cap, so the outer copy is not a
// second-order addition to it — it is an unbounded-by-comparison new term.
// internal/blocklist rejected the view for the same reason (large maps mutated
// incrementally) and its hotread.go carries that reasoning at length.
//
// Sharding the read lock instead removes the contention with NO write
// amplification whatsoever: both index writers (rebuildIndex, addHostToIndexes)
// are byte-identical, every mutator keeps true exclusive access, and the host
// sets keep the copy-on-write discipline they already had. That also means this
// change cannot carry the failure class a view carries — there is no view to
// publish, so there is no such thing as a mutator that forgot to publish one,
// which for THIS store would be a silent SECURITY failure (a category a Deny
// rule keys on that stops matching, or a removed host that keeps matching).
//
// ── The trade, stated plainly ────────────────────────────────────────────────
//
// A writer acquires all readShardCount locks instead of one: measured
// uncontended and allocation-free at 1948 ns against 29.94 ns for the single
// RWMutex it replaces (BenchmarkHotRWWriteLock times both shapes in one run;
// medians of n=3), i.e. 65x, which is just the shard count. That cost is paid by rebuildIndex
// (11 call sites, all admin/feed/cluster rate) and by addHostToIndexes, each of
// which already does far more work than the extra lock acquisitions — the
// inner-set copy alone is 0.5-553 us.
//
// At ONE core the hot path is ~2 ns dearer per call (22.2 vs 20.0 ns) from the
// single rand.Uint64 on top of the same RWMutex pair, which shows up end to end
// as 5321 vs 5182 ns on the 50-rule scan — 2.8 ns per rule, matching the
// primitive exactly. A single-core gateway is the one shape a forward proxy is
// never in, so that is the right side of the trade to give up; it is recorded
// here rather than papered over, exactly as internal/connlimit and
// internal/blocklist recorded their own.
//
// Nothing about the VERDICT changes. Same index, same key derivation, same exact
// then suffix probe sequence, same exclusion against writers — this is a cost
// change only.
//
// NOTE ON THE DUPLICATE: internal/blocklist carries the same primitive. It is
// deliberately NOT extracted into a shared package — internal engines must not
// depend on a new generic hub (CLAUDE.md package-ownership rule), the two copies
// share no contract that can drift into incorrectness (each is independently
// correct), and extracting it would mean editing a security-critical hot path in
// a PR about this one. If a third consumer appears, extraction becomes the right
// call and should be its own change.

// readShardCount is the number of cache-line-isolated reader locks. 64 matches
// internal/connlimit and internal/blocklist; it must be a power of two so the
// index is a mask.
const readShardCount = 64

// cacheLine is the padding target. 64 bytes is the line size on every
// architecture this ships to (amd64, arm64).
const cacheLine = 64

// rwMutexSize is the size of a sync.RWMutex in bytes. Pinned by
// TestHotRW_ShardsAreCacheLineIsolated rather than computed with unsafe.Sizeof,
// which would drag the unsafe import in for a padding constant.
const rwMutexSize = 24

// readShard is one reader lock, padded so no two shards share a cache line.
//
// Without the padding a sync.RWMutex is 24 bytes and two shards would share a
// line: taking one shard's lock would invalidate its neighbour and hand back
// most of what splitting the lock just bought.
type readShard struct {
	sync.RWMutex
	_ [cacheLine - rwMutexSize]byte
}

// hotRW is an RWMutex whose READ side is spread across readShardCount
// independent locks, for an index read per-rule-per-request and written by
// operators, the SaaS feed merge and cluster sync.
//
// Readers on the request path take exactly ONE shard, so concurrent readers on
// different cores almost never touch the same cache line. Writers take EVERY
// shard, so a writer still excludes every reader — the mutual-exclusion
// guarantee is identical to the sync.RWMutex it replaces.
//
// Writers acquire shards in ascending index order and no reader ever holds two
// shards at once, so the ordering is total and deadlock is impossible. Like
// sync.RWMutex, hotRW is NOT reentrant: a goroutine holding a read lock must not
// take the write lock. That constraint is unchanged from the plain RWMutex this
// replaces, so any call sequence that was correct before is correct now — and
// the store's documented lock order (mutMu → {saveMu, fpMu} → mu) is untouched,
// because this replaces mu in place rather than adding a lock.
type hotRW struct {
	shards [readShardCount]readShard
}

// rlockHot takes the read lock for the per-request hot path and returns the
// shard the caller must RUnlock.
//
// The shard is chosen by rand.Uint64, which since Go 1.22 is backed by the
// runtime's per-P generator: no lock, no allocation, ~2 ns. There is no key to
// shard on — a category's host set is reached through the shared outer index, so
// the goal is simply to spread concurrent readers across cache lines, and a
// per-P random index does that without needing access to the P id. Two readers
// that collide on a shard contend exactly as they did before this change and no
// worse; with 64 shards that is ~1 in 64.
func (h *hotRW) rlockHot() *readShard {
	sh := &h.shards[rand.Uint64()&(readShardCount-1)] // #nosec G404 -- cache-line spread, not crypto; the index cannot affect the verdict
	sh.RLock()
	return sh
}

// RLock takes the read lock for COLD readers — the admin/list/persist/lookup
// surfaces, which are not on the per-rule request path and have no reason to pay
// for shard selection. They all share shard 0, which is correct because a writer
// holds every shard: what they get is a plain RWMutex, and they never contend
// with the hot path except through a writer.
func (h *hotRW) RLock() { h.shards[0].RLock() }

// RUnlock releases the cold read lock taken by RLock.
func (h *hotRW) RUnlock() { h.shards[0].RUnlock() }

// Lock takes the write lock: every shard, in ascending order.
func (h *hotRW) Lock() {
	for i := range h.shards {
		h.shards[i].Lock()
	}
}

// Unlock releases the write lock. The order is irrelevant for correctness;
// descending simply mirrors the acquisition.
func (h *hotRW) Unlock() {
	for i := len(h.shards) - 1; i >= 0; i-- {
		h.shards[i].Unlock()
	}
}
