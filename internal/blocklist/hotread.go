package blocklist

import (
	"math/rand/v2"
	"sync"
)

// ── The blocklist read lock is SHARDED ────────────────────────────────────────
//
// IsBlocked runs on EVERY proxied destination — plain HTTP, CONNECT, WebSocket
// and SOCKS5 all reach it through preDispatchBlocked, before any policy work
// begins — and it took a single process-wide sync.RWMutex read lock to reach its
// verdict.
//
// RWMutex.RLock is an atomic read-modify-write on ONE shared word (readerCount),
// so every request in the process wrote the same cache line purely to read maps
// that in steady state never change. That is not a constant cost but a
// THROUGHPUT CEILING, and it is the same finding already closed for
// internal/threatfeed, internal/connlimit and security.go's IPFilter.
//
// Measured on a 4-core Intel Xeon @ 2.10GHz, linux/amd64, against a 100k-entry
// feed-backed store with one wildcard, resolving an ordinary 33-byte CDN
// hostname that matches nothing — a MISS is what every ALLOWED request pays, and
// allowed requests are the overwhelming majority of a gateway's traffic. Medians
// of n=7, aggregate throughput in millions of lookups per second
// (BenchmarkIsBlockedScaling vs BenchmarkIsBlockedScaling_Baseline, -cpu 1,2,4):
//
//	                 │      before       │      after        │
//	  cores          │  1     2     4    │  1     2     4    │
//	  NoExceptions   │ 9.01  6.25  6.58  │ 8.60 10.21 16.43  │  2.50x at 4 cores
//	  WithExceptions │ 3.47  3.34  3.52  │ 3.55  6.01 11.08  │  3.15x at 4 cores
//
// The finding is the "before" row, and it is not that the store was slow — it is
// that it was CAPPED. Four cores delivered 6.58M lookups/s against 9.01M on one:
// adding hardware SUBTRACTED throughput, because every added core only
// contributed more traffic to the one cache line all of them had to write. After,
// throughput rises with core count (1.9x and 3.1x from one core to four), and the
// gap widens on the 16- and 32-core hardware the appliance actually ships to,
// where the pre-fix curve is flat and the post-fix one is still climbing.
//
// The two postures bracket the result honestly rather than quoting the best one.
// NoExceptions is the DEFAULT posture and the one that isolates the lock, since
// isExcepted short-circuits on an empty map and little else remains.
// WithExceptions adds ~170 ns of parent-walk probing that does not contend, which
// DILUTES the lock as a share of the per-call cost — the larger 3.15x there is a
// second-order effect of the baseline being capped in absolute terms, not
// evidence that the change helps more when there is more work to do.
//
// ── Why a sharded lock and NOT the atomic.Pointer read view ───────────────────
//
// The established fix in this repo is an immutable view published through an
// atomic.Pointer, with every mutator installing a REPLACEMENT map. That is the
// right shape for threatfeed and for IPFilter, and it is the WRONG shape here —
// measured, not assumed.
//
// Those stores replace their large maps wholesale and mutate only small ones
// incrementally. This one is the opposite: exact and wildcards are LARGE
// (a feed-backed deployment runs to 10^6 hosts) and they are mutated
// INCREMENTALLY, by ApplyDelta on every cluster delta sync, by Add, AddManual,
// Remove, and by the pruning paths. Copy-on-write bills every one of those a
// full map copy. Measured on this machine before the approach was chosen, by
// allocating a map[string]bool of each size and re-inserting every key (the
// exact work a publish would do); no benchmark is carried in the tree for a
// design that was rejected, but the figure is reproducible in a dozen lines:
//
//	10k entries      0.65 ms      437 KB
//	100k entries    12    ms      3.5 MB
//	1M entries     190    ms       56 MB
//
// So a view would trade a read-side contention ceiling for 190 ms of stall and
// 56 MB of garbage on every delta sync — a GC-pressure regression on the same
// hot path — and the admin bulk-delete handler (ui_policy.go, which loops
// bl.Remove) would become O(hosts x blocklist-size), the exact O(N^2) trap the
// IPFilter change had to add AddAll to escape.
//
// Sharding the read lock instead removes the contention with NO write
// amplification whatsoever: the maps stay exactly as they are, every mutator
// body is byte-identical, and writers keep true exclusive access. That also
// means this change cannot reintroduce the failure class the view carries —
// there is no view to publish, so there is no such thing as a mutator that
// forgot to publish one (a silent SECURITY failure: a removed blocklist entry
// that keeps admitting, or a revoked exception that keeps blocking).
//
// ── The trade, stated plainly ─────────────────────────────────────────────────
//
// A writer must acquire all readShardCount locks instead of one: 1.52 us
// uncontended and allocation-free, against 24 ns for the single RWMutex it
// replaces — 62x, which is just the shard count (BenchmarkHotRWWriteLock
// measures both shapes, medians of n=5). That is a real cost and it is still the
// right trade, because every caller that takes it already does far more work
// than 1.5 us — ApplyDelta SHA-256s its whole
// token set, Save marshals and atomically rewrites the file, ReplaceFeedEntries
// rebuilds both enforcement maps — and all of them run at admin or feed rate,
// against a read taken once per proxied request. Reads got cheap by making
// writes dearer, which is the correct direction for this store.
//
// At one core the fast path is ~5 ns dearer — 8.60 against 9.01M lookups/s, a
// 5% regression from the one rand.Uint64 on top of the same RWMutex pair. A
// single-core gateway is the one shape a forward proxy is never in, so that is
// the right side of the trade to give up; it is recorded here rather than
// papered over, exactly as internal/connlimit recorded its own.
//
// Nothing about the VERDICT changes. Same maps, same probe sequence, same
// mode semantics, same exclusion against writers — this is a cost change only.

// readShardCount is the number of cache-line-isolated reader locks. 64 matches
// internal/connlimit; it must be a power of two so the index is a mask.
const readShardCount = 64

// cacheLine is the padding target. 64 bytes is the line size on every
// architecture this ships to (amd64, arm64) — the same constant, chosen for the
// same reason, as internal/connlimit's.
const cacheLine = 64

// rwMutexSize is the size of a sync.RWMutex in bytes. Pinned by
// TestHotRW_ShardsAreCacheLineIsolated rather than computed with unsafe.Sizeof,
// which would drag the unsafe import into a security-critical package for a
// padding constant.
const rwMutexSize = 24

// readShard is one reader lock, padded so no two shards share a cache line.
//
// Without the padding, a sync.RWMutex is 24 bytes and two shards would share a
// line: taking one shard's lock would invalidate its neighbour and hand back
// most of what splitting the lock just bought. Same false-sharing reasoning, and
// the same measured conclusion, as internal/connlimit's shard.
type readShard struct {
	sync.RWMutex
	_ [cacheLine - rwMutexSize]byte
}

// hotRW is an RWMutex whose READ side is spread across readShardCount
// independent locks, for a store read on the request path and written by
// operators.
//
// Readers take exactly ONE shard, so concurrent readers on different cores
// almost never touch the same cache line. Writers take EVERY shard, so a writer
// still excludes every reader — the mutual-exclusion guarantee is identical to
// the sync.RWMutex it replaces.
//
// Writers acquire shards in ascending index order and no reader ever holds two
// shards at once, so the ordering is total and deadlock is impossible. Like
// sync.RWMutex, hotRW is NOT reentrant: a goroutine holding a read lock must not
// take the write lock. That constraint is unchanged from the plain RWMutex this
// replaces, so any call sequence that was correct before is correct now.
type hotRW struct {
	shards [readShardCount]readShard
}

// rlockHot takes the read lock for the per-request hot path and returns the
// shard the caller must RUnlock.
//
// The shard is chosen by rand.Uint64, which since Go 1.22 is backed by the
// runtime's per-P generator: no lock, no allocation, ~2 ns. There is no key to
// shard on here — the answer depends on the whole store, not on one map entry —
// so the goal is simply to spread concurrent readers across cache lines, and a
// per-P random index does that without needing access to the P id. Two readers
// that collide on a shard contend exactly as they did before this change and no
// worse; with 64 shards that is ~1 in 64.
func (h *hotRW) rlockHot() *readShard {
	sh := &h.shards[rand.Uint64()&(readShardCount-1)] // #nosec G404 -- cache-line spread, not crypto; the index cannot affect the verdict
	sh.RLock()
	return sh
}

// RLock takes the read lock for COLD readers — the admin/list/persist surfaces,
// which are not on the request path and have no reason to pay for shard
// selection. They all share shard 0, which is correct because a writer holds
// every shard: what they get is a plain RWMutex, and they never contend with the
// hot path except through a writer.
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
