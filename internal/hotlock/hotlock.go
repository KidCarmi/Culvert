// Package hotlock provides HotRW: a reader/writer lock whose READ side is
// spread across independent, cache-line-isolated shards, for a store that is
// read on the proxy request path and written at operator or feed rate.
//
// ── The problem it solves ─────────────────────────────────────────────────────
//
// sync.RWMutex.RLock is an atomic read-modify-write on ONE shared word
// (readerCount), so a store read once per request has every core in the process
// writing the same cache line purely to read maps that in steady state never
// change. That is not a constant cost but a THROUGHPUT CEILING: adding cores
// adds coherence traffic on that line rather than throughput, and on a
// many-core appliance the curve goes flat or inverts.
//
// This is the same finding this repo has closed in internal/threatfeed,
// internal/connlimit, internal/rewrite and security.go's IPFilter. Those four
// closed it with an immutable view published through an atomic.Pointer, which
// makes reads free but bills every mutator a full copy of the data it changes.
// HotRW is the instrument for the OTHER shape: a store whose hot data is LARGE
// and mutated INCREMENTALLY, where copy-on-write would trade a read-side
// ceiling for a write-side stall and a GC-pressure regression on the same hot
// path.
//
// It was first written for internal/blocklist and is shared — not copied — with
// internal/urlcat. Each caller records its own measurements and its own reason
// for choosing this over a view: see internal/blocklist/hotread.go and
// internal/urlcat/hotread.go. Extracting rather than duplicating follows the
// same rule as internal/storeguard and security.go's prefixSet — a second copy
// of a concurrency primitive is how the reasoning behind it rots.
//
// ── What it guarantees ───────────────────────────────────────────────────────
//
// Readers on the request path take exactly ONE shard (RLockHot), so concurrent
// readers on different cores almost never touch the same cache line. Writers
// take EVERY shard, so a writer still excludes every reader: the
// mutual-exclusion guarantee is IDENTICAL to the sync.RWMutex it replaces, and
// no caller's verdict can change by adopting it.
//
// Writers acquire shards in ascending index order and no reader ever holds two
// shards at once, so the ordering is total and deadlock is impossible.
//
// Like sync.RWMutex, HotRW is NOT reentrant: a goroutine holding a read lock
// must not take the write lock. That constraint is unchanged from the plain
// RWMutex it replaces, so any call sequence that was correct before is correct
// now.
//
// ── The trade, stated plainly ────────────────────────────────────────────────
//
// A writer acquires ShardCount locks instead of one — ~1.5 us uncontended and
// allocation-free, against ~24 ns for the single RWMutex it replaces. That is
// ~64x, which is just the shard count. It is the right trade only for a store
// whose writers already do far more work than that (hashing a token set,
// marshalling and atomically rewriting a file, rebuilding an index) and run at
// admin or feed rate, against a read taken once per proxied request.
//
// At ONE core the read fast path is a few ns dearer, from the single
// rand.Uint64 on top of the same RWMutex pair. A single-core gateway is the one
// shape a forward proxy is never in, so that is the right side of the trade to
// give up — recorded here rather than papered over.
package hotlock

import (
	"math/rand/v2"
	"sync"
)

// ShardCount is the number of cache-line-isolated reader locks. 64 matches
// internal/connlimit; it must be a power of two so the index is a mask.
const ShardCount = 64

// CacheLineBytes is the padding target. 64 bytes is the line size on every
// architecture this ships to (amd64, arm64) — the same constant, chosen for the
// same reason, as internal/connlimit's.
const CacheLineBytes = 64

// RWMutexSize is the size of a sync.RWMutex in bytes. Stated as a constant and
// pinned by TestShardsAreCacheLineIsolated rather than computed with
// unsafe.Sizeof, which would drag the unsafe import into a package on the
// request path of two security-critical stores for the sake of a padding
// constant.
const RWMutexSize = 24

// Shard is one reader lock, padded so no two shards share a cache line.
//
// Without the padding, a sync.RWMutex is 24 bytes and two shards would share a
// line: taking one shard's lock would invalidate its neighbour and hand back
// most of what splitting the lock just bought. Same false-sharing reasoning,
// and the same measured conclusion, as internal/connlimit's shard.
type Shard struct {
	sync.RWMutex
	_ [CacheLineBytes - RWMutexSize]byte
}

// HotRW is an RWMutex whose read side is sharded. The zero value is ready to
// use and must not be copied once used, exactly like sync.RWMutex.
type HotRW struct {
	shards [ShardCount]Shard
}

// RLockHot takes the read lock for the per-request hot path and returns the
// shard the caller must RUnlock.
//
// The shard is chosen by rand.Uint64, which since Go 1.22 is backed by the
// runtime's per-P generator: no lock, no allocation, ~2 ns. There is generally
// no key to shard on — the answer depends on the whole store, not on one map
// entry — so the goal is simply to spread concurrent readers across cache
// lines, and a per-P random index does that without needing access to the P id.
// Two readers that collide on a shard contend exactly as they did before, and
// no worse; with 64 shards that is ~1 in 64.
func (h *HotRW) RLockHot() *Shard {
	sh := &h.shards[rand.Uint64()&(ShardCount-1)] // #nosec G404 -- cache-line spread, not crypto; the index cannot affect any verdict
	sh.RLock()
	return sh
}

// RLock takes the read lock for COLD readers — the admin, list and persist
// surfaces, which are not on the request path and have no reason to pay for
// shard selection. They all share shard 0, which is correct because a writer
// holds every shard: what they get is a plain RWMutex, and they never contend
// with the hot path except through a writer.
func (h *HotRW) RLock() { h.shards[0].RLock() }

// RUnlock releases the cold read lock taken by RLock.
func (h *HotRW) RUnlock() { h.shards[0].RUnlock() }

// ShardAt returns the i'th reader lock. It exists for the STRUCTURAL gates each
// adopter carries — "cold readers take exactly shard 0", "hot reads spread
// across shards", "a Shard is exactly one cache line" — which is the class of
// gate this repo prefers for hot paths, because it is deterministic on any
// hardware, under any load, with or without -race, where a scaling-ratio gate
// narrows until it flakes and then gets muted.
//
// It is not a locking API: production code takes RLockHot, RLock or Lock and
// never reaches for an individual shard. i must be in [0, ShardCount).
func (h *HotRW) ShardAt(i int) *Shard { return &h.shards[i] }

// Lock takes the write lock: every shard, in ascending order.
func (h *HotRW) Lock() {
	for i := range h.shards {
		h.shards[i].Lock()
	}
}

// Unlock releases the write lock. The order is irrelevant for correctness;
// descending simply mirrors the acquisition.
func (h *HotRW) Unlock() {
	for i := len(h.shards) - 1; i >= 0; i-- {
		h.shards[i].Unlock()
	}
}
