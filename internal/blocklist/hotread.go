package blocklist

import "github.com/KidCarmi/Culvert/internal/hotlock"

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

// ── The engine lives in internal/hotlock ──────────────────────────────────────
//
// The mechanism below was written here and has since been EXTRACTED verbatim to
// internal/hotlock so internal/urlcat could adopt it for the same reason (its
// per-rule category probe took one process-wide RLock per rule per request).
// The narrative above — the finding, the measurements, and the recorded reason
// for choosing a sharded lock over an atomic.Pointer view — stays with this
// store, because it is this store's evidence.
//
// These aliases keep every call site and every gate in this package pointing at
// the shared engine, so internal/blocklist's hot-read suite is what proves the
// extraction: a second copy is how the reasoning above rots (the same rule that
// moved the badger recovery engine to internal/storeguard and the CIDR
// machinery to security.go's prefixSet).
type (
	hotRW     = hotlock.HotRW
	readShard = hotlock.Shard
)

const (
	readShardCount = hotlock.ShardCount
	cacheLine      = hotlock.CacheLineBytes
	rwMutexSize    = hotlock.RWMutexSize
)
