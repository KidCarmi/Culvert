// Package connlimit provides per-IP connection limiting. It prevents a single
// client IP from consuming all proxy resources via many concurrent connections
// (e.g. HTTP flood, slow-read attacks). It is a self-contained leaf (stdlib
// only, no Culvert coupling) extracted from the flat package main per ADR-0002.
package connlimit

import (
	"hash/maphash"
	"sync"
	"sync/atomic"
)

const defaultMaxConnsPerIP = 1024

// ── Sharding ─────────────────────────────────────────────────────────────────
//
// Acquire + a deferred Release run on EVERY proxied request (proxy.go's
// handleRequest, socks5.go), not once per TCP connection — so on a keep-alive
// connection the pair is paid per request. Against one process-wide mutex that
// made the limiter a throughput CEILING rather than a constant cost: three
// exclusive lock acquisitions per request (Acquire; Release's lookup; Release's
// delete when the count returns to zero), all on the same cache line, so every
// request in the process serialised there regardless of which client it came
// from.
//
// The measurement that matters is not ns/op at one core, it is how ns/op MOVES
// with core count. BenchmarkAcquireRelease_EnabledParallel, distinct client
// IPs, one Acquire+Release per iteration, n=12 (2.8GHz Xeon, Go 1.26):
//
//	GOMAXPROCS │  before  │  after  │
//	     1     │   103ns  │  119ns  │  +15%
//	     2     │   187ns  │  131ns  │
//	     4     │   294ns  │  103ns  │  -65%
//
// Before, each added core made every request MORE expensive: four cores bought
// 1.4x the throughput of one (9.7M -> 13.6M ops/s). After, the per-op cost is
// flat in core count and four cores buy 4.6x (8.4M -> 39.0M ops/s) — 2.9x the
// old four-core ceiling, and the gap widens on the 16- and 32-core hardware
// this actually ships to.
//
// The +15% at GOMAXPROCS=1 is the honest price and it is paid deliberately:
// two maphash.String calls, ~5.5ns each, one in Acquire and one in Release.
// A single-core box with one client is the one shape that got slower, and it is
// the one shape a gateway is never in. Against the ~100us a proxied request
// costs end to end, 11ns is noise in both directions; the reason to make this
// trade is the ceiling, not the constant.
//
// Sharding spreads DISTINCT clients, so it does nothing for traffic arriving
// from a single NAT egress — BenchmarkAcquireRelease_SingleIPParallel pins that
// case as unchanged rather than pretending otherwise.
//
// 64 shards mirrors the per-IP rate limiter already in this tree (rlShardCount,
// security.go), which reached the same conclusion for the same reason.
const shardCount = 64

// cacheLine is the padding target below. 64 bytes is the line size on every
// architecture this ships to (amd64, arm64); over-padding on a machine with
// larger lines costs a few KB of a 4KB table, and under-padding only forfeits
// part of the win, so this is a constant rather than a runtime probe.
const cacheLine = 64

// shard is one lock + counter map. A sync.Mutex plus a map header is 16 bytes,
// so four unpadded shards share a cache line and taking one shard's lock
// invalidates three innocent neighbours — false sharing that hands back most of
// what splitting the lock just bought.
//
// The padding was measured, not assumed. At n=10 it looked like noise (p=0.28);
// at n=25 it is decisive: -22% on the distinct-IP parallel benchmark (p=0.005)
// and -19% on the enabled one (p=0.000), -21% geomean. Removing it does not
// break anything — it just gives back a fifth of the gain.
//
// ── Counter representation ───────────────────────────────────────────────────
//
// The counter is held BY VALUE, not behind a *int64. A pointer map made every
// first Acquire for an IP heap-allocate an 8-byte counter, and because Release
// deletes the entry when the count returns to zero, the common production shape
// — a client with one request in flight at a time — allocated and discarded one
// counter PER REQUEST, not per client:
//
//	BenchmarkAcquireRelease_SingleIP   132.5 ns/op   8 B/op   1 allocs/op
//
// It was the largest Culvert-owned allocation site in the end-to-end proxy
// profile (2.4% of every allocation the whole proxy made, Acquire's own flat
// cost). Holding the value inline removes that allocation, removes one heap
// object per tracked IP from the GC's scan set, and — because the counter no
// longer has to be mutable from outside the shard lock — lets every mutation
// happen under the single lock the map operation already needs. That drops the
// per-request lock acquisitions from three to two: see Release, which used to
// take the lock twice (lookup, then the zero-count delete).
//
// Sizing note: a map header is still 8 bytes, so the 16-byte prefix the padding
// below subtracts is unchanged.
type shard struct {
	mu    sync.Mutex
	conns map[string]int64
	_     [cacheLine - 16]byte
}

// ConnLimiter tracks active connections per client IP.
//
// maxPerIP is atomic rather than lock-guarded: with the counters sharded there
// is no single lock left that could serialise it against Acquire, and none is
// needed. The cap is only ever read to make a point-in-time admit/reject
// comparison, and Enable never touches a counter, so an Enable interleaved with
// an Acquire has always been able to land on either side of it. What the lock
// DID protect — the counter increment against Release's delete (the TOCTOU note
// on Acquire) — is preserved exactly, per shard.
type ConnLimiter struct {
	shards   [shardCount]shard
	seed     maphash.Seed
	maxPerIP atomic.Int64
	enabled  atomic.Bool
	rejected atomic.Int64
}

// New returns a ConnLimiter with the default per-IP cap, initially disabled.
func New() *ConnLimiter {
	cl := &ConnLimiter{seed: maphash.MakeSeed()}
	for i := range cl.shards {
		cl.shards[i].conns = make(map[string]int64)
	}
	cl.maxPerIP.Store(defaultMaxConnsPerIP)
	return cl
}

// shard maps a client IP to its lock + counter map. Every operation for a given
// IP MUST route through this one function: Acquire, Release and ActiveConns all
// depend on landing on the same shard, which is what preserves the per-IP
// accounting invariants across the split.
//
// Hashing is what the split costs, so it is the one part worth measuring rather
// than assuming. Over a dotted quad: maphash.String 5.6ns (the runtime's
// AES-accelerated string hasher), the FNV-1a byte loop the per-IP rate limiter
// uses (security.go) 6.9ns — FNV is a multiply-per-byte dependency chain, so it
// does not pipeline. maphash is the cheaper of the two and allocation-free, but
// it does NOT make the hash free: a request hashes twice, once in Acquire and
// once in Release, and that ~11ns IS the +15% at GOMAXPROCS=1 recorded above.
// The FNV variant was built and measured first; it was ~3ns worse per request
// and is not carried.
//
// The seed is per-limiter and random, so the shard an IP lands on is not
// predictable from outside the process. That is not the reason for the choice —
// the key space is validated IP strings, not arbitrary attacker input — but it
// does mean a client cannot aim traffic at one shard on purpose.
func (cl *ConnLimiter) shard(ip string) *shard {
	return &cl.shards[maphash.String(cl.seed, ip)%shardCount]
}

// Enable turns on connection limiting.
func (cl *ConnLimiter) Enable(maxPerIP int) {
	if maxPerIP <= 0 {
		maxPerIP = defaultMaxConnsPerIP
	}
	// Enable is called at runtime (admin API, config import, CP snapshot sync)
	// while Acquire reads maxPerIP on the proxy hot path. Publishing the cap
	// before the enabled flag means a reader that observes enabled==true never
	// reads a stale cap alongside it.
	cl.maxPerIP.Store(int64(maxPerIP))
	cl.enabled.Store(true)
}

// Disable turns off connection limiting.
func (cl *ConnLimiter) Disable() { cl.enabled.Store(false) }

// Enabled reports whether connection limiting is currently active.
func (cl *ConnLimiter) Enabled() bool { return cl.enabled.Load() }

// MaxPerIP returns the current per-IP limit.
func (cl *ConnLimiter) MaxPerIP() int {
	return int(cl.maxPerIP.Load())
}

// ActiveIPs returns the number of IPs currently tracked.
//
// It is a diagnostic gauge — the admin API's activeIPs field (ui_config.go) and
// the tests, never the request path — and with the counters sharded it is a sum
// of per-shard snapshots rather than one instantaneous whole-map reading: under
// concurrent traffic it can land between two consistent states. Quiescent
// readings, every Acquire paired with its Release, stay exact. That is the one
// behavioural difference the shard split makes, and it is confined here.
//
// It touches all 64 shard locks, but each is held only for a len() read, so an
// admin poll costs the request path nothing measurable.
func (cl *ConnLimiter) ActiveIPs() int {
	n := 0
	for i := range cl.shards {
		sh := &cl.shards[i]
		sh.mu.Lock()
		n += len(sh.conns)
		sh.mu.Unlock()
	}
	return n
}

// Rejected returns the cumulative count of connections refused because the
// client IP was over its per-IP cap (process lifetime; never reset). This is
// the only signal an admin has that a configured limit is actually rejecting
// live traffic rather than sitting unused — the reject path (proxy.go,
// socks5.go) has no other counter or metric.
func (cl *ConnLimiter) Rejected() int64 {
	return cl.rejected.Load()
}

// Acquire records a connection from ip and reports whether it is admitted
// (false ⇒ the per-IP limit is exceeded and the caller should reject).
//
// The per-IP counter is ALWAYS maintained, even while the limiter is disabled;
// the enabled flag gates only the rejection decision, not the accounting. This
// keeps Acquire and Release symmetric across a runtime disable/re-enable: every
// admitted connection is counted exactly once and released exactly once. If
// Acquire skipped counting while disabled (the historical behavior), a
// connection admitted during the disabled window would later be Released
// unconditionally and decrement a DIFFERENT, still-counted connection's slot —
// letting a subsequent re-enable admit past the cap (fail-open). Conversely,
// gating Release on enabled leaks the slot of a connection counted while
// enabled and released after disable, wedging that IP over-limit forever
// (the #503 fail-closed bug). Counting unconditionally closes both.
//
// The admit decision is made INSIDE the single lock hold, before the count is
// written, rather than by incrementing first and undoing the increment after a
// second lock acquisition. The two are equivalent on the state they leave
// behind: a rejection requires n > limit, limit is never below 1 (New stores
// the default and Enable clamps a non-positive argument to it), so a rejected
// Acquire always found n >= 2 — an entry that already existed and that the undo
// therefore restored to its prior value without deleting it. Not writing it is
// that same outcome reached without the write, and the never-taken "drop the
// entry if it was the last" branch goes with it. ActiveConns, ActiveIPs and
// Rejected all read exactly what they read before (TestAcquireRelease_
// LimitAndCleanup and TestRejected_OnlyCountsOverCapAcquires are the pins).
//
// enabled + the limit are still snapshotted under the lock, so an Enable racing
// an Acquire lands on one side of this decision or the other, as it always has.
func (cl *ConnLimiter) Acquire(ip string) bool {
	sh := cl.shard(ip)
	sh.mu.Lock()
	// The count this connection would occupy. The lock is held through the
	// decision and the write to prevent a TOCTOU race with Release(), which
	// routes the same ip to this same shard.
	n := sh.conns[ip] + 1
	// Snapshot enabled + the limit for this decision — Enable()/Disable() may
	// rewrite them at runtime.
	enabled := cl.enabled.Load()
	limit := cl.maxPerIP.Load()
	if enabled && n > limit {
		// Over the cap: this connection is NOT admitted, so it will never be
		// Released — leave the count as it was.
		sh.mu.Unlock()
		cl.rejected.Add(1)
		return false
	}
	sh.conns[ip] = n
	sh.mu.Unlock()
	return true
}

// Release decrements the connection count for ip. It does NOT gate on enabled:
// Acquire counts every admitted connection unconditionally (see its doc), so
// Release must mirror that exactly. The decrement is guarded by map-entry
// presence, and the ≤0 delete prevents underflow, so releasing an IP with no
// live count is a safe no-op.
//
// With the count held by value the lookup, the decrement and the zero-count
// delete are one lock hold instead of three (lookup; unlocked atomic; re-lock to
// re-check and delete) — the re-check existed only because the decrement
// happened outside the lock and the entry could have been re-created under it.
// A present entry is always >= 1 (it is created at 1 and deleted rather than
// stored at 0), so `n <= 1` is exactly the old "the decrement reached <= 0", and
// an absent entry is still the same underflow-safe no-op.
func (cl *ConnLimiter) Release(ip string) {
	sh := cl.shard(ip)
	sh.mu.Lock()
	if n, ok := sh.conns[ip]; ok {
		if n <= 1 {
			delete(sh.conns, ip)
		} else {
			sh.conns[ip] = n - 1
		}
	}
	sh.mu.Unlock()
}

// ActiveConns returns the current connection count for an IP (testing).
func (cl *ConnLimiter) ActiveConns(ip string) int64 {
	sh := cl.shard(ip)
	sh.mu.Lock()
	n := sh.conns[ip] // absent ⇒ 0, as before
	sh.mu.Unlock()
	return n
}
