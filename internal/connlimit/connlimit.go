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
// case rather than pretending otherwise. That residual, and the three lock
// acquisitions counted above, are what the next section closes.
//
// ── One critical section per call ────────────────────────────────────────────
//
// Splitting the lock reduced CONTENTION for distinct clients and left the
// per-request lock COUNT at three, because Release took the shard lock twice:
// once to look the counter up and again to delete the entry after an unlocked
// decrement returned zero. On a keep-alive connection with no second request in
// flight — the ordinary shape — the count returns to zero on EVERY request, so
// every request paid: an 8-byte allocation, a map insert, a map delete, three
// lock acquisitions and two atomic read-modify-writes.
//
// The profile said so plainly. BenchmarkAcquireRelease_DistinctIPsParallel at
// GOMAXPROCS=1: mutex Lock+Unlock 34% of all samples, mapdelete_faststr 28%,
// and Release 62% of cumulative time against Acquire's 34% — the cheaper half
// of the pair costing nearly twice as much, structurally. In the single-NAT
// case at four cores it is starker: mutex machinery 64% of all samples, with
// procyieldAsm and futex showing real parking, because every request in the
// process serialises on one shard and takes it three times to do it.
//
// Both halves now do their whole job inside ONE critical section, and the
// counter is stored by value (see the shard type). That removes the allocation,
// the pointer chase, the write barriers, the per-counter atomics, one of
// Release's two lock acquisitions and Acquire's increment-then-undo dance on the
// reject path. The admit/reject boundary, the unconditional-accounting contract
// and the delete-when-last behaviour are byte-for-byte the same decisions.
//
// Measured on a 4-core Xeon @2.10GHz, Go 1.26.8, one Acquire+Release pair per
// iteration, medians of n=6, with the pre-change shape frozen in-tree as the
// _Legacy arms of connlimit_critsec_bench_test.go so BOTH arms are timed in ONE
// run. The box drifted by half again between measurement rounds, so the RATIO
// is the claim and these absolutes are indicative (ns/op):
//
//	shape                      │ before │ after │        │ allocs
//	single NAT egress, 1 core  │  103.2 │  66.3 │ -35.8% │ 1 -> 0
//	single NAT egress, 4 cores │  267.6 │ 199.6 │ -25.4% │ 1 -> 0
//	distinct IPs,      1 core  │  105.7 │  70.0 │ -33.8% │ 1 -> 0
//	distinct IPs,      4 cores │  108.3 │   85.6│ -21.0% │ 1 -> 0
//	entry churn,       1 core  │   99.8 │  67.4 │ -32.5% │ 1 -> 0
//	entry churn,       4 cores │  105.9 │  68.0 │ -35.8% │ 1 -> 0
//	reject path,       1 core  │   62.6 │  29.6 │ -52.7% │ 0 -> 0
//	reject path,       4 cores │  245.1 │ 101.3 │ -58.7% │ 0 -> 0
//	steady state,      1 core  │   58.3 │  60.7 │  +4.2% │ 0 -> 0
//	steady state,      4 cores │   61.8 │  61.7 │   0.0% │ 0 -> 0
//
// THE LAST ROW IS THE HONEST PRICE and it is recorded rather than rounded away.
// "Steady state" is the one shape where the entry is RETAINED across the pair —
// an IP with a second request already in flight, so the count never returns to
// zero. There, the previous form did a map lookup plus an atomic add through the
// retained pointer and took Release's lock only once (its second acquisition
// fired only on the decrement to zero), whereas this form does a lookup plus a
// mapassign in each half. A mapassign on an existing key is ~1.2ns dearer than
// an atomic add through a pointer that is already in hand, twice per pair. n=15
// puts it at 58.3 -> 60.7 ns with OVERLAPPING distributions, it is parity at
// four cores, and it is the only one of the ten measured shapes that regressed.
//
// It is the right trade because it is bought with the two shapes that dominate a
// real gateway. Entry CHURN is the ordinary keep-alive request (one request in
// flight, count back to zero, entry created and destroyed) and is 32-36% cheaper
// with the allocation gone. The REJECT path is 53-59% cheaper, and that is the
// path an attacker drives — a flood used to cost the limiter MORE per refusal
// than per admission, which is backwards for a mitigation. Even the retained-
// entry case wins once there is contention, because what dominates then is lock
// hold time and acquisition count, not the work inside.
//
// The Release rewrite is also a CORRECTNESS fix — the two-phase shape could
// delete a live connection's entry and admit past the cap. The window, and the
// deterministic reproduction, are documented on Release itself.
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
// The counter is stored BY VALUE, not as a *int64. Every mutation of a given
// IP's count already happens under that IP's shard lock, so the indirection
// bought nothing and cost four things on the per-request path: one 8-byte heap
// allocation per tracked IP (and the entry is created and destroyed on EVERY
// request of a keep-alive connection that has no second request in flight, so
// that is an allocation per request, not per client), a pointer chase, GC write
// barriers on every map insert and delete, and an atomic read-modify-write on
// a value the lock already serialises. It also made the counter's IDENTITY a
// thing Release had to reason about, which is where the fail-open window below
// came from. Measured: 100.1 -> 69.0 ns/op per Acquire+Release pair serially and
// 1 -> 0 allocs/op (see the package header).
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
func (cl *ConnLimiter) Acquire(ip string) bool {
	// Snapshot enabled + the limit for this decision BEFORE taking the shard
	// lock: neither is lock-guarded (both are atomics, and the lock never
	// protected them — see the ConnLimiter doc), the decision is point-in-time
	// either way, and keeping them out shortens the one critical section every
	// request from a given IP serialises on.
	//
	// The READ ORDER is load-bearing and must stay enabled-then-cap: Enable
	// publishes the cap BEFORE the flag, so a reader that observes
	// enabled==true can never pair it with a stale cap.
	enabled := cl.enabled.Load()
	limit := cl.maxPerIP.Load()

	sh := cl.shard(ip)
	sh.mu.Lock()
	// A missing key reads as 0, so the absent and zero cases need no branch —
	// n is this connection's would-be count either way. The whole decision
	// (read, compare, commit) happens inside ONE critical section, which is
	// what makes the TOCTOU guard the previous shape needed against Release
	// unnecessary rather than merely reordered.
	n := sh.conns[ip] + 1
	if enabled && n > limit {
		// Over the cap: this connection is NOT admitted, so it will never be
		// Released — simply do not commit the count. The previous shape
		// incremented first and then undid it under a second lock; not writing
		// is the same net accounting with no window to guard.
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
// presence, and the delete-at-one prevents underflow, so releasing an IP with
// no live count is a safe no-op.
//
// ONE CRITICAL SECTION, and that is a correctness property before it is a cost
// one. Release used to take the shard lock TWICE — once to look the counter up,
// then again to delete the entry once an UNLOCKED decrement had taken it to
// zero — and the second pass re-checked the counter's VALUE without re-checking
// its IDENTITY. Acquire's reject path had exactly that identity guard
// (`cur == ctr`), so the pattern was known and applied in one of the two places
// that needed it.
//
// What the gap permitted (reproduced deterministically by
// TestRelease_LegacyTwoPhaseLosesALiveSlot, which drives the interleaving
// rather than racing for it): Release A reads the counter, unlocks, decrements
// 1 -> 0 and is descheduled. Acquire B finds the still-mapped counter, takes it
// 0 -> 1; Release B takes it back to 0 and deletes the entry. Acquire C then
// misses, allocates a FRESH counter, maps it, and takes it to 1 — a live,
// admitted connection. A now re-locks, loads its STALE pointer, sees 0, and
// deletes whatever is at ip — which is C's entry, count 1. C's accounting is
// destroyed, so the IP goes on to hold limit+1 concurrent connections: a
// fail-OPEN past a configured per-IP cap, the same direction as the #503 bug
// the unconditional-accounting contract above exists to close.
//
// Doing the lookup, the decrement and the conditional delete in one critical
// section removes the window outright. There is no longer a pointer that can go
// stale, no unlocked mutation of a count the lock is supposed to serialise, and
// no value-vs-identity re-check to get wrong — and it halves this function's
// lock traffic, which is the dominant cost when traffic arrives from a single
// NAT egress (see the package header).
func (cl *ConnLimiter) Release(ip string) {
	sh := cl.shard(ip)
	sh.mu.Lock()
	if n, ok := sh.conns[ip]; ok {
		if n <= 1 {
			// Last live connection for this IP (or a stray release against a
			// count the map should never hold) — drop the entry so the map
			// stays bounded by LIVE clients, not by every client ever seen.
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
	defer sh.mu.Unlock()
	// A missing key reads as 0, which is exactly the answer for an untracked
	// IP. Reading under the lock (rather than atomically off a pointer) is what
	// makes this a consistent snapshot of the same state Acquire/Release commit.
	return sh.conns[ip]
}
