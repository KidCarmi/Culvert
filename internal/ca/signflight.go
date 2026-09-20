package ca

import (
	"crypto/tls"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// ── Leaf-signing single flight ────────────────────────────────────────────────
//
// GetCert is the tls.Config.GetCertificate callback for every SSL-inspected
// CONNECT, so a cache miss there is the most expensive unit of work this
// appliance performs per connection: signLeaf is 144 us / 19.6 KB / 327 allocs
// on the reference box, 85% of it the irreducible P-256 sign inside
// x509.CreateCertificate. That cost is correct once per host per TTL. It was
// being paid once per CONCURRENT MISS.
//
// Nothing stood between the cache probe and the sign, so every handshake that
// arrived for one host while the first was still signing started its own sign.
// The duplicates are pure waste — same host, same CA, same shared leaf key,
// same 24h window, and the last writer simply overwrites the others in the
// cache — and the amplification GROWS WITH CORE COUNT, because what bounds the
// herd is how many signs can be in flight at once. Measured on a 4-core box
// (64 workers over 256 cold hosts, internal/ca/signflight_bench_test.go):
//
//	GOMAXPROCS=1   256 signs for 256 hosts   1.00x   <- the control: no
//	                                                    concurrency, no waste
//	GOMAXPROCS=4   430-546 signs             1.7-2.1x
//
// i.e. on four cores roughly half the signing work was already redundant, and
// the 16/32-core hardware the appliance ships to sits further up that curve.
// The shape is the one this tree has recorded five times over (threatfeed,
// connlimit, the IP filter, the latency histogram, topHosts): adding cores
// stops buying throughput. Here it is worse than a shared cache line, because
// each duplicate is 144 us of elliptic-curve math and 19.6 KB of garbage, and
// it lands during exactly the cold-cache burst the cache exists to absorb —
// a restart, a TTL boundary (entries are created by traffic and expire on a
// uniform 1h TTL, so a working set goes cold together), or a traffic spike.
//
// The fix is the leader/follower single flight this tree already uses for
// hostIPCache (CHAOS-60/64), jwksCache (CHAOS-49) and internal/ocsp
// (CHAOS-65(7)) — GetCert was the one remaining hot cache without it. It is a
// COST change only: the follower receives the leader's certificate, which is
// the certificate it would have signed itself, and the cache, its TTL, the
// LRU, the CA-validity refusal and the fail-closed posture are all untouched.
//
// Four invariants, each of which this tree learned the hard way somewhere else:
//
//  1. The leader PUBLISHES ON EVERY EXIT PATH, INCLUDING A PANIC. A leader that
//     died without closing its channel would strand every follower forever —
//     turning a bounded CPU cost into a permanent handshake hang, strictly
//     worse than the defect being fixed. This is the defect CHAOS-60 introduced
//     inside its own fix and caught in review; here the publish is deferred and
//     a leader that produced neither certificate nor error is reported as
//     ErrSignAbandoned rather than as (nil, nil), which crypto/tls would
//     otherwise turn into an opaque "no certificates configured".
//
//  2. NO FOLLOWER TIMER. Releasing a follower on a timer would release it to
//     start exactly the sign being collapsed. The leader's work is bounded CPU,
//     not I/O, and the connection's own handshake deadline is the outer bound.
//
//  3. THE CACHE IS RE-CHECKED BEFORE A FLIGHT IS OPENED. The caller's probe
//     happened earlier; a handshake descheduled while the leader finished would
//     otherwise open a NEW flight and sign again for a certificate already
//     cached — defeating the collapsing during precisely the cold-cache burst
//     it exists for (the CHAOS-65 finding).
//
//  4. LOCK ORDER IS flightMu -> mu, AND IT IS THE ONLY ORDER THIS FILE TAKES.
//     mu is never held while flightMu is acquired. signLeaf and storeLeaf both
//     run with flightMu RELEASED, so a 144 us sign never blocks another host's
//     flight bookkeeping.
//
// Accounting is deliberately unchanged in meaning: cacheHits + cacheMisses
// still equals the number of GetCert calls, and a follower is still a MISS
// (it did miss the cache) — it is simply a miss served without signing. The
// collapsing itself gets its own counter, signFlightsJoined, mirroring
// culvert_ocsp_singleflight_joined_total.

// ErrSignAbandoned is returned to the followers of a leaf-signing flight whose
// leader exited without producing either a certificate or an error — reachable
// only through a panic inside the signing path. It is fail-closed: the
// handshake is refused rather than completed with no certificate.
var ErrSignAbandoned = errors.New("ca: leaf signing abandoned")

// signFlight is one in-progress leaf signing for one host.
//
// cert and err are written by the leader BEFORE done is closed and read by
// followers only AFTER receiving from it, so the close/receive pair carries the
// happens-before edge and no additional synchronisation is needed.
type signFlight struct {
	done chan struct{}
	cert *tls.Certificate
	err  error
}

// signFlightState is embedded in Manager. It is deliberately a separate struct
// so the ordering rule above is local: nothing outside this file touches
// flightMu.
type signFlightState struct {
	flightMu sync.Mutex
	flights  map[string]*signFlight

	// signFlightsJoined counts misses served by joining an in-progress flight —
	// i.e. the signs that did NOT happen. Lock-free; no identity data.
	signFlightsJoined atomic.Int64
}

// SignFlightsJoined returns the number of leaf-cache misses that were served by
// joining an in-progress sign instead of starting one (CA single flight).
//
// It is the operator's measure of how much duplicate signing the collapsing is
// absorbing: a value that tracks culvert_cert_cache_misses_total means the
// gateway is in a cold-cache burst and the herd is being collapsed; a flat zero
// on a node that inspects traffic means misses are arriving far enough apart
// that none overlap, which is the healthy steady state.
func (cm *Manager) SignFlightsJoined() int64 { return cm.signFlightsJoined.Load() }

// signOnce returns a leaf certificate for host, collapsing concurrent misses
// for the same host onto ONE sign. The caller has already probed the cache and
// charged the miss.
func (cm *Manager) signOnce(host string) (*tls.Certificate, error) {
	cm.flightMu.Lock()
	// Invariant 3: re-check under flightMu. The caller's probe is already stale
	// by the time we get here if a leader finished in between, and signing again
	// for a cached certificate is the exact waste this file exists to remove.
	// Counted as a miss (it was one) — just a miss served without signing, so
	// cacheHits + cacheMisses still equals the GetCert call count.
	if cert, ok := cm.cachedLeaf(host, time.Now()); ok {
		cm.flightMu.Unlock()
		return cert, nil
	}
	if f, ok := cm.flights[host]; ok {
		cm.flightMu.Unlock()
		cm.signFlightsJoined.Add(1)
		<-f.done // invariant 2: no timer
		return f.cert, f.err
	}
	f := &signFlight{done: make(chan struct{})}
	if cm.flights == nil {
		cm.flights = make(map[string]*signFlight)
	}
	cm.flights[host] = f
	cm.flightMu.Unlock()

	// Invariant 1: publish on every exit path, panic included.
	defer func() {
		if f.cert == nil && f.err == nil {
			f.err = ErrSignAbandoned
		}
		cm.flightMu.Lock()
		// Compare identity, not presence: a ClearCache/rotation between our
		// registration and here cannot replace the entry, but deleting by key
		// alone would be a latent way to evict a successor's flight.
		if cur, ok := cm.flights[host]; ok && cur == f {
			delete(cm.flights, host)
		}
		cm.flightMu.Unlock()
		close(f.done)
	}()

	// Invariant 4: the sign and the store run with flightMu released.
	//
	// SignLatencyObserver stays on this branch and only this branch: it measures
	// how long a SIGN takes, and a follower performs none. That is the contract
	// TestCertSignHistogram_ObservesSignOnly already pins for a cache hit, now
	// holding for a collapsed miss too — culvert_cert_sign_duration_seconds_count
	// remains exactly the number of signs.
	// One clock read serves both the latency observation and the entry's TTL
	// stamp, as it did before: the stamp is taken BEFORE the sign, so the TTL
	// never counts the sign's own duration as freshness.
	now := time.Now()
	cert, err := cm.signLeaf(host)
	if err != nil {
		f.err = err
		return nil, err
	}
	if SignLatencyObserver != nil {
		SignLatencyObserver(time.Since(now).Seconds())
	}
	cm.storeLeaf(host, cert, now)
	f.cert = cert
	return cert, nil
}
