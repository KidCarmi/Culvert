package ca

import (
	"crypto/tls"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// certcache_lockfree_test.go — the gates for the leaf-cache hit path.
//
// GetCert runs once per SSL-inspected connection, so its cache-hit path is
// ~all of production on a warm gateway. It now reads the cache with NO lock
// held and allocates nothing. Both properties are invisible to every
// behavioural test in this package — a future edit could put cm.mu.RLock()
// back into cachedLeaf, or reintroduce an unconditional net.SplitHostPort, and
// the suite would stay green while the throughput ceiling and the per-
// connection garbage came back. BenchmarkGetCert_Hit measures them but cannot
// FAIL on them, and a benchmark ratio on a shared vCPU box is not a gate.
//
// So pin them deterministically instead, with no timing dependence at all.

// TestGetCert_HitPathDoesNotTakeTheManagerLock is the gate for the
// synchronisation change, and it is exact rather than statistical: it holds
// mu EXCLUSIVELY for the whole duration of a GetCert that must hit the cache.
//
// If the hit path reaches mu in any form — RLock, Lock, or a helper that does
// — this test deadlocks and the package times out with a goroutine dump
// naming the offending frame. If it does not, the call returns the cached
// leaf. There is no middle outcome and no hardware on which the answer
// differs.
func TestGetCert_HitPathDoesNotTakeTheManagerLock(t *testing.T) {
	cm := readyManager(t)
	hello := &tls.ClientHelloInfo{ServerName: "warm.example.com"}
	want, err := cm.GetCert(hello) // warm the cache (this one signs, under mu)
	if err != nil {
		t.Fatalf("warm GetCert: %v", err)
	}

	// Exclusive, not RLock: an RLock would be satisfied by a reader-side
	// regression and the gate would pass on the defect it exists to catch.
	cm.mu.Lock()
	got, err := cm.GetCert(hello)
	cm.mu.Unlock()

	if err != nil {
		t.Fatalf("GetCert with mu held: %v — the hit path must not need the manager lock", err)
	}
	if got != want {
		t.Fatalf("GetCert with mu held returned a different certificate (%p, want %p) — "+
			"it did not serve from the cache", got, want)
	}
}

// TestGetCert_HitPathDoesNotAllocate is the gate for the allocation change.
//
// The whole hit path is covered, not just cachedLeaf: the allocation this
// removed was in GetCert's own host derivation (net.SplitHostPort reports a
// missing port by allocating a *net.AddrError, and SNI never carries a port,
// so that error was allocated and discarded once per inspected connection).
func TestGetCert_HitPathDoesNotAllocate(t *testing.T) {
	cm := readyManager(t)
	hello := &tls.ClientHelloInfo{ServerName: "warm.example.com"}
	if _, err := cm.GetCert(hello); err != nil {
		t.Fatalf("warm GetCert: %v", err)
	}
	var cert *tls.Certificate
	allocs := testing.AllocsPerRun(200, func() {
		c, err := cm.GetCert(hello)
		if err != nil {
			t.Fatalf("GetCert: %v", err)
		}
		cert = c
	})
	if cert == nil {
		t.Fatal("GetCert returned no certificate; this gate measured the wrong thing")
	}
	if allocs != 0 {
		t.Fatalf("GetCert cache hit allocates %.1f objects/op, want 0 — "+
			"one allocation here is one per SSL-inspected connection", allocs)
	}
}

// TestGetCert_PortBearingServerNameStillSplits is the negative control for the
// SplitHostPort guard: skipping the split when there is no colon must not stop
// a port-bearing spelling from being split, or two spellings of one host would
// occupy two cache entries and sign twice.
func TestGetCert_PortBearingServerNameStillSplits(t *testing.T) {
	cm := readyManager(t)
	bare, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "split.example.com"})
	if err != nil {
		t.Fatalf("GetCert bare: %v", err)
	}
	withPort, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "split.example.com:443"})
	if err != nil {
		t.Fatalf("GetCert with port: %v", err)
	}
	if withPort != bare {
		t.Fatalf("ServerName %q did not resolve to the cached entry for the bare host — "+
			"the port was not stripped, so the host signs twice and caches twice", "split.example.com:443")
	}
	if n := cm.CertCacheLen(); n != 1 {
		t.Fatalf("cache holds %d entries for one host in two spellings, want 1", n)
	}
}

// TestCertCache_EntriesAreImmutableUnderConcurrentReaders pins the contract
// that makes the unlocked read legal: a stored *certCacheEntry is never
// written again. Back-dating one for a TTL test must REPLACE it, not assign
// through the pointer.
//
// Meaningful under -race (the root shard runs this package with it); without
// -race it still exercises the concurrent paths and asserts the TTL effect.
func TestCertCache_EntriesAreImmutableUnderConcurrentReaders(t *testing.T) {
	cm := readyManager(t)
	const host = "churn.example.com"
	if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: host}); err != nil {
		t.Fatalf("warm GetCert: %v", err)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			hello := &tls.ClientHelloInfo{ServerName: host}
			for !stop.Load() {
				if _, err := cm.GetCert(hello); err != nil {
					t.Errorf("concurrent GetCert: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		// Back-date past the TTL, then let the readers re-sign it. A mutating
		// implementation writes entry.createdAt while they read it.
		cm.AgeCacheEntryForTest(host, time.Now().Add(-2*certCacheTTL))
	}
	stop.Store(true)
	wg.Wait()

	// The aged entry must still be rejected by the TTL check, i.e. the
	// replacement actually took effect rather than silently no-op'ing.
	cm.AgeCacheEntryForTest(host, time.Now().Add(-2*certCacheTTL))
	if _, ok := cm.cachedLeaf(host, time.Now()); ok {
		t.Fatal("a back-dated entry was served from the cache — AgeCacheEntryForTest " +
			"no longer replaces the entry, so the TTL gates in this package prove nothing")
	}
}

// TestCertCache_LenDrivesEviction is the bookkeeping gate. sync.Map has no
// len(), so certCacheMaxSize is now enforced against the explicit cacheLen
// counter: if an insert or an eviction ever fails to move it, the LRU stops
// firing (unbounded growth) or fires forever (every connection re-signs).
//
// Seeding is used to reach the bound because signing 10 000 leaves would make
// this a minute-long test; the eviction itself is then driven by a REAL
// GetCert, which is the only path that evicts.
func TestCertCache_LenDrivesEviction(t *testing.T) {
	cm := readyManager(t)
	seed, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "seed.example.com"})
	if err != nil {
		t.Fatalf("seed GetCert: %v", err)
	}
	now := time.Now()
	// One short of the bound, counting the seed host above.
	for i := cm.CertCacheLen(); i < certCacheMaxSize; i++ {
		cm.SeedCacheEntryForTest(fmt.Sprintf("f%d.example.com", i), seed, now)
	}
	if n := cm.CertCacheLen(); n != certCacheMaxSize {
		t.Fatalf("cache len = %d after seeding to the bound, want %d", n, certCacheMaxSize)
	}

	// One more real insert crosses the bound and must evict 10%.
	if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "overflow.example.com"}); err != nil {
		t.Fatalf("overflow GetCert: %v", err)
	}
	want := certCacheMaxSize + 1 - certCacheMaxSize/10
	if n := cm.CertCacheLen(); n != want {
		t.Fatalf("cache len = %d after the insert that crosses certCacheMaxSize, want %d "+
			"(%d + 1 inserted, oldest %d evicted)", n, want, certCacheMaxSize, certCacheMaxSize/10)
	}
	// cacheOrder must have been compacted with the map, or the CHAOS-28 leak
	// returns in a new place.
	cm.mu.RLock()
	order := len(cm.cacheOrder)
	cm.mu.RUnlock()
	if order != want {
		t.Fatalf("cacheOrder = %d after eviction, cache len = %d — they must agree", order, want)
	}
}

// TestCertCache_ResetClearsTheLenCounter pins the other half of the
// bookkeeping: a CA replacement clears the map, and a counter left behind
// would make the very next insert look like an overflow and evict 1 000
// just-signed leaves.
func TestCertCache_ResetClearsTheLenCounter(t *testing.T) {
	cm := readyManager(t)
	for i := 0; i < 5; i++ {
		if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: fmt.Sprintf("r%d.example.com", i)}); err != nil {
			t.Fatalf("GetCert %d: %v", i, err)
		}
	}
	if n := cm.CertCacheLen(); n != 5 {
		t.Fatalf("cache len = %d before reset, want 5", n)
	}
	cm.ClearCache()
	if n := cm.CertCacheLen(); n != 0 {
		t.Fatalf("cache len = %d after ClearCache, want 0", n)
	}
	if _, ok := cm.cachedLeaf("r0.example.com", time.Now()); ok {
		t.Fatal("a cleared host was still served from the cache")
	}
	hits, misses, size := cm.CacheStats()
	if size != 0 {
		t.Fatalf("CacheStats size = %d after ClearCache, want 0 (hits=%d misses=%d)", size, hits, misses)
	}
}

// TestCertCache_ZeroValueManagerIsUsable pins what New() may no longer be
// relied on to do. package main's whitebox tests construct &CertManager{}
// directly, so the leaf cache must need no initialisation — which is true for
// a sync.Map and was NOT true for the map this replaced.
func TestCertCache_ZeroValueManagerIsUsable(t *testing.T) {
	cm := &Manager{}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA on a zero-value Manager: %v", err)
	}
	if _, ok := cm.cachedLeaf("absent.example.com", time.Now()); ok {
		t.Fatal("the empty cache of a zero-value Manager served an entry")
	}
	if _, err := cm.GetCert(&tls.ClientHelloInfo{ServerName: "zero.example.com"}); err != nil {
		t.Fatalf("GetCert on a zero-value Manager: %v", err)
	}
	if n := cm.CertCacheLen(); n != 1 {
		t.Fatalf("cache len = %d after one sign on a zero-value Manager, want 1", n)
	}
}
