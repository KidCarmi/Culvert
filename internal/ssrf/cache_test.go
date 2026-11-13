package ssrf

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestResultCache_BoundedUnderHighCardinality is the regression for the
// unbounded verdict cache: the key is client-controlled on CONNECT/SOCKS5, so
// a flood of distinct hostnames must never retain more than two generations.
func TestResultCache_BoundedUnderHighCardinality(t *testing.T) {
	const genCap = 64
	c := newResultCache(genCap)
	for i := 0; i < 50*genCap; i++ {
		c.Store(fmt.Sprintf("h%d.flood.test", i), false)
		if n := c.len(); n > 2*genCap {
			t.Fatalf("after %d stores cache holds %d keys, bound is %d", i+1, n, 2*genCap)
		}
	}
	// The most recent keys are still served.
	if _, ok := c.Lookup(fmt.Sprintf("h%d.flood.test", 50*genCap-1)); !ok {
		t.Error("most recent key must be cached")
	}
	// The oldest keys were dropped (re-resolved on next use; never stale).
	if _, ok := c.Lookup("h0.flood.test"); ok {
		t.Error("oldest key must have been evicted by rotation")
	}
}

// TestResultCache_HotHostSurvivesFlood: a host that keeps being looked up is
// promoted out of the retiring generation, so a one-off-key flood cannot force
// legitimate hot destinations back to DNS on every rotation.
func TestResultCache_HotHostSurvivesFlood(t *testing.T) {
	const genCap = 32
	c := newResultCache(genCap)
	c.Store("hot.test", true)
	for i := 0; i < 20*genCap; i++ {
		c.Store(fmt.Sprintf("x%d.flood.test", i), false)
		priv, ok := c.Lookup("hot.test")
		if !ok || !priv {
			t.Fatalf("hot private host lost or flipped after %d flood stores (found=%v private=%v)", i+1, ok, priv)
		}
	}
}

// TestResultCache_PromotionKeepsOriginalExpiry: promotion must never extend
// freshness past cacheTTL from the original resolution.
func TestResultCache_PromotionKeepsOriginalExpiry(t *testing.T) {
	c := newResultCache(4)
	exp := time.Now().Add(time.Second)
	c.cur["p.test"] = cacheEntry{private: true, expires: exp}
	c.mu.Lock()
	c.rotateLocked()
	c.mu.Unlock()
	if _, ok := c.Lookup("p.test"); !ok {
		t.Fatal("live previous-generation entry must be served")
	}
	c.mu.RLock()
	e, inCur := c.cur["p.test"]
	_, inPrev := c.prev["p.test"]
	c.mu.RUnlock()
	if !inCur || inPrev {
		t.Fatalf("entry must move to the current generation (inCur=%v inPrev=%v)", inCur, inPrev)
	}
	if !e.expires.Equal(exp) {
		t.Errorf("promotion changed expiry: got %v want %v", e.expires, exp)
	}
}

// TestResultCache_ExpiredNeverServedFromEitherGeneration preserves the 30 s
// maximum freshness: rotation must not make an expired verdict visible.
func TestResultCache_ExpiredNeverServedFromEitherGeneration(t *testing.T) {
	c := newResultCache(4)
	past := time.Now().Add(-time.Millisecond)
	c.cur["a.test"] = cacheEntry{private: false, expires: past}
	c.mu.Lock()
	c.rotateLocked()
	c.mu.Unlock()
	c.cur["b.test"] = cacheEntry{private: false, expires: past}
	for _, h := range []string{"a.test", "b.test"} {
		if _, ok := c.Lookup(h); ok {
			t.Errorf("expired %s served", h)
		}
	}
}

// TestResultCache_StoreSupersedesPreviousGeneration: a fresh verdict replaces
// a stale opposite verdict held in the previous generation (e.g. a host that
// re-pointed from public to private), and CacheDelete clears both generations.
func TestResultCache_StoreSupersedesPreviousGeneration(t *testing.T) {
	c := newResultCache(4)
	c.Store("flip.test", false)
	c.mu.Lock()
	c.rotateLocked()
	c.mu.Unlock()
	c.Store("flip.test", true)
	if priv, ok := c.Lookup("flip.test"); !ok || !priv {
		t.Fatalf("newer private verdict must win, got found=%v private=%v", ok, priv)
	}
	if n := c.len(); n != 1 {
		t.Errorf("a key must live in exactly one generation, cache holds %d", n)
	}

	orig := dnsCache
	dnsCache = newResultCache(4)
	t.Cleanup(func() { dnsCache = orig })
	CacheStore("del.test", true)
	CacheCleanup() // move to previous generation
	CacheDelete("del.test")
	if _, ok := dnsCache.Lookup("del.test"); ok {
		t.Error("CacheDelete must clear the previous generation too")
	}
}

// TestPrivateHost_CachedPrivateVerdictSurvivesRotation: the security verdict
// is unchanged by which generation holds it.
func TestPrivateHost_CachedPrivateVerdictSurvivesRotation(t *testing.T) {
	orig := dnsCache
	dnsCache = newResultCache(cacheGenCap)
	t.Cleanup(func() { dnsCache = orig })
	CacheStore("evil.rot.test", true)
	CacheCleanup()
	if err := PrivateHost("evil.rot.test:443"); err == nil {
		t.Fatal("cached-private host in the previous generation must still be refused")
	}
}

// TestResultCache_ConcurrentAccess exercises Store/Lookup/rotation/delete
// together under -race and checks the bound holds throughout.
func TestResultCache_ConcurrentAccess(t *testing.T) {
	const genCap = 128
	c := newResultCache(genCap)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				h := fmt.Sprintf("w%d-%d.test", w, i%300)
				c.Store(h, i%2 == 0)
				c.Lookup(h)
				c.Lookup("shared.test")
				if i%500 == 0 {
					c.mu.Lock()
					c.rotateLocked()
					c.mu.Unlock()
				}
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			c.Store("shared.test", true)
			if n := c.len(); n > 2*genCap {
				t.Errorf("bound violated under concurrency: %d", n)
				return
			}
		}
	}()
	wg.Wait()
	if n := c.len(); n > 2*genCap {
		t.Errorf("final size %d exceeds bound %d", n, 2*genCap)
	}
}

// BenchmarkResultCache_LookupHit measures the hot read path.
func BenchmarkResultCache_LookupHit(b *testing.B) {
	c := newResultCache(cacheGenCap)
	c.Store("hit.test", false)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.Lookup("hit.test")
		}
	})
}

// BenchmarkResultCache_StoreHighCardinality measures inserts of distinct keys
// including the rotation cost.
func BenchmarkResultCache_StoreHighCardinality(b *testing.B) {
	c := newResultCache(cacheGenCap)
	keys := make([]string, 1<<16)
	for i := range keys {
		keys[i] = fmt.Sprintf("h%d.bench.test", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Store(keys[i&(len(keys)-1)], false)
	}
}
