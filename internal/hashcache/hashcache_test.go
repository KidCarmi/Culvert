package hashcache

import (
	"testing"
	"time"
)

func TestNew_Defaults(t *testing.T) {
	c := New(0, 0) // non-positive ⇒ defaults applied
	if c.maxSize != 10_000 {
		t.Errorf("default maxSize = %d, want 10000", c.maxSize)
	}
	if c.ttl != time.Hour {
		t.Errorf("default ttl = %v, want 1h", c.ttl)
	}
}

func TestSHA256Hex_Deterministic(t *testing.T) {
	const want = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if got := SHA256Hex([]byte("test")); got != want {
		t.Errorf("SHA256Hex(\"test\") = %q, want %q", got, want)
	}
}

func TestGetSet_HitAndCounters(t *testing.T) {
	c := New(100, time.Minute)
	hash := SHA256Hex([]byte("payload"))
	c.Set(hash, ScanCacheResult{Clean: false, Reason: "Eicar", Source: "clamav"})

	got, ok := c.Get(hash)
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got.Reason != "Eicar" || got.Source != "clamav" || got.Clean {
		t.Errorf("unexpected result: %+v", got)
	}
	if _, ok := c.Get("missing"); ok {
		t.Error("expected miss for unknown hash")
	}
	hits, misses, size := c.Stats()
	if hits != 1 || misses != 1 || size != 1 {
		t.Errorf("Stats = (%d,%d,%d), want (1,1,1)", hits, misses, size)
	}
}

func TestGet_Expired(t *testing.T) {
	c := New(100, time.Millisecond)
	hash := SHA256Hex([]byte("ephemeral"))
	c.Set(hash, ScanCacheResult{Clean: true})
	time.Sleep(5 * time.Millisecond)
	if _, ok := c.Get(hash); ok {
		t.Error("expected miss for expired entry")
	}
}

func TestEvictAndClear(t *testing.T) {
	c := New(100, time.Minute)
	c.Set("a", ScanCacheResult{Clean: true})
	c.Set("b", ScanCacheResult{Clean: false, Source: "yara"})

	if !c.Evict("a") {
		t.Error("Evict should return true for an existing entry")
	}
	if c.Evict("a") {
		t.Error("Evict should return false after the entry is gone")
	}
	c.Clear()
	if _, _, size := c.Stats(); size != 0 {
		t.Errorf("size after Clear = %d, want 0", size)
	}
}

// TestSet_EvictsUnderCapacity exercises evictLocked: filling past maxSize with
// non-expired entries must never grow the cache, and must drop exactly one
// entry — the one closest to expiry — rather than a large arbitrary batch.
func TestSet_EvictsUnderCapacity(t *testing.T) {
	const capacity = 8
	c := New(capacity, time.Hour)
	for i := 0; i < capacity; i++ {
		// Distinct lifetimes; "c" expires soonest.
		ttl := time.Duration(10+i) * time.Minute
		if i == 2 {
			ttl = time.Minute
		}
		c.SetTTL(string(rune('a'+i)), ScanCacheResult{Clean: true}, ttl)
	}
	if _, _, size := c.Stats(); size != capacity {
		t.Fatalf("size at capacity = %d, want %d", size, capacity)
	}
	c.Set("overflow", ScanCacheResult{Clean: true})
	if _, _, size := c.Stats(); size != capacity {
		t.Errorf("size after overflow = %d, want %d (one dropped, one inserted)", size, capacity)
	}
	if _, ok := c.Get("c"); ok {
		t.Error("the entry closest to expiry must be the one evicted")
	}
	for i := 0; i < capacity; i++ {
		if k := string(rune('a' + i)); k != "c" {
			if _, ok := c.Get(k); !ok {
				t.Errorf("live entry %q dropped although a sooner-expiring one existed", k)
			}
		}
	}
	if _, ok := c.Get("overflow"); !ok {
		t.Error("the inserted entry must be present")
	}
	checkInvariants(t, c)
}

func TestSet_EvictsExpiredFirst(t *testing.T) {
	const capacity = 4
	// Generous TTL so the freshly inserted entry can never expire mid-test
	// on a slow runner (the previous 1ms-TTL + sleep version flaked in CI:
	// "fresh" itself expired between Set and Get). Expiry of the initial
	// entries is forced deterministically by backdating them instead.
	c := New(capacity, time.Hour)
	for i := 0; i < capacity; i++ {
		c.Set(string(rune('a'+i)), ScanCacheResult{Clean: true})
	}
	c.mu.Lock()
	for _, e := range c.entries {
		e.expiresAt = time.Now().Add(-time.Minute)
	}
	c.mu.Unlock()
	// Next Set hits capacity → evictLocked clears the expired ones first,
	// leaving room without resorting to the 25 % drop.
	c.Set("fresh", ScanCacheResult{Clean: true})
	if _, ok := c.Get("fresh"); !ok {
		t.Error("freshly inserted entry should be present")
	}
	if _, _, size := c.Stats(); size != 1 {
		t.Errorf("size after expired-first eviction = %d, want 1 (only the fresh entry)", size)
	}
}

// TestSetIfGeneration_RefusedAcrossClear pins the contract the scanner relies
// on (CHAOS-107): a verdict whose computation began before a Clear must not be
// stored after it, while one begun after the Clear, or with no Clear at all,
// is stored normally. Evict is a per-entry removal, not an invalidation of
// everything computed so far, so it must not advance the epoch.
func TestSetIfGeneration_RefusedAcrossClear(t *testing.T) {
	c := New(10, time.Hour)
	clean := ScanCacheResult{Clean: true, Source: "clean"}

	g0 := c.Generation()
	if !c.SetIfGeneration("a", clean, g0) {
		t.Fatal("store with the current generation must succeed")
	}
	c.Evict("a")
	if c.Generation() != g0 {
		t.Fatal("Evict must not advance the generation")
	}

	stale := c.Generation()
	c.Clear()
	if c.Generation() == stale {
		t.Fatal("Clear must advance the generation")
	}
	if c.SetIfGeneration("b", clean, stale) {
		t.Fatal("a verdict begun before Clear must be refused")
	}
	if _, ok := c.Get("b"); ok {
		t.Fatal("refused verdict must not be in the cache")
	}

	if !c.SetIfGeneration("c", clean, c.Generation()) {
		t.Fatal("a verdict begun after Clear must be stored")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("stored verdict must be readable")
	}
}

// TestInvalidate_AdvancesEpochOnEmptyCache: an empty cache says nothing about
// verdicts still being computed, so Invalidate must advance the epoch even when
// it drops nothing, and report exactly what it dropped otherwise.
func TestInvalidate_AdvancesEpochOnEmptyCache(t *testing.T) {
	c := New(10, time.Hour)
	clean := ScanCacheResult{Clean: true, Source: "clean"}

	inFlight := c.Generation()
	if n := c.Invalidate(); n != 0 {
		t.Fatalf("Invalidate on an empty cache dropped %d entries, want 0", n)
	}
	if c.Generation() == inFlight {
		t.Fatal("Invalidate must advance the generation even on an empty cache")
	}
	if c.SetIfGeneration("a", clean, inFlight) {
		t.Fatal("a verdict begun before an empty-cache Invalidate must be refused")
	}

	c.Set("x", clean)
	c.Set("y", clean)
	if n := c.Invalidate(); n != 2 {
		t.Fatalf("Invalidate dropped %d entries, want 2", n)
	}
	if _, _, size := c.Stats(); size != 0 {
		t.Fatalf("size after Invalidate = %d, want 0", size)
	}
}
