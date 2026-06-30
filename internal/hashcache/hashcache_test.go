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
// non-expired entries must drop ~25 % rather than grow unbounded.
func TestSet_EvictsUnderCapacity(t *testing.T) {
	const capacity = 8
	c := New(capacity, time.Hour)
	for i := 0; i < capacity; i++ {
		c.Set(string(rune('a'+i)), ScanCacheResult{Clean: true})
	}
	if _, _, size := c.Stats(); size != capacity {
		t.Fatalf("size at capacity = %d, want %d", size, capacity)
	}
	// One more Set triggers evictLocked; with no expired entries it drops
	// maxSize/4 (=2), then inserts the new key.
	c.Set("overflow", ScanCacheResult{Clean: true})
	_, _, size := c.Stats()
	if size > capacity {
		t.Errorf("size after overflow = %d, must not exceed maxSize %d", size, capacity)
	}
	if size != capacity-(capacity/4)+1 {
		t.Errorf("size after overflow = %d, want %d (dropped maxSize/4 then inserted 1)", size, capacity-(capacity/4)+1)
	}
}

func TestSet_EvictsExpiredFirst(t *testing.T) {
	const capacity = 4
	c := New(capacity, time.Millisecond)
	for i := 0; i < capacity; i++ {
		c.Set(string(rune('a'+i)), ScanCacheResult{Clean: true})
	}
	time.Sleep(5 * time.Millisecond) // all entries now expired
	// Next Set hits capacity → evictLocked clears the expired ones first,
	// leaving room without resorting to the 25 % drop.
	c.Set("fresh", ScanCacheResult{Clean: true})
	if _, ok := c.Get("fresh"); !ok {
		t.Error("freshly inserted entry should be present")
	}
}
