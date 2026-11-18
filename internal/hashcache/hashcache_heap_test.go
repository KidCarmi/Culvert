package hashcache

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// checkInvariants asserts the map and the expiry heap describe the same set of
// entries, every heap index is accurate, the heap property holds, and the
// cache is within its bound.
func checkInvariants(t *testing.T, c *HashCache) {
	t.Helper()
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.entries) != len(c.byExpiry) {
		t.Fatalf("map holds %d entries, heap %d", len(c.entries), len(c.byExpiry))
	}
	if len(c.entries) > c.maxSize {
		t.Fatalf("cache holds %d entries, bound is %d", len(c.entries), c.maxSize)
	}
	for i, e := range c.byExpiry {
		if e.idx != i {
			t.Fatalf("heap slot %d holds entry with idx %d", i, e.idx)
		}
		if c.entries[e.key] != e {
			t.Fatalf("heap slot %d (%q) is not the map's entry for that key", i, e.key)
		}
		if i > 0 {
			if parent := c.byExpiry[(i-1)/2]; e.expiresAt.Before(parent.expiresAt) {
				t.Fatalf("heap property violated at slot %d", i)
			}
		}
	}
}

// backdate forces key's entry to have expired, keeping the heap valid.
func backdate(c *HashCache, key string, ago time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	old := c.entries[key]
	ne := &hashCacheEntry{result: old.result, expiresAt: time.Now().Add(-ago), key: key, idx: old.idx}
	c.entries[key] = ne
	c.byExpiry[ne.idx] = ne
	fixHeap(c, ne.idx)
}

func fixHeap(c *HashCache, i int) {
	// container/heap.Fix, spelled out so the test does not depend on it.
	h := c.byExpiry
	for i > 0 {
		p := (i - 1) / 2
		if !h[i].expiresAt.Before(h[p].expiresAt) {
			break
		}
		h.Swap(i, p)
		i = p
	}
}

// TestEvict_LiveNeverDroppedWhileExpiredRemains: with a mix of live and
// expired entries, eviction consumes expired entries before any live one.
func TestEvict_LiveNeverDroppedWhileExpiredRemains(t *testing.T) {
	const capacity = 16
	c := New(capacity, time.Hour)
	for i := 0; i < capacity; i++ {
		c.Set(fmt.Sprintf("k%d", i), ScanCacheResult{Clean: true})
	}
	expired := map[string]bool{"k3": true, "k7": true, "k11": true}
	for k := range expired {
		backdate(c, k, time.Minute)
	}
	checkInvariants(t, c)
	for i := 0; i < len(expired); i++ {
		c.Set(fmt.Sprintf("new%d", i), ScanCacheResult{Clean: true})
		checkInvariants(t, c)
	}
	for i := 0; i < capacity; i++ {
		k := fmt.Sprintf("k%d", i)
		_, ok := c.Get(k)
		if expired[k] && ok {
			t.Errorf("expired %s served", k)
		}
		if !expired[k] && !ok {
			t.Errorf("live %s dropped while expired entries remained", k)
		}
	}
}

// TestEvict_ExpiredReapIsBatchBounded: a full cache in which everything has
// expired — the old worst case, which swept and deleted the whole map in one
// lock hold — reaps at most evictExpiredBatch entries per insert.
func TestEvict_ExpiredReapIsBatchBounded(t *testing.T) {
	const capacity = 10 * evictExpiredBatch
	c := New(capacity, time.Hour)
	for i := 0; i < capacity; i++ {
		c.SetTTL(fmt.Sprintf("k%d", i), ScanCacheResult{Clean: true}, time.Nanosecond)
	}
	time.Sleep(time.Millisecond)
	c.Set("fresh", ScanCacheResult{Clean: true})
	_, _, size := c.Stats()
	if want := capacity - evictExpiredBatch + 1; size != want {
		t.Fatalf("size after one insert = %d, want %d (one bounded batch reaped)", size, want)
	}
	checkInvariants(t, c)
	if _, ok := c.Get("fresh"); !ok {
		t.Fatal("fresh entry must be present")
	}
	// Keep inserting: the remaining expired entries are consumed before any
	// live one is ever dropped.
	for i := 0; i < capacity; i++ {
		c.Set(fmt.Sprintf("live%d", i), ScanCacheResult{Clean: true})
	}
	checkInvariants(t, c)
	for i := 0; i < capacity; i++ {
		if _, ok := c.Get(fmt.Sprintf("live%d", i)); !ok {
			t.Fatalf("live%d dropped", i)
		}
	}
}

// TestSet_OverwriteAtCapacityEvictsNothing: re-storing an existing key does
// not change the key count, so it must not cost another entry its slot, and
// the new lifetime replaces the old one.
func TestSet_OverwriteAtCapacityEvictsNothing(t *testing.T) {
	const capacity = 4
	c := New(capacity, time.Hour)
	for i := 0; i < capacity; i++ {
		c.Set(fmt.Sprintf("k%d", i), ScanCacheResult{Clean: true})
	}
	c.SetTTL("k0", ScanCacheResult{Clean: false, Source: "timeout"}, time.Nanosecond)
	time.Sleep(time.Millisecond)
	checkInvariants(t, c)
	for i := 1; i < capacity; i++ {
		if _, ok := c.Get(fmt.Sprintf("k%d", i)); !ok {
			t.Fatalf("overwrite of k0 evicted k%d", i)
		}
	}
	if _, ok := c.Get("k0"); ok {
		t.Fatal("the overwrite's shorter lifetime must apply")
	}
	// k0 now expires first, so it is the next eviction.
	c.Set("k4", ScanCacheResult{Clean: true})
	checkInvariants(t, c)
	c.mu.RLock()
	_, k0 := c.entries["k0"]
	c.mu.RUnlock()
	if k0 {
		t.Fatal("the expired overwrite should have been reaped first")
	}
}

// TestHeap_RandomOpsKeepInvariants drives every mutator in a deterministic
// random sequence and checks the map/heap invariants and the bound after each.
func TestHeap_RandomOpsKeepInvariants(t *testing.T) {
	const capacity = 32
	c := New(capacity, time.Hour)
	rng := rand.New(rand.NewSource(1)) //nolint:gosec // deterministic op sequence, not crypto
	keep := func(existing ScanCacheResult) bool { return !existing.Clean }
	for i := 0; i < 20_000; i++ {
		k := fmt.Sprintf("k%d", rng.Intn(3*capacity))
		ttl := time.Duration(1+rng.Intn(120)) * time.Minute
		switch op := rng.Intn(100); {
		case op < 40:
			c.SetTTL(k, ScanCacheResult{Clean: rng.Intn(2) == 0}, ttl)
		case op < 55:
			c.SetTTLUnless(k, ScanCacheResult{Clean: false, Source: "timeout"}, ttl, keep)
		case op < 70:
			c.SetIfGeneration(k, ScanCacheResult{Clean: true}, c.Generation())
		case op < 85:
			c.Evict(k)
		case op < 87:
			c.Invalidate()
		case op < 92:
			c.mu.RLock()
			_, present := c.entries[k]
			c.mu.RUnlock()
			if present {
				backdate(c, k, time.Duration(1+rng.Intn(60))*time.Second)
			}
		default:
			c.Get(k)
		}
		checkInvariants(t, c)
	}
}

// TestConcurrent_GetDuringOverwriteAndEviction runs readers against writers
// that overwrite hot keys and churn the cache through eviction. Under -race
// this pins the contract that a published entry's result/expiry are never
// written after publication (Get reads them after releasing its lock).
func TestConcurrent_GetDuringOverwriteAndEviction(t *testing.T) {
	const capacity = 64
	c := New(capacity, time.Hour)
	var readers, writers sync.WaitGroup
	stop := make(chan struct{})
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				if res, ok := c.Get(fmt.Sprintf("hot%d", i%8)); ok && res.Source == "" {
					t.Error("served a zero-value result")
					return
				}
			}
		}()
	}
	for w := 0; w < 2; w++ {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := 0; i < 5000; i++ {
				c.SetTTL(fmt.Sprintf("hot%d", i%8), ScanCacheResult{Clean: i%2 == 0, Source: "clean"}, time.Duration(1+i%5)*time.Minute)
				c.Set(fmt.Sprintf("w%d-%d", w, i), ScanCacheResult{Clean: true, Source: "clean"})
				if i%100 == 0 {
					c.Evict(fmt.Sprintf("hot%d", i%8))
				}
			}
		}(w)
	}
	var bound sync.WaitGroup
	bound.Add(1)
	done := make(chan struct{})
	go func() {
		defer bound.Done()
		for {
			if _, _, n := c.Stats(); n > capacity {
				t.Errorf("bound violated under concurrency: %d", n)
			}
			select {
			case <-done:
				return
			default:
			}
			time.Sleep(time.Millisecond)
		}
	}()
	writers.Wait() // readers run for the writers' whole lifetime
	close(stop)
	readers.Wait()
	close(done)
	bound.Wait()
	checkInvariants(t, c)
}
