package autoexclude

import (
	"strconv"
	"sync"
	"testing"
)

// TestCache_ConcurrentObserveContainsRemoveListEvict exercises the single-RWMutex
// + atomic-hit-counter design under real goroutine contention, so `go test -race`
// actually verifies the concurrency claim. The existing coverage exercised the
// cache only from a single goroutine (unit tests) or from benchmarks — and the CI
// -race gate does NOT run benchmarks, so the RWMutex/atomic design had no
// race-detected regression guard. This closes that gap (F3).
//
// It fans ~1000 goroutines across all mutating and reading entry points
// concurrently — Observe (write lock + promotion + evictLocked sort under load,
// via a deliberately small MaxEntries), Contains (RLock + atomic hit bump), Remove
// (write lock), and List/Stats/Len (RLock snapshots) — over a shared, colliding
// key space (few scopes, many hosts) so readers and writers genuinely contend on
// the same entries. Invariants asserted after the barrier: no data race (the
// detector is the real assertion), no panic, and the bound holds (Len never
// exceeds MaxEntries).
func TestCache_ConcurrentObserveContainsRemoveListEvict(t *testing.T) {
	const (
		goroutines = 1000
		scopes     = 8
		hosts      = 512
		maxEntries = 256 // small on purpose: force eviction under load
	)
	// ConfirmN=1 so a single Observe promotes — maximizes writer churn and makes
	// the eviction path (evictLocked sort under the write lock) fire under
	// contention rather than staying in the pending map.
	c := New(Config{ConfirmN: 1, MaxEntries: maxEntries})

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			scope := "s" + strconv.Itoa(g%scopes)
			host := "h" + strconv.Itoa(g%hosts) + ".example"
			switch g % 5 {
			case 0:
				c.Observe(scope, scope, host, ReasonUnsupportedParams, "ip:"+strconv.Itoa(g))
			case 1:
				c.Contains(scope, host) // RLock + atomic hit bump on a shared entry
			case 2:
				c.Remove(scope, host)
			case 3:
				_ = c.List()
				_ = c.Stats()
			case 4:
				c.Observe(scope, scope, host, ReasonClientPinned, "id:u"+strconv.Itoa(g%3))
				_ = c.Len()
			}
		}(g)
	}
	wg.Wait()

	if got := c.Len(); got > maxEntries {
		t.Fatalf("Len()=%d exceeds MaxEntries cap %d after concurrent load — the bound leaked under contention", got, maxEntries)
	}
	// A post-barrier read path must still be race-free and internally consistent.
	if list := c.List(); len(list) > maxEntries {
		t.Fatalf("List() returned %d entries, exceeds cap %d", len(list), maxEntries)
	}
}
