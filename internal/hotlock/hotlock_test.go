package hotlock

import (
	"sync"
	"testing"
	"time"
	"unsafe"
)

// Gates for the sharded read lock ENGINE. Each adopter carries its own gates for
// its own wiring (internal/blocklist/hotread_test.go,
// internal/urlcat/hotread_test.go); these pin the contract the engine itself
// owes both of them.

// TestWriteLockExcludesEveryShard is the whole safety argument: a writer holds
// EVERY shard, so it excludes a reader whichever shard that reader draws. Using
// TryLock makes it exhaustive and deterministic rather than a
// 1-in-ShardCount coin flip.
func TestWriteLockExcludesEveryShard(t *testing.T) {
	var h HotRW
	h.Lock()
	for i := 0; i < ShardCount; i++ {
		if h.ShardAt(i).TryRLock() {
			h.ShardAt(i).RUnlock()
			h.Unlock()
			t.Fatalf("shard %d was readable while the write lock was held: a writer no longer excludes every reader", i)
		}
	}
	h.Unlock()

	// And it must be releasable — a writer that leaves a shard locked deadlocks
	// the next reader, which is the failure mode of an asymmetric Lock/Unlock.
	done := make(chan struct{})
	go func() {
		sh := h.RLockHot()
		sh.RUnlock()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a read could not be taken after Unlock: the write lock was not fully released")
	}
}

// TestColdReadLockUsesShardZero pins the cold-reader contract: the admin and
// persist surfaces share shard 0 rather than paying for shard selection.
func TestColdReadLockUsesShardZero(t *testing.T) {
	var h HotRW
	h.RLock()
	defer h.RUnlock()

	if h.ShardAt(0).TryLock() {
		h.ShardAt(0).Unlock()
		t.Fatal("RLock did not take shard 0")
	}
	for i := 1; i < ShardCount; i++ {
		if !h.ShardAt(i).TryLock() {
			t.Fatalf("RLock took shard %d as well as shard 0; a cold reader must take exactly one", i)
		}
		h.ShardAt(i).Unlock()
	}
}

// TestHotReadsSpreadAcrossShards is the reason the engine exists. It is
// STRUCTURAL, not a timing ratio: it counts distinct shards reached, so a
// collapse back to one lock fails on any hardware, at any load, with or without
// -race. This repo has twice rejected scaling-ratio gates for this path class
// (internal/connlimit, metrics.go) because their margin narrows until they flake.
func TestHotReadsSpreadAcrossShards(t *testing.T) {
	var h HotRW
	seen := make(map[*Shard]struct{}, ShardCount)
	for i := 0; i < ShardCount*ShardCount; i++ {
		sh := h.RLockHot()
		seen[sh] = struct{}{}
		sh.RUnlock()
	}
	if len(seen) < ShardCount/2 {
		t.Fatalf("hot reads landed on %d distinct shards out of %d: the read path is sharing one lock again", len(seen), ShardCount)
	}
}

// TestShardsAreCacheLineIsolated pins the padding. Without it a sync.RWMutex is
// 24 bytes and two shards share a 64-byte line, so taking one shard's lock
// invalidates its neighbour and hands back most of what splitting the lock
// bought. It also pins RWMutexSize, which hotlock.go states as a constant so
// that a future Go release changing the struct fails the build here rather than
// silently unpadding every shard.
func TestShardsAreCacheLineIsolated(t *testing.T) {
	if got := unsafe.Sizeof(sync.RWMutex{}); got != RWMutexSize {
		t.Fatalf("sync.RWMutex is %d bytes, but RWMutexSize says %d; update the constant and re-check the padding", got, RWMutexSize)
	}
	if got := unsafe.Sizeof(Shard{}); got != CacheLineBytes {
		t.Fatalf("Shard is %d bytes, want exactly one %d-byte cache line", got, CacheLineBytes)
	}
	if ShardCount&(ShardCount-1) != 0 {
		t.Fatalf("ShardCount = %d must be a power of two: RLockHot indexes with a mask", ShardCount)
	}
}

// TestConcurrentReadersAndWriters is the -race safety net: readers on random
// shards against a writer taking all of them, over shared state. Any break in
// the exclusion surfaces as a data race on the guarded value.
func TestConcurrentReadersAndWriters(t *testing.T) {
	var h HotRW
	guarded := 0

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				sh := h.RLockHot()
				_ = guarded
				sh.RUnlock()

				h.RLock()
				_ = guarded
				h.RUnlock()
			}
		}()
	}
	for i := 0; i < 2000; i++ {
		h.Lock()
		guarded++
		h.Unlock()
	}
	close(stop)
	wg.Wait()

	if guarded != 2000 {
		t.Fatalf("guarded value = %d, want 2000", guarded)
	}
}

// BenchmarkWriteLock measures the write-side trade both adopters record: a
// writer takes ShardCount locks instead of one. Both shapes run in the same
// binary so the multiple is reproducible in-tree.
func BenchmarkWriteLock(b *testing.B) {
	b.Run("sharded", func(b *testing.B) {
		var h HotRW
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			h.Lock()
			h.Unlock()
		}
	})
	b.Run("single", func(b *testing.B) {
		var mu sync.RWMutex
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			mu.Lock()
			mu.Unlock() //nolint:staticcheck // SA2001: measuring the lock pair itself
		}
	})
}

// BenchmarkRLockHot is the read fast path, and the -cpu sweep is the point:
//
//	go test -run '^$' -bench 'BenchmarkRLockHot|BenchmarkRLockSingle' -cpu 1,2,4 ./internal/hotlock/
func BenchmarkRLockHot(b *testing.B) {
	var h HotRW
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sh := h.RLockHot()
			sh.RUnlock()
		}
	})
}

// BenchmarkRLockSingle is the shape RLockHot replaces, for the same-run
// comparison.
func BenchmarkRLockSingle(b *testing.B) {
	var mu sync.RWMutex
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			mu.RLock()
			mu.RUnlock()
		}
	})
}
