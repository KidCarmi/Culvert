package blocklist

import (
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Reader-stall benchmarks for the feed merge (PERF-BLOCKLIST-MERGE-1).
//
//	go test -run '^$' -bench BenchmarkMergeFromLines_ReaderStall -benchtime 5x ./internal/blocklist/
//
// MergeFromLines is the writer the blocklist-feed syncer calls on every
// successful sync; IsBlocked is the reader every proxied destination calls. The
// number that matters is not how long a merge takes but how long the longest
// single IsBlocked waits while one runs, because that wait is paid by every
// request in flight at once. Each benchmark reports it as max-reader-stall-ms.
//
// The figure is wall-clock on whatever host runs it, so it includes scheduler
// and GC pauses. It is evidence for a human, deliberately not a CI assertion:
// the deterministic gate for the same contract is
// TestMergeFromLines_SteadyStateResyncTakesNoWriteLock.

// mergeStallLines builds n hosts-format feed lines, the shape of the large
// public lists ("0.0.0.0 host"), which is also NormalizeLine's dearest input.
func mergeStallLines(n int) []string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = "0.0.0.0 ads-" + strconv.Itoa(i) + ".tracker.example.com"
	}
	return lines
}

// measureReaderStall runs merge while readers hammer IsBlocked and returns the
// longest single IsBlocked observed.
func measureReaderStall(b *Store, merge func()) time.Duration {
	readers := max(2, runtime.GOMAXPROCS(0)-1)
	var (
		wg       sync.WaitGroup
		stop     atomic.Bool
		maxStall atomic.Int64
		started  sync.WaitGroup
	)
	started.Add(readers)
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Done()
			for !stop.Load() {
				t0 := time.Now()
				b.IsBlocked("www.unlisted-destination.example.org")
				d := int64(time.Since(t0))
				for cur := maxStall.Load(); d > cur && !maxStall.CompareAndSwap(cur, d); cur = maxStall.Load() {
				}
			}
		}()
	}
	started.Wait()
	merge()
	stop.Store(true)
	wg.Wait()
	return time.Duration(maxStall.Load())
}

func benchMergeReaderStall(b *testing.B, n int, resync bool) {
	lines := mergeStallLines(n)
	const feed = "https://feeds.example.net/hosts.txt"
	var worst time.Duration
	b.ReportAllocs()
	for b.Loop() {
		b.StopTimer()
		s := New()
		if resync {
			s.MergeFromLines(lines, feed)
		}
		runtime.GC()
		b.StartTimer()
		worst = max(worst, measureReaderStall(s, func() { s.MergeFromLines(lines, feed) }))
	}
	b.ReportMetric(float64(worst)/float64(time.Millisecond), "max-reader-stall-ms")
}

// First sync of a feed: every line is new, so every line is a map insert.
func BenchmarkMergeFromLines_ReaderStall_FirstSync_100k(b *testing.B) {
	benchMergeReaderStall(b, 100_000, false)
}

func BenchmarkMergeFromLines_ReaderStall_FirstSync_1M(b *testing.B) {
	benchMergeReaderStall(b, 1_000_000, false)
}

// Re-sync of an unchanged feed: the steady state, repeated on every sync
// interval for every configured feed. Nothing changes in the store.
func BenchmarkMergeFromLines_ReaderStall_Resync_100k(b *testing.B) {
	benchMergeReaderStall(b, 100_000, true)
}

func BenchmarkMergeFromLines_ReaderStall_Resync_1M(b *testing.B) {
	benchMergeReaderStall(b, 1_000_000, true)
}
