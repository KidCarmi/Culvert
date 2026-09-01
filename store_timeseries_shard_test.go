package main

// store_timeseries_shard_test.go — correctness + regression gates for the
// sharded per-minute time series (store.go).
//
// The change removed a process-wide mutex from a path every proxied request
// runs. What it must NOT remove is the accounting: the series is what the
// dashboard sparkline, /api/stats and the history-store disk estimate are
// computed from, so the load-bearing property is CONSERVATION — every recorded
// request shows up exactly once in the 60-minute window.
//
// The performance gate here is deliberately STRUCTURAL rather than a timing
// ratio: it holds ts.mu and requires the record path to complete anyway. That
// is deterministic on any hardware, under any load, with or without -race —
// the same reasoning that made TestBenchGate_IPFilterAllowedTakesNoLock and
// internal/connlimit's TestBenchGate_DistinctIPsDoNotShareALock structural.
// A scaling-ratio gate was rejected for the same reason those were: a gate
// that can flake gets muted.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// withFreshTimeSeries swaps the package-global series for an isolated one, so
// these tests are not perturbed by counts other tests in the binary recorded
// (the suite runs shuffled under the determinism gate).
func withFreshTimeSeries(t *testing.T) {
	t.Helper()
	prev := ts
	ts = &timeSeries{}
	t.Cleanup(func() { ts = prev })
}

// tsWindowTotals sums the whole 60-minute window.
func tsWindowTotals() (total, allowed, blocked int64) {
	tot, alw, blk := tsGet()
	for i := range tot {
		total += tot[i]
		allowed += alw[i]
		blocked += blk[i]
	}
	return
}

// TestTimeSeries_ConcurrentRecordsAreConserved is the central invariant. Under
// concurrency a request can be descheduled between reading liveMin and
// incrementing, landing in the next minute's accumulator — an at-most-one-
// bucket attribution shift that is explicitly accepted. What is NOT accepted is
// losing it, which is what a fold that zeroed instead of swapping would do.
func TestTimeSeries_ConcurrentRecordsAreConserved(t *testing.T) {
	withFreshTimeSeries(t)

	const goroutines, perGoroutine = 8, 2000
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				// A deterministic 3:1 allow:block mix.
				tsRecordResult(i%4 != 0)
			}
		}(g)
	}
	wg.Wait()

	want := int64(goroutines * perGoroutine)
	total, allowed, blocked := tsWindowTotals()
	if total != want {
		t.Errorf("total = %d, want %d (records were lost or double-counted)", total, want)
	}
	if allowed+blocked != want {
		t.Errorf("allowed+blocked = %d, want %d", allowed+blocked, want)
	}
	if wantBlocked := want / 4; blocked != wantBlocked {
		t.Errorf("blocked = %d, want %d (verdict split must survive sharding)", blocked, wantBlocked)
	}
}

// TestTimeSeries_ConservedAcrossRollover folds the live shards underneath
// running writers: a fold that zeroed a shard instead of swapping it would
// silently drop every increment that landed between the read and the reset.
//
// The number of records is not fixed in advance — the writers run until told to
// stop and count themselves — so the assertion is exact regardless of how the
// scheduler interleaves them. Only 20 rollovers are driven, well inside the
// 60-bucket ring, so nothing legitimately ages out of the window.
func TestTimeSeries_ConservedAcrossRollover(t *testing.T) {
	withFreshTimeSeries(t)

	const writers, rollovers = 4, 20
	var recorded atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup

	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tsRecordResult(true)
				recorded.Add(1)
			}
		}()
	}

	base := time.Now().Unix() / 60
	for k := 1; k <= rollovers; k++ {
		time.Sleep(time.Millisecond)
		ts.rollover(base + int64(k))
	}
	close(stop)
	wg.Wait()

	// Fold the tail so nothing is still sitting in the shards, then read the
	// ring directly — the windowed view is relative to ts.cur, which moved.
	ts.mu.Lock()
	ts.foldLiveLocked()
	var total int64
	for i := range ts.buckets {
		total += ts.buckets[i]
	}
	ts.mu.Unlock()

	if want := recorded.Load(); total != want {
		t.Errorf("total across %d rollovers = %d, want %d (a fold raced a writer and dropped it)", rollovers, total, want)
	}
}

// TestTimeSeries_ReadDoesNotDrain pins that tsGet is side-effect-free. The live
// shards are summed in, not swapped out — if a read drained them the dashboard
// would report traffic once and then show zero on the very next poll.
func TestTimeSeries_ReadDoesNotDrain(t *testing.T) {
	withFreshTimeSeries(t)

	for i := 0; i < 25; i++ {
		tsRecordResult(true)
	}
	first, _, _ := tsWindowTotals()
	second, _, _ := tsWindowTotals()
	if first != 25 || second != 25 {
		t.Fatalf("reads = %d then %d, want 25 both (tsGet must not drain the live shards)", first, second)
	}
}

// TestTimeSeries_FoldLandsInTheMinuteItBelongsTo pins the attribution the fold
// is responsible for: counts recorded before a rollover belong to the bucket
// that was current when they were recorded, not to the new one.
func TestTimeSeries_FoldLandsInTheMinuteItBelongsTo(t *testing.T) {
	withFreshTimeSeries(t)

	for i := 0; i < 7; i++ {
		tsRecordResult(true)
	}
	// Advance one minute. The seven above belong to the OLD bucket.
	ts.rollover(ts.liveMin.Load() + 1)
	for i := 0; i < 3; i++ {
		tsRecordResult(false)
	}

	total, _, _ := tsGet()
	if got := total[59]; got != 3 {
		t.Errorf("current bucket = %d, want 3 (post-rollover records only)", got)
	}
	if got := total[58]; got != 7 {
		t.Errorf("previous bucket = %d, want 7 (pre-rollover records folded there)", got)
	}
}

// TestTimeSeries_AdvanceBeyondWindowWipesRing carries over the old tsAdvance
// contract: a gap longer than the window clears it rather than replaying
// thousands of no-op steps.
func TestTimeSeries_AdvanceBeyondWindowWipesRing(t *testing.T) {
	withFreshTimeSeries(t)

	tsRecordResult(true)
	ts.rollover(ts.liveMin.Load() + 500)

	total, _, _ := tsWindowTotals()
	if total != 0 {
		t.Errorf("window total after a 500-minute gap = %d, want 0", total)
	}
}

// TestTimeSeries_ClockGoingBackwardsDoesNotCorruptTheRing carries over the old
// diff <= 0 branch: a backwards clock must not rewind ts.cur or wipe buckets.
func TestTimeSeries_ClockGoingBackwardsDoesNotCorruptTheRing(t *testing.T) {
	withFreshTimeSeries(t)

	for i := 0; i < 4; i++ {
		tsRecordResult(true)
	}
	ts.mu.Lock()
	curBefore := ts.cur
	ts.mu.Unlock()

	ts.rollover(ts.liveMin.Load() - 5) // clock stepped backwards

	ts.mu.Lock()
	curAfter := ts.cur
	ts.mu.Unlock()
	if curAfter != curBefore {
		t.Errorf("cur moved %d -> %d on a backwards clock, want unchanged", curBefore, curAfter)
	}
	if total, _, _ := tsWindowTotals(); total != 4 {
		t.Errorf("window total = %d, want 4 (a backwards clock must not drop counts)", total)
	}
}

// TestBenchGate_TimeSeriesRecordTakesNoLock is the structural regression gate.
// It holds the ring mutex — the lock the old implementation took on EVERY
// request — and requires the record path to complete anyway. If tsRecordResult
// ever goes back to serialising on ts.mu this deadlocks and the test fails on
// its timeout, deterministically, on any hardware.
func TestBenchGate_TimeSeriesRecordTakesNoLock(t *testing.T) {
	// A minute boundary crossing mid-gate is a legitimate reason to need the
	// lock (that is what a rollover is for), so it is retried rather than
	// reported as a regression. The window is microseconds wide, so the retry
	// is effectively never taken; it exists so the gate can never flake.
	for attempt := 0; attempt < 3; attempt++ {
		withFreshTimeSeries(t)
		startMin := time.Now().Unix() / 60

		// Arm liveMin so the record path takes its steady-state branch.
		tsRecordResult(true)

		done := make(chan struct{})
		ts.mu.Lock()
		go func() {
			defer close(done)
			for i := 0; i < 1000; i++ {
				tsRecordResult(i%2 == 0)
			}
		}()

		select {
		case <-done:
			ts.mu.Unlock()
			if total, _, _ := tsWindowTotals(); total != 1001 {
				t.Errorf("total = %d, want 1001", total)
			}
			return
		case <-time.After(5 * time.Second):
			ts.mu.Unlock()
			<-done // let the blocked goroutine finish now that the lock is free
			if time.Now().Unix()/60 != startMin {
				continue // rolled a real minute — a lock here is correct
			}
			t.Fatal("REGRESSION: tsRecordResult blocked on ts.mu — the per-request path must not take the ring lock")
		}
	}
	t.Fatal("gate did not complete inside a single wall-clock minute after 3 attempts")
}

// TestTimeSeriesShards_DistributionIsNotDegenerate is the control for the gate
// above: a passing no-lock gate would also pass if every request piled onto ONE
// shard, which is the contended cache line this change exists to remove. Real
// traffic must spread.
func TestTimeSeriesShards_DistributionIsNotDegenerate(t *testing.T) {
	var used int
	// A rollover mid-loop drains the shards, which would understate the spread
	// through no fault of the index. Retry in that case; the loop is
	// microseconds wide so this is effectively never taken.
	for attempt := 0; attempt < 3; attempt++ {
		withFreshTimeSeries(t)
		const n = tsShardCount * 50
		tsRecordResult(true)
		armed := ts.liveMin.Load()
		for i := 0; i < n; i++ {
			tsRecordResult(true)
		}
		if ts.liveMin.Load() != armed {
			continue // rolled a real minute — shards were legitimately folded away
		}
		used = 0
		ts.mu.Lock()
		for i := range ts.live {
			if ts.live[i].total > 0 {
				used++
			}
		}
		ts.mu.Unlock()
		break
	}

	// With n = 50x the shard count, the chance of leaving even a quarter of the
	// shards untouched is vanishing; anything near 1 means the index collapsed.
	if used < tsShardCount*3/4 {
		t.Errorf("only %d/%d shards used — shard selection collapsed, so the counters still share a cache line", used, tsShardCount)
	}
}

// TestTimeSeries_ShardCountIsAPowerOfTwo pins the assumption tsShardIndex's
// mask depends on. A non-power-of-two would silently bias the distribution.
func TestTimeSeries_ShardCountIsAPowerOfTwo(t *testing.T) {
	if tsShardCount == 0 || tsShardCount&(tsShardCount-1) != 0 {
		t.Fatalf("tsShardCount = %d, want a power of two (tsShardIndex masks)", tsShardCount)
	}
}
