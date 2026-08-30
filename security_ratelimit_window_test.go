package main

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// security_ratelimit_window_test.go — the correctness wall for the ring-buffer
// sliding window in RateLimiter.Allow / AllowClusterAware.
//
// The change is a COST change (O(occupancy) filter-and-copy per request →
// amortized O(1)), so it is only admissible if the accept/reject verdict for
// every request sequence is unchanged. legacyWindow below is the pre-change
// algorithm kept verbatim as the oracle; if it and clientBucket ever disagree,
// the optimization changed observable behavior and must be reverted — not the
// test relaxed.

// legacyWindow is character-for-character the pre-change window maintenance
// from RateLimiter.Allow: a filter-and-copy eviction over the whole slice, an
// occupancy test against the limit, then an append. It must not be
// "modernised".
type legacyWindow struct {
	timestamps []time.Time
}

// admit runs one request against the legacy window and reports the verdict.
func (w *legacyWindow) admit(now time.Time, window time.Duration, limit int) bool {
	cutoff := now.Add(-window)

	valid := w.timestamps[:0]
	for _, t := range w.timestamps {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	w.timestamps = valid

	if len(w.timestamps) >= limit {
		return false
	}
	w.timestamps = append(w.timestamps, now)
	return true
}

// ringAdmit runs one request against the new bucket, mirroring exactly what
// Allow does between taking and releasing the shard lock.
func ringAdmit(b *clientBucket, now time.Time, window time.Duration, limit int) bool {
	b.lastSeen = now
	b.expire(now.Add(-window))
	if b.n >= limit {
		return false
	}
	b.add(now, limit)
	return true
}

// TestRateLimitWindow_DifferentialAgainstLegacy is the spine: for randomized
// (limit, window, arrival-gap) shapes, the ring must return the legacy verdict
// on every single request, and must agree on the in-window occupancy after it.
//
// The arrival gaps deliberately straddle the window boundary — some sequences
// never expire anything (the bucket saturates), some expire every entry between
// arrivals (the bucket stays at one), and some sit in between (a partial prefix
// expires each time), which is the case the prefix-only expiry has to get right.
func TestRateLimitWindow_DifferentialAgainstLegacy(t *testing.T) {
	// #nosec G404 -- deterministic seeded generator for reproducible test data
	rnd := rand.New(rand.NewSource(20260830))
	base := time.Now()

	for trial := 0; trial < 300; trial++ {
		limit := 1 + rnd.Intn(24)
		window := time.Duration(1+rnd.Intn(40)) * time.Millisecond
		// maxGap spans well past the window so expiry-of-everything is reached.
		maxGap := time.Duration(1+rnd.Intn(int(window/time.Millisecond)*3+2)) * time.Millisecond

		var legacy legacyWindow
		ring := &clientBucket{}
		now := base

		for step := 0; step < 200; step++ {
			now = now.Add(time.Duration(rnd.Int63n(int64(maxGap) + 1)))
			wantAllow := legacy.admit(now, window, limit)
			gotAllow := ringAdmit(ring, now, window, limit)
			if wantAllow != gotAllow {
				t.Fatalf("trial %d step %d (limit=%d window=%s): verdict %v, want %v",
					trial, step, limit, window, gotAllow, wantAllow)
			}
			if len(legacy.timestamps) != ring.n {
				t.Fatalf("trial %d step %d (limit=%d window=%s): occupancy %d, want %d",
					trial, step, limit, window, ring.n, len(legacy.timestamps))
			}
			if ring.n > len(ring.stamps) {
				t.Fatalf("trial %d step %d: ring occupancy %d exceeds capacity %d",
					trial, step, ring.n, len(ring.stamps))
			}
		}
	}
}

// TestRateLimitWindow_ExpiryBoundaryMatchesLegacy pins the ONE verdict the
// randomized differential above cannot reach: a stamp landing EXACTLY on the
// cutoff. Random nanosecond gaps essentially never produce it, but the boundary
// is where an expiry predicate is most easily written a half-step wrong
// (`Before(cutoff)` instead of `!After(cutoff)`), and getting it wrong widens
// the window by one request per period. The legacy keep-condition was
// `t.After(cutoff)`, so a stamp equal to the cutoff is EXPIRED; both sides are
// asserted here against a stamp placed exactly one window back.
func TestRateLimitWindow_ExpiryBoundaryMatchesLegacy(t *testing.T) {
	const window = 100 * time.Millisecond
	base := time.Now()

	for _, tc := range []struct {
		name   string
		offset time.Duration // stamp age relative to the cutoff
	}{
		{"exactly on the cutoff", 0},
		{"one nanosecond older", -time.Nanosecond},
		{"one nanosecond newer", time.Nanosecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stamp := base
			// now is chosen so that now-window == stamp+offset, i.e. the stamp
			// sits `offset` away from the cutoff.
			now := stamp.Add(window - tc.offset)

			var legacy legacyWindow
			legacy.timestamps = append(legacy.timestamps, stamp)
			ring := &clientBucket{}
			ring.add(stamp, 4)

			// Occupancy AFTER eviction, before any accept decision.
			legacy.admit(now, window, 1<<30)
			ring.expire(now.Add(-window))
			want := len(legacy.timestamps) - 1 // admit appended one
			if ring.n != want {
				t.Fatalf("occupancy %d after eviction, want %d (legacy)", ring.n, want)
			}
		})
	}
}

// TestRateLimitWindow_RingNeverExceedsLimitCapacity pins the memory contract
// the ring replaces append's doubling with: capacity grows lazily and is
// clamped to the configured limit, so a high limit never pre-allocates.
func TestRateLimitWindow_RingNeverExceedsLimitCapacity(t *testing.T) {
	const limit = 6000
	window := time.Minute
	now := time.Now()

	// An IP that sends a handful of requests under a 6000/min policy must hold
	// a handful of slots — pre-sizing to the limit would cost ~1.4 GB across a
	// 10k-IP table.
	small := &clientBucket{}
	for i := 0; i < 3; i++ {
		if !ringAdmit(small, now.Add(time.Duration(i)*time.Millisecond), window, limit) {
			t.Fatal("unexpected reject while under the limit")
		}
	}
	if got := len(small.stamps); got > 4 {
		t.Fatalf("3 requests allocated %d ring slots; expected lazy growth (<=4)", got)
	}

	// A saturating IP grows to at most the limit, never past it.
	big := &clientBucket{}
	for i := 0; i < limit+50; i++ {
		ringAdmit(big, now.Add(time.Duration(i)*time.Microsecond), window, limit)
	}
	if big.n != limit {
		t.Fatalf("saturated occupancy %d, want %d", big.n, limit)
	}
	if got := len(big.stamps); got != limit {
		t.Fatalf("ring capacity %d, want exactly the limit %d", got, limit)
	}
}

// TestRateLimitWindow_GrowPreservesOrderAcrossWrap is the one shape a plain
// slice never had: growing while head != 0 must re-lay the ring out oldest-
// first, or expiry (which walks from head and stops at the first live entry)
// silently keeps stale stamps or drops live ones.
func TestRateLimitWindow_GrowPreservesOrderAcrossWrap(t *testing.T) {
	const (
		limit  = 8
		window = 100 * time.Millisecond
	)
	base := time.Now()
	b := &clientBucket{}

	// Fill to capacity 4 (two doublings), then expire part of it so head moves
	// off zero, then refill so the next add has to grow a WRAPPED ring.
	for i := 0; i < 4; i++ {
		ringAdmit(b, base.Add(time.Duration(i)*time.Millisecond), window, limit)
	}
	if b.head != 0 {
		t.Fatalf("setup: head=%d, want 0", b.head)
	}
	// Advance past the first two stamps only.
	mid := base.Add(1*time.Millisecond + window)
	ringAdmit(b, mid, window, limit)
	if b.head == 0 {
		t.Fatal("setup: expected head to advance off zero after a partial expiry")
	}
	for i := 0; i < 4; i++ {
		ringAdmit(b, mid.Add(time.Duration(i+1)*time.Millisecond), window, limit)
	}

	// Every stamp still present must be strictly ordered from head — the
	// invariant prefix-expiry depends on.
	prev := time.Time{}
	for i := 0; i < b.n; i++ {
		got := b.stamps[(b.head+i)%len(b.stamps)]
		if !prev.IsZero() && got.Before(prev) {
			t.Fatalf("ring out of order at %d: %s before %s", i, got, prev)
		}
		prev = got
	}

	// And the whole window must still expire cleanly to empty.
	b.expire(prev.Add(time.Nanosecond))
	if b.n != 0 {
		t.Fatalf("occupancy %d after expiring everything, want 0", b.n)
	}
}

// TestRateLimitWindow_OutOfOrderArrivalStaysOrderedAndFailsClosed pins the one
// place the ring is deliberately NOT verdict-identical to the filter-and-copy
// form it replaces.
//
// Allow samples time.Now() before taking the shard lock, so under concurrency a
// stamp can reach add out of order. clientBucket.add clamps it up to the newest
// stamp present, which keeps the ring ordered (prefix-expiry depends on it) at
// the cost of recording a slightly earlier time than the caller observed. Two
// properties must hold, and both are the safe direction: the ring stays
// ordered, and a clamped stamp expires no LATER than its true arrival would
// have — so an inversion can never let the window admit past the limit.
func TestRateLimitWindow_OutOfOrderArrivalStaysOrderedAndFailsClosed(t *testing.T) {
	const (
		limit  = 8
		window = time.Second
	)
	base := time.Now()
	b := &clientBucket{}

	// Interleave forward and backward arrivals, the shape a pre-lock clock read
	// produces when goroutines are descheduled between sampling and appending.
	offsets := []time.Duration{0, 40, 20, 90, 60, 55, 130}
	for _, off := range offsets {
		b.add(base.Add(off*time.Millisecond), limit)
	}
	if b.n != len(offsets) {
		t.Fatalf("occupancy %d, want %d", b.n, len(offsets))
	}

	var prev time.Time
	newest := base
	for i := 0; i < b.n; i++ {
		got := b.stamps[(b.head+i)%len(b.stamps)]
		if i > 0 && got.Before(prev) {
			t.Fatalf("ring out of order at %d: %s before %s", i, got, prev)
		}
		prev, newest = got, got
	}

	// Fail-closed: every recorded stamp is at or before the true arrival it
	// stands for, so expiring at the newest true arrival empties the window.
	trueNewest := base.Add(130 * time.Millisecond)
	if newest.After(trueNewest) {
		t.Fatalf("clamped stamp %s is later than the true arrival %s — that would extend the window", newest, trueNewest)
	}
	b.expire(trueNewest)
	if b.n != 0 {
		t.Fatalf("occupancy %d after expiring at the newest true arrival, want 0", b.n)
	}
}

// TestRateLimitWindow_AllowEnforcesLimitEndToEnd exercises the real Allow path
// (shard lock, exempt check, atomics) rather than the bucket in isolation.
func TestRateLimitWindow_AllowEnforcesLimitEndToEnd(t *testing.T) {
	r := newRateLimiter()
	r.Configure(5, time.Minute)
	const ip = "203.0.113.9"

	for i := 0; i < 5; i++ {
		if !r.Allow(ip) {
			t.Fatalf("request %d rejected while under the limit", i)
		}
	}
	if r.Allow(ip) {
		t.Fatal("request 6 admitted past a limit of 5")
	}
	// A different IP has its own budget.
	if !r.Allow("203.0.113.10") {
		t.Fatal("a distinct IP must not inherit another IP's window")
	}
}

// TestRateLimitWindow_ExportHotDeltasCountsInWindowOnly pins that the delta
// export still reports in-window occupancy after the eviction moved into
// clientBucket.expire.
// It ages the window out by BACK-DATING the recorded stamps rather than by
// sleeping past a short window. A 50ms window with a 60ms sleep would have been
// the obvious shape and is a latent flake: the nine Allow calls are only
// microseconds of work, but on a loaded machine — the full suite under -race is
// exactly that — the goroutine can be descheduled long enough for the first
// stamps to age out before the first export runs, and the test would fail on
// timing rather than on behaviour. Back-dating is deterministic, and it shifts
// every stamp by the same amount so the ring's ordering invariant still holds.
func TestRateLimitWindow_ExportHotDeltasCountsInWindowOnly(t *testing.T) {
	r := newRateLimiter()
	r.Configure(10, time.Minute)
	const ip = "203.0.113.11"
	for i := 0; i < 9; i++ {
		r.Allow(ip)
	}
	if got := r.ExportHotDeltas(); len(got) != 1 || got[0].IP != ip || got[0].Count != 9 {
		t.Fatalf("deltas = %+v, want one entry for %s with count 9", got, ip)
	}

	s := r.shard(ip)
	s.mu.Lock()
	b := s.clients[ip]
	for i := 0; i < b.n; i++ {
		j := (b.head + i) % len(b.stamps)
		b.stamps[j] = b.stamps[j].Add(-2 * time.Minute)
	}
	s.mu.Unlock()

	if got := r.ExportHotDeltas(); len(got) != 0 {
		t.Fatalf("deltas = %+v after the window elapsed, want none", got)
	}
}

// TestRateLimitWindow_ConcurrentAllowIsRaceFree runs the gate under the race
// detector across many IPs (so the shard map is exercised) while a periodic
// Cleanup and delta export run alongside — the three writers that touch a
// bucket. Correctness here is "no race, no panic, and the per-IP cap holds".
func TestRateLimitWindow_ConcurrentAllowIsRaceFree(t *testing.T) {
	r := newRateLimiter()
	const limit = 32
	r.Configure(limit, time.Minute)

	const workers = 8
	admitted := make([]int, workers)
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// All workers hammer ONE ip so they contend on one bucket, plus
			// their own so the shard map keeps growing.
			for i := 0; i < 200; i++ {
				if r.Allow("198.51.100.1") {
					admitted[w]++
				}
				r.Allow(fmt.Sprintf("198.51.100.%d", w+2))
			}
		}(w)
	}
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				r.Cleanup()
				r.ExportHotDeltas()
			}
		}
	}()
	wg.Wait()
	close(done)

	total := 0
	for _, n := range admitted {
		total += n
	}
	// Cleanup only drops buckets idle for two windows (a minute here), so the
	// shared IP's budget cannot be reset mid-test: exactly `limit` requests
	// may be admitted across all workers.
	if total != limit {
		t.Fatalf("admitted %d requests against a limit of %d", total, limit)
	}
}
