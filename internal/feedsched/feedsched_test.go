package feedsched

import (
	"context"
	"sync"
	"testing"
	"time"
)

// ── Fake clock/timer seams ────────────────────────────────────────────────────
//
// The whole point of the seams is that the cadence contract is asserted without
// sleeping: every gate below runs in microseconds and is deterministic under
// -race and -shuffle.

type fakeTimer struct {
	ch    chan time.Time
	clock *fakeClock
}

func (f *fakeTimer) C() <-chan time.Time { return f.ch }
func (f *fakeTimer) Stop() bool          { return true }
func (f *fakeTimer) Reset(d time.Duration) bool {
	f.clock.record(d)
	return true
}

type fakeClock struct {
	mu     sync.Mutex
	delays []time.Duration
	timer  *fakeTimer
}

func (c *fakeClock) record(d time.Duration) {
	c.mu.Lock()
	c.delays = append(c.delays, d)
	c.mu.Unlock()
}

func (c *fakeClock) NewTimer(d time.Duration) Timer {
	c.record(d)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.timer = &fakeTimer{ch: make(chan time.Time), clock: c}
	return c.timer
}

func (c *fakeClock) all() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.delays...)
}

// noJitter makes delays exactly reproducible; jitter itself is gated separately.
func noJitter(d time.Duration) time.Duration { return d }

// ── Cadence contract ──────────────────────────────────────────────────────────

// TestNextDelay_SuccessUsesInterval_FailureBacksOff is the core contract: a
// failed round must NOT wait a full interval.
//
// This is the DEFECT GATE for the bare-ticker shape both older feeds shipped.
// A time.NewTicker(interval) returns `interval` here regardless of outcome, so
// the failure arm below fails against the pre-fix behavior by construction.
func TestNextDelay_SuccessUsesInterval_FailureBacksOff(t *testing.T) {
	s := New(Config{
		Interval:   func() time.Duration { return 6 * time.Hour },
		BackoffMin: 5 * time.Minute,
		BackoffMax: 1 * time.Hour,
		Jitter:     noJitter,
		Clock:      &fakeClock{},
	})

	if got := s.NextDelay(true); got != 6*time.Hour {
		t.Fatalf("success delay = %s, want the configured interval 6h", got)
	}

	want := []time.Duration{5 * time.Minute, 10 * time.Minute, 20 * time.Minute, 40 * time.Minute, time.Hour, time.Hour}
	for i, w := range want {
		got := s.NextDelay(false)
		if got != w {
			t.Fatalf("failure %d: delay = %s, want %s", i+1, got, w)
		}
		if got >= 6*time.Hour {
			t.Fatalf("failure %d: retry delay %s reached the full sync interval — a failed round must be retried sooner", i+1, got)
		}
	}
}

// TestNextDelay_SuccessResetsBackoff — a recovered feed returns to its normal
// cadence immediately; the failure count must not be sticky.
func TestNextDelay_SuccessResetsBackoff(t *testing.T) {
	s := New(Config{
		Interval:   func() time.Duration { return 6 * time.Hour },
		BackoffMin: 5 * time.Minute,
		BackoffMax: time.Hour,
		Jitter:     noJitter,
		Clock:      &fakeClock{},
	})
	for i := 0; i < 5; i++ {
		s.NextDelay(false)
	}
	if s.Failures() != 5 {
		t.Fatalf("Failures() = %d, want 5", s.Failures())
	}
	if got := s.NextDelay(true); got != 6*time.Hour {
		t.Fatalf("post-recovery delay = %s, want 6h", got)
	}
	if s.Failures() != 0 {
		t.Fatalf("Failures() = %d after a success, want 0", s.Failures())
	}
	if got := s.NextDelay(false); got != 5*time.Minute {
		t.Fatalf("first failure after recovery = %s, want the initial backoff 5m", got)
	}
}

// TestBackoffCeilingIsClampedToInterval — the CONTROL on the retry direction.
//
// A retry ceiling above the steady-state interval would mean a failing feed
// attempts LESS often than a healthy one: the recovery mechanism becomes an
// extra delay. New clamps it, so a caller cannot express that shape.
func TestBackoffCeilingIsClampedToInterval(t *testing.T) {
	s := New(Config{
		Interval:   func() time.Duration { return 30 * time.Minute },
		BackoffMin: 5 * time.Minute,
		BackoffMax: 12 * time.Hour, // absurd: far above the interval
		Jitter:     noJitter,
		Clock:      &fakeClock{},
	})
	for i := 0; i < 20; i++ {
		d := s.NextDelay(false)
		if d > 30*time.Minute {
			t.Fatalf("failure %d: backoff %s exceeded the 30m interval — retrying must only tighten the cadence", i+1, d)
		}
	}
}

// TestBackoffNeverExceedsAnIntervalShorterThanTheFloor is the gate the
// ceiling-clamp test above was too weak to be: it uses an interval BELOW
// BackoffMin.
//
// Codex review of PR #1305 found the original code raised the clamped ceiling
// back up to the floor, so an admin running `-feed-sync-interval 1m` against a
// 5 m floor got a failed round retried FIVE TIMES LATER than a healthy sync —
// the bare-ticker regression this package exists to remove, reintroduced
// inside the fix. The invariant is one sentence and it must hold at every
// interval, not just comfortable ones:
//
//	a retry is never later than the configured cadence.
func TestBackoffNeverExceedsAnIntervalShorterThanTheFloor(t *testing.T) {
	for _, iv := range []time.Duration{time.Minute, 2 * time.Minute, 30 * time.Second, 5 * time.Minute} {
		s := New(Config{
			Interval:   func() time.Duration { return iv },
			BackoffMin: 5 * time.Minute,
			BackoffMax: time.Hour,
			Jitter:     noJitter,
			Clock:      &fakeClock{},
		})
		for i := 0; i < 12; i++ {
			d := s.NextDelay(false)
			if d > iv {
				t.Fatalf("interval %s, failure %d: retry delay %s is LATER than the healthy cadence — retrying must only tighten it", iv, i+1, d)
			}
			if d <= 0 {
				t.Fatalf("interval %s, failure %d: non-positive delay %s would hot-loop", iv, i+1, d)
			}
		}
	}
}

// TestRetryRateIsBounded is the other CONTROL. A scheduler that retried
// IMMEDIATELY would satisfy "a failure is retried before the next interval"
// while being far worse than the defect: an unbounded hot loop against a
// third-party feed origin, which is how a customer's egress IP gets blocked.
func TestRetryRateIsBounded(t *testing.T) {
	s := New(Config{
		Interval: func() time.Duration { return 6 * time.Hour },
		Jitter:   noJitter,
		Clock:    &fakeClock{},
	})
	for i := 0; i < 50; i++ {
		if d := s.NextDelay(false); d < DefaultBackoffMin {
			t.Fatalf("failure %d: retry delay %s is below the %s floor", i+1, d, DefaultBackoffMin)
		}
	}
}

// TestJitterStaysWithinFractionAndIsStable — fleet spread, and reproducible
// within a node.
func TestJitterStaysWithinFractionAndIsStable(t *testing.T) {
	j := StableJitter(0.10)
	base := time.Hour
	first := j(base)
	if first < 54*time.Minute || first > 66*time.Minute {
		t.Fatalf("jittered %s outside ±10%% of %s", first, base)
	}
	for i := 0; i < 10; i++ {
		if got := j(base); got != first {
			t.Fatalf("jitter is not stable: %s then %s", first, got)
		}
	}
	if got := j(0); got != 0 {
		t.Fatalf("jitter(0) = %s, want 0", got)
	}
}

// TestJitterSpreadsAcrossNodes — two independently constructed schedulers must
// not share an offset, or a fleet stays in phase (the thundering-herd half of
// the finding).
func TestJitterSpreadsAcrossNodes(t *testing.T) {
	base := time.Hour
	seen := make(map[time.Duration]bool)
	for i := 0; i < 32; i++ {
		seen[StableJitter(0.10)(base)] = true
	}
	if len(seen) < 8 {
		t.Fatalf("32 nodes produced only %d distinct offsets — jitter is not spreading the fleet", len(seen))
	}
}

// ── Loop behaviour ────────────────────────────────────────────────────────────

// TestRun_ImmediateRoundThenBackoffOnFailure covers the cold-start case that
// makes this finding severe: a node whose FIRST sync fails (empty on-disk DB,
// feed origin down) must re-attempt on the backoff schedule, not after a full
// interval, because until it succeeds it is enforcing with no intelligence.
func TestRun_ImmediateRoundThenBackoffOnFailure(t *testing.T) {
	clock := &fakeClock{}
	rounds := make(chan struct{}, 4)
	s := New(Config{
		Interval:   func() time.Duration { return 6 * time.Hour },
		BackoffMin: 5 * time.Minute,
		BackoffMax: time.Hour,
		Jitter:     noJitter,
		Clock:      clock,
		RunNow:     func() bool { return true },
		Run: func(context.Context) bool {
			rounds <- struct{}{}
			return false
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	// The immediate cold-start round.
	waitRound(t, rounds)
	// Its outcome (failure) must have scheduled the FIRST timer at the backoff.
	waitDelay(t, clock, 1)
	if d := clock.all()[0]; d != 5*time.Minute {
		t.Fatalf("first scheduled delay after a failed cold-start round = %s, want 5m", d)
	}

	// Fire it; the second failure must double.
	fire(t, clock)
	waitRound(t, rounds)
	waitDelay(t, clock, 2)
	if d := clock.all()[1]; d != 10*time.Minute {
		t.Fatalf("second delay = %s, want 10m", d)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after ctx cancellation")
	}
}

// TestRun_CancellationIsPromptDuringABackoffWait — shutdown must never wait out
// a retry delay. The scheduler is parked on a timer that will never fire here,
// so only the ctx branch can return.
func TestRun_CancellationIsPromptDuringABackoffWait(t *testing.T) {
	clock := &fakeClock{}
	s := New(Config{
		Interval: func() time.Duration { return 6 * time.Hour },
		Jitter:   noJitter,
		Clock:    clock,
		Run:      func(context.Context) bool { return true },
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	waitDelay(t, clock, 1)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run blocked in its wait after ctx cancellation — a shutdown would have to wait out the delay")
	}
}

// TestRun_PanickingRoundIsContainedAndChargedAsFailure — a panic in a feed body
// (third-party input the operator does not control) must cost ONE window and
// back off, not kill an in-line gateway and not stall the loop forever.
func TestRun_PanickingRoundIsContainedAndChargedAsFailure(t *testing.T) {
	clock := &fakeClock{}
	rounds := make(chan struct{}, 4)
	var panics int
	var mu sync.Mutex
	s := New(Config{
		Interval:   func() time.Duration { return 6 * time.Hour },
		BackoffMin: 5 * time.Minute,
		Jitter:     noJitter,
		Clock:      clock,
		RunNow:     func() bool { return true },
		OnPanic: func(any) {
			mu.Lock()
			panics++
			mu.Unlock()
		},
		Run: func(context.Context) bool {
			rounds <- struct{}{}
			panic("hostile feed body")
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()

	waitRound(t, rounds)
	waitDelay(t, clock, 1)
	if d := clock.all()[0]; d != 5*time.Minute {
		t.Fatalf("delay after a panicking round = %s, want the 5m backoff (a panic is a failed round)", d)
	}
	// The loop is alive: fire the timer and observe a second round.
	fire(t, clock)
	waitRound(t, rounds)

	mu.Lock()
	got := panics
	mu.Unlock()
	if got < 1 {
		t.Fatal("OnPanic was never called — a contained panic must still reach the crash-recording plane")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestRun_NoImmediateRoundWaitsOneInterval — a node with a warm on-disk feed DB
// must not re-fetch at boot. That is what keeps a fleet-wide restart from
// becoming a synchronised fetch storm even before jitter spreads it.
func TestRun_NoImmediateRoundWaitsOneInterval(t *testing.T) {
	clock := &fakeClock{}
	var ran bool
	var mu sync.Mutex
	s := New(Config{
		Interval: func() time.Duration { return 6 * time.Hour },
		Jitter:   noJitter,
		Clock:    clock,
		RunNow:   func() bool { return false },
		Run: func(context.Context) bool {
			mu.Lock()
			ran = true
			mu.Unlock()
			return true
		},
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	waitDelay(t, clock, 1)
	if d := clock.all()[0]; d != 6*time.Hour {
		t.Fatalf("first delay = %s, want one full interval", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if ran {
		t.Fatal("a round ran at t=0 despite RunNow() == false")
	}
}

// TestInterval_NonPositiveDoesNotHotLoop — a misconfigured or zero interval must
// never degrade into a zero-delay loop against a third-party origin.
func TestInterval_NonPositiveDoesNotHotLoop(t *testing.T) {
	s := New(Config{
		Interval: func() time.Duration { return 0 },
		Jitter:   noJitter,
		Clock:    &fakeClock{},
	})
	if d := s.NextDelay(true); d <= 0 {
		t.Fatalf("delay for a zero interval = %s, want a positive fallback", d)
	}
	s2 := New(Config{Jitter: noJitter, Clock: &fakeClock{}}) // nil Interval
	if d := s2.NextDelay(true); d <= 0 {
		t.Fatalf("delay for a nil Interval = %s, want a positive fallback", d)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func waitRound(t *testing.T, rounds <-chan struct{}) {
	t.Helper()
	select {
	case <-rounds:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a feed round")
	}
}

// waitDelay waits until at least n delays have been recorded.
func waitDelay(t *testing.T, c *fakeClock, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(c.all()) >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d scheduled delays (saw %d)", n, len(c.all()))
}

func fire(t *testing.T, c *fakeClock) {
	t.Helper()
	c.mu.Lock()
	tm := c.timer
	c.mu.Unlock()
	if tm == nil {
		t.Fatal("no timer created yet")
	}
	select {
	case tm.ch <- time.Time{}:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out firing the scheduler timer")
	}
}
