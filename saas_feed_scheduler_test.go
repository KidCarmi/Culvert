package main

// saas_feed_scheduler_test.go — F3b-4: deterministic scheduler tests (fake clock/timer,
// no sleeps): no-overlap serialization, backoff + jitter, immediate wakeup, clean
// cancellation with no goroutine/timer leak.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ─── fake clock / timer seams ────────────────────────────────────────────────────

type fakeSchedTimer struct {
	c      chan time.Time
	mu     sync.Mutex
	resets []time.Duration
	stops  int
}

func newFakeSchedTimer() *fakeSchedTimer { return &fakeSchedTimer{c: make(chan time.Time, 1)} }

func (f *fakeSchedTimer) C() <-chan time.Time { return f.c }
func (f *fakeSchedTimer) Reset(d time.Duration) bool {
	f.mu.Lock()
	f.resets = append(f.resets, d)
	f.mu.Unlock()
	return true
}
func (f *fakeSchedTimer) Stop() bool {
	f.mu.Lock()
	f.stops++
	f.mu.Unlock()
	return true
}
func (f *fakeSchedTimer) fire() { f.c <- time.Time{} }
func (f *fakeSchedTimer) lastReset() (time.Duration, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resets) == 0 {
		return 0, false
	}
	return f.resets[len(f.resets)-1], true
}

type fakeSchedClock struct {
	timer *fakeSchedTimer
	now   time.Time
}

func (c *fakeSchedClock) NewTimer(time.Duration) schedTimer { return c.timer }
func (c *fakeSchedClock) Now() time.Time                    { return c.now }

// harness builds a scheduler whose refresh is a channel-synchronized stub.
type schedHarness struct {
	sched    *saasFeedScheduler
	timer    *fakeSchedTimer
	called   chan struct{}               // signalled when refresh begins
	release  chan saasFeedRefreshOutcome // test supplies the outcome to return
	calls    atomic.Int64
	inFlight atomic.Int64
	maxConc  atomic.Int64
}

func newSchedHarness(interval time.Duration) *schedHarness {
	h := &schedHarness{
		timer:   newFakeSchedTimer(),
		called:  make(chan struct{}, 8),
		release: make(chan saasFeedRefreshOutcome, 8),
	}
	h.sched = &saasFeedScheduler{
		refresh: func(ctx context.Context) saasFeedRefreshOutcome {
			h.calls.Add(1)
			cur := h.inFlight.Add(1)
			if cur > h.maxConc.Load() {
				h.maxConc.Store(cur)
			}
			h.called <- struct{}{}
			out := <-h.release
			h.inFlight.Add(-1)
			return out
		},
		interval: func() time.Duration { return interval },
		noteNext: func(time.Time) {},
		clock:    &fakeSchedClock{timer: h.timer, now: time.Unix(0, 0)},
		jitter:   func(d time.Duration) time.Duration { return d }, // identity jitter for determinism
		wake:     make(chan struct{}, 1),
	}
	return h
}

func TestF3b4_Scheduler_TickAndCadence(t *testing.T) {
	h := newSchedHarness(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.sched.run(ctx); close(done) }()

	h.timer.fire()
	<-h.called
	h.release <- refreshActivated
	// After a success, the next delay is the configured interval.
	waitReset(t, h.timer, time.Hour)

	cancel()
	<-done
	if h.calls.Load() != 1 {
		t.Errorf("expected 1 refresh, got %d", h.calls.Load())
	}
}

func TestF3b4_Scheduler_BackoffOnFailure(t *testing.T) {
	h := newSchedHarness(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.sched.run(ctx)

	// First failure ⇒ backoff min.
	h.timer.fire()
	<-h.called
	h.release <- refreshFailed
	waitReset(t, h.timer, saasFeedBackoffMin)

	// Second failure ⇒ backoff min<<1.
	h.timer.fire()
	<-h.called
	h.release <- refreshFailed
	waitReset(t, h.timer, saasFeedBackoffMin<<1)

	// Success ⇒ cadence restored to the interval.
	h.timer.fire()
	<-h.called
	h.release <- refreshActivated
	waitReset(t, h.timer, time.Hour)
	cancel()
}

func TestF3b4_Scheduler_ImmediateWakeup(t *testing.T) {
	h := newSchedHarness(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.sched.run(ctx)

	// No timer fire — a Wake alone must trigger a refresh immediately.
	h.sched.Wake()
	select {
	case <-h.called:
	case <-time.After(2 * time.Second):
		t.Fatal("Wake did not trigger an immediate refresh")
	}
	h.release <- refreshActivated
	cancel()
}

func TestF3b4_Scheduler_NoOverlap(t *testing.T) {
	h := newSchedHarness(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go h.sched.run(ctx)

	// Fire the timer AND wake while a refresh is in flight — the loop is sequential, so
	// the second trigger cannot start a concurrent refresh.
	h.timer.fire()
	<-h.called
	h.sched.Wake() // queued
	h.timer.fire() // buffered
	h.release <- refreshActivated
	<-h.called // the next (serialized) refresh begins
	h.release <- refreshActivated
	if got := h.maxConc.Load(); got > 1 {
		t.Errorf("refreshes overlapped: max concurrency %d", got)
	}
	cancel()
}

func TestF3b4_Scheduler_CleanCancel(t *testing.T) {
	h := newSchedHarness(time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { h.sched.run(ctx); close(done) }()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduler did not exit on cancellation (goroutine/timer leak)")
	}
	if h.timer.stops == 0 {
		t.Error("timer not stopped on exit (leak)")
	}
}

func TestF3b4_Scheduler_BackoffDelayBounds(t *testing.T) {
	if backoffDelay(1) != saasFeedBackoffMin {
		t.Errorf("backoff(1) = %v, want %v", backoffDelay(1), saasFeedBackoffMin)
	}
	if got := backoffDelay(100); got != saasFeedBackoffMax {
		t.Errorf("backoff(100) = %v, want clamp %v", got, saasFeedBackoffMax)
	}
	if backoffDelay(0) != saasFeedBackoffMin {
		t.Errorf("backoff(0) must floor to min")
	}
}

// waitReset polls the fake timer for a Reset with the expected delay (no sleep loop —
// bounded spin with a deadline).
func waitReset(t *testing.T, timer *fakeSchedTimer, want time.Duration) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d, ok := timer.lastReset(); ok && d == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	got, _ := timer.lastReset()
	t.Fatalf("timer not reset to %v (last = %v)", want, got)
}
