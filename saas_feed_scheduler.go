package main

// saas_feed_scheduler.go — F3b-4: the single lifecycle-owned refresh scheduler.
//
// One scheduler drives the signed feed's periodic refresh. It owns NO refresh logic —
// every wake calls the runtime's serialized runRefresh, so a scheduled tick and a manual
// refresh can never overlap (the run-mutex is the single mutual-exclusion point; the
// scheduler never holds the live-store lock during network/disk work). The scheduler is
// built entirely on injectable seams (clock, timer, jitter) so its cadence, bounded
// exponential backoff, stable per-node jitter, immediate disabled→enabled wakeup, and
// clean cancellation are all deterministically testable with a fake clock — no sleeps.
//
// Cadence: after a success/no-change the configured interval (jittered) is restored;
// after a failure the delay follows bounded exponential backoff; a valid config change
// (disabled→enabled or an authoritative interval change) fires an immediate wakeup. The
// loop exits promptly on context cancellation with no goroutine/timer leak.

import (
	"context"
	"math/rand"
	"time"
)

const (
	// saasFeedJitterFrac spreads the fleet ±10% (a stable per-node offset, not re-rolled
	// per tick) so nodes sharing a start time do not synchronize their origin fetches.
	saasFeedJitterFrac = 0.10

	// Bounded exponential backoff after a failed refresh.
	saasFeedBackoffMin = 1 * time.Minute
	saasFeedBackoffMax = 6 * time.Hour
	// saasFeedBackoffShift caps the exponent purely as an overflow guard; the max clamp
	// (saasFeedBackoffMax) does the real bounding (1m<<16 ≫ 6h, so it always clamps).
	saasFeedBackoffShift = 16
)

// schedTimer is the injectable timer seam (production wraps *time.Timer).
type schedTimer interface {
	C() <-chan time.Time
	Reset(d time.Duration) bool
	Stop() bool
}

// schedClock is the injectable clock seam.
type schedClock interface {
	NewTimer(d time.Duration) schedTimer
	Now() time.Time
}

// realSchedTimer / realSchedClock are the production seams.
type realSchedTimer struct{ t *time.Timer }

func (r realSchedTimer) C() <-chan time.Time { return r.t.C }
func (r realSchedTimer) Reset(d time.Duration) bool {
	if d < 0 {
		d = 0
	}
	return r.t.Reset(d)
}
func (r realSchedTimer) Stop() bool { return r.t.Stop() }

type realSchedClock struct{}

func (realSchedClock) NewTimer(d time.Duration) schedTimer {
	if d < 0 {
		d = 0
	}
	return realSchedTimer{t: time.NewTimer(d)}
}
func (realSchedClock) Now() time.Time { return time.Now() }

// stableJitter returns a jitter function with a per-process STABLE offset (chosen once)
// within ±frac. Deterministic per node lifetime, spread across the fleet.
func stableJitter(frac float64) func(time.Duration) time.Duration {
	off := (rand.Float64()*2 - 1) * frac // #nosec G404 -- fleet spread, not crypto; chosen once
	return func(base time.Duration) time.Duration {
		if base <= 0 {
			return base
		}
		return base + time.Duration(float64(base)*off)
	}
}

// saasFeedScheduler is the lifecycle-owned refresh loop. It is decoupled from the runtime
// via three seams (refresh / interval / noteNext) so its cadence, backoff, jitter,
// wakeup, and cancellation are unit-testable with a fake clock and a counting refresh.
type saasFeedScheduler struct {
	refresh  func(ctx context.Context) saasFeedRefreshOutcome
	interval func() time.Duration
	noteNext func(time.Time)

	clock  schedClock
	jitter func(time.Duration) time.Duration

	wake chan struct{} // buffered(1) immediate-wakeup signal

	failures int // consecutive failure count for backoff (loop-local)
}

// newSaaSFeedScheduler builds the production scheduler (real clock + stable jitter) bound
// to a runtime's serialized refresh + resolved cadence.
func newSaaSFeedScheduler(rt *saasFeedRuntime) *saasFeedScheduler {
	return &saasFeedScheduler{
		refresh:  func(ctx context.Context) saasFeedRefreshOutcome { return rt.runRefresh(ctx, "loop") },
		interval: rt.currentInterval,
		noteNext: rt.status.noteNextAttempt,
		clock:    realSchedClock{},
		jitter:   stableJitter(saasFeedJitterFrac),
		wake:     make(chan struct{}, 1),
	}
}

// Wake requests an immediate refresh (non-blocking; coalesces multiple requests). Called
// when a config change (disabled→enabled, authoritative interval/URL change) requires the
// scheduler to re-evaluate now rather than at the next tick.
func (s *saasFeedScheduler) Wake() {
	if s == nil {
		return
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// run is the loop. It performs the FIRST refresh only when woken or after the first
// (jittered) interval — startup recovery + the startup seed handle t=0, so the loop's
// first natural tick is one interval out (mirrors the release-refresh loop). Exits on
// ctx cancellation with the timer stopped (no leak).
func (s *saasFeedScheduler) run(ctx context.Context) {
	timer := s.clock.NewTimer(s.jitter(s.interval()))
	defer timer.Stop()
	s.noteNext(s.clock.Now().Add(s.interval()))
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.wake:
			// Immediate wakeup: drain the pending timer so it does not double-fire.
			if !timer.Stop() {
				select {
				case <-timer.C():
				default:
				}
			}
		case <-timer.C():
		}
		if ctx.Err() != nil {
			return
		}
		outcome := s.runTick(ctx)
		if outcome == refreshCanceled || ctx.Err() != nil {
			return
		}
		delay := s.nextDelay(outcome)
		s.noteNext(s.clock.Now().Add(delay))
		timer.Reset(delay)
	}
}

// runTick executes one refresh, panic-contained so a bug costs one tick, not the loop.
func (s *saasFeedScheduler) runTick(ctx context.Context) (outcome saasFeedRefreshOutcome) {
	defer func() {
		if r := recover(); r != nil {
			outcome = refreshFailed
			if logger != nil {
				logger.Printf("SaaSFeed: refresh tick panicked (recovered, loop continues): %v", r)
			}
		}
	}()
	return s.refresh(ctx)
}

// nextDelay computes the delay until the next tick: the jittered configured cadence after
// a success/no-change/skip; bounded exponential backoff after a failure.
func (s *saasFeedScheduler) nextDelay(outcome saasFeedRefreshOutcome) time.Duration {
	if outcome == refreshFailed {
		s.failures++
		return s.jitter(backoffDelay(s.failures))
	}
	s.failures = 0
	return s.jitter(s.interval())
}

// backoffDelay is bounded exponential backoff: min<<(n-1), clamped at max.
func backoffDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := failures - 1
	if shift > saasFeedBackoffShift {
		shift = saasFeedBackoffShift
	}
	d := saasFeedBackoffMin << uint(shift)
	if d > saasFeedBackoffMax || d <= 0 {
		return saasFeedBackoffMax
	}
	return d
}
