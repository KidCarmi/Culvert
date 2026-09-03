// Package feedsched is the shared cadence engine for Culvert's periodic
// intelligence feeds: bounded exponential backoff after a failed round, a
// stable per-node jitter offset on the steady-state interval, and prompt
// cancellation — all behind injectable clock/timer/jitter seams so a feed's
// schedule is unit-testable with a fake clock and no sleeps.
//
// # Why this package exists
//
// Culvert ships THREE periodic feed loops and, before this package, only the
// newest of them scheduled itself correctly:
//
//   - the signed SaaS URL-category feed (main's saasFeedScheduler) — bounded
//     backoff, stable ±10% jitter, immediate wakeup, fake-clock tests;
//   - the UT1 community category feed (internal/feedsync) — a bare
//     time.NewTicker(24h);
//   - the URLhaus/OpenPhish threat feed (internal/threatfeed) — a bare
//     time.NewTicker(6h).
//
// A bare ticker has two failure modes, and both are reachable by ordinary
// operations rather than by an exotic fault.
//
// **A failed round is not retried until the next full interval.** The threat
// feed's round fetches two public endpoints over the customer's own egress
// path; a DNS blip, a 503 from the provider, a proxy restart or a few seconds
// of packet loss fails it. Nothing then re-attempts for SIX HOURS. The worst
// shape is a node that boots into a feed outage: `Start` syncs immediately
// when the on-disk DB is empty, so a fresh or re-imaged node whose first sync
// fails runs with ZERO threat intelligence — not stale intelligence, none —
// until the first tick, with every probe reporting a healthy node. For the
// category feed the same window is TWENTY-FOUR hours.
//
// **A fleet stays in phase forever.** `time.NewTicker` fires at a fixed offset
// from process start, so nodes that boot together — a rolling upgrade, a
// compose restart, a hypervisor recovering a rack — sync together, forever.
// Culvert's feed origins are third-party and shared (abuse.ch, openphish.com,
// and a raw.githubusercontent.com mirror serving a 50+ MB tarball), so a fleet
// in lockstep is a self-inflicted thundering herd against a provider that
// answers it by rate-limiting the customer's egress IP. That closes a loop:
// the herd causes the failure, and the absent retry then holds the whole fleet
// at that failure for a full interval.
//
// # The contract
//
//   - After a SUCCESSFUL round the next delay is the configured interval,
//     offset by a per-scheduler jitter fraction chosen ONCE (stable per node,
//     spread across the fleet — re-rolling per tick would let nodes drift back
//     into phase and would make the cadence untestable).
//   - After a FAILED round the next delay is bounded exponential backoff from
//     BackoffMin, doubling, clamped at BackoffMax, jittered the same way. The
//     failure count resets on the first success.
//   - BackoffMax is expected to sit BELOW the steady-state interval, so retries
//     are strictly a *tightening* of the cadence: a persistently failing feed
//     converges on one attempt per BackoffMax and never on more traffic than a
//     healthy one would generate at its own interval. `New` clamps a
//     misconfigured BackoffMax down to the interval rather than trusting it.
//   - Retries are unbounded in COUNT but bounded in RATE, and never silent:
//     the owning feed counts and reports every failure (see the health planes
//     in internal/threatfeed and internal/feedsync). This is the same posture
//     ha_lease_recovery.go records — "avoid infinite retries" forbids a silent
//     hot loop, not a rate-bounded loop whose state an operator can read. A
//     feed that stopped retrying would be strictly worse: intelligence would
//     freeze permanently on one transient error.
//   - The wait is interruptible: ctx cancellation returns promptly from inside
//     a backoff, so shutdown never waits out a delay.
//   - A panicking round is a FAILED round, not a dead loop. Containment is at
//     the round, per internal/obs's rule (guard the iteration, never the
//     goroutine) — a bad feed body costs one window and backs off, rather than
//     killing an in-line gateway or silently stalling the loop forever.
//
// The main-side saasFeedScheduler predates this package and additionally owns
// an immediate config-change wakeup bound to its runtime; migrating it onto
// these seams is recorded as a follow-up rather than bundled into a chaos fix.
package feedsched

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
)

// Clock is the injectable timer factory. Production uses RealClock; tests
// supply a fake so cadence, backoff growth and cancellation are asserted
// deterministically without sleeping.
//
// Deliberately narrower than the main-side saasFeedScheduler's schedClock: this
// loop never reads the wall clock (it schedules purely by relative delay), so a
// Now() method would be dead surface a fake has to implement for nothing.
type Clock interface {
	NewTimer(d time.Duration) Timer
}

// Timer is the injectable timer seam (production wraps *time.Timer).
type Timer interface {
	C() <-chan time.Time
	Reset(d time.Duration) bool
	Stop() bool
}

// RealClock is the production Clock.
type RealClock struct{}

type realTimer struct{ t *time.Timer }

func (r realTimer) C() <-chan time.Time { return r.t.C }
func (r realTimer) Reset(d time.Duration) bool {
	if d < 0 {
		d = 0
	}
	return r.t.Reset(d)
}
func (r realTimer) Stop() bool { return r.t.Stop() }

// NewTimer implements Clock.
func (RealClock) NewTimer(d time.Duration) Timer {
	if d < 0 {
		d = 0
	}
	return realTimer{t: time.NewTimer(d)}
}

// StableJitter returns a jitter function whose offset within ±frac is chosen
// ONCE. Stable per node for the process lifetime, spread across the fleet.
//
// Deliberately not re-rolled per tick: a per-tick roll gives the same expected
// cadence but lets two nodes that happen to draw similar offsets drift back
// into phase over time, and it makes the schedule unreproducible in a test.
func StableJitter(frac float64) func(time.Duration) time.Duration {
	if frac < 0 {
		frac = 0
	}
	off := (rand.Float64()*2 - 1) * frac // #nosec G404 -- fleet spread, not crypto; drawn once
	return func(base time.Duration) time.Duration {
		if base <= 0 {
			return base
		}
		d := base + time.Duration(float64(base)*off)
		if d <= 0 {
			return base
		}
		return d
	}
}

// Config describes one feed's schedule. Interval is a function rather than a
// value so a feed whose cadence is admin-tunable is re-read every round instead
// of being frozen at construction.
type Config struct {
	// Name identifies the feed in log lines. Never rendered into an alert.
	Name string

	// Interval returns the steady-state cadence between successful rounds.
	Interval func() time.Duration

	// Run performs one round and reports whether it succeeded. It must respect
	// ctx and must not panic — but if it does, the scheduler contains it and
	// charges the round as a failure.
	Run func(ctx context.Context) bool

	// RunNow reports whether a round should happen immediately at t=0 rather
	// than after the first interval. Feeds use this for the cold-start case
	// ("the on-disk DB is empty, so serve nothing until we fetch"). Nil means
	// no immediate round.
	RunNow func() bool

	// BackoffMin / BackoffMax bound the post-failure retry delay. Zero values
	// take the package defaults.
	BackoffMin time.Duration
	BackoffMax time.Duration

	// JitterFrac is the ±fraction applied to every computed delay.
	JitterFrac float64

	// Clock and Jitter are test seams; nil takes the production implementations.
	Clock  Clock
	Jitter func(time.Duration) time.Duration

	// OnPanic is invoked when a round panics, before it is charged as a
	// failure. Nil falls back to a WARN line naming the feed.
	//
	// In production both feeds additionally wrap their round body in
	// obs.SafeCall, so a panic in the FEED reaches the crash-recording plane
	// (metric + audit + log) and never gets this far. This recover is the
	// second layer, covering a panic in the Run closure itself; it exists so
	// that layer can never turn into a dead loop or a process kill.
	OnPanic func(v any)
}

const (
	// DefaultBackoffMin is the first retry delay after a failed round. Chosen
	// well above a provider's transient-error window and far below any feed's
	// steady-state interval: it recovers a DNS blip in minutes instead of
	// hours, while never being fast enough to look like a retry storm to the
	// third-party origin.
	DefaultBackoffMin = 5 * time.Minute

	// DefaultBackoffMax caps the retry delay. See the Config.BackoffMax note:
	// New additionally clamps this to the feed's own interval, so retrying can
	// only ever tighten the cadence, never loosen it past a healthy node's.
	DefaultBackoffMax = 1 * time.Hour

	// DefaultJitterFrac matches the main-side saasFeedScheduler's ±10%.
	DefaultJitterFrac = 0.10

	// backoffShift caps the exponent as an overflow guard only; the BackoffMax
	// clamp does the real bounding.
	backoffShift = 16
)

// Scheduler is one feed's cadence loop.
type Scheduler struct {
	cfg      Config
	clock    Clock
	jitter   func(time.Duration) time.Duration
	failures int // consecutive failed rounds; loop-local, reset on success
}

// New builds a Scheduler, filling in production seams and defaults.
//
// The BackoffMax clamp is the load-bearing default: a feed that configured a
// backoff ceiling ABOVE its own interval would, after a failure, retry LESS
// often than a healthy node syncs — turning the recovery mechanism into an
// additional delay. Clamping here means a caller cannot express that.
func New(cfg Config) *Scheduler {
	if cfg.BackoffMin <= 0 {
		cfg.BackoffMin = DefaultBackoffMin
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = DefaultBackoffMax
	}
	if cfg.BackoffMax < cfg.BackoffMin {
		cfg.BackoffMax = cfg.BackoffMin
	}
	if cfg.JitterFrac == 0 {
		cfg.JitterFrac = DefaultJitterFrac
	}
	s := &Scheduler{cfg: cfg, clock: cfg.Clock, jitter: cfg.Jitter}
	if s.clock == nil {
		s.clock = RealClock{}
	}
	if s.jitter == nil {
		s.jitter = StableJitter(cfg.JitterFrac)
	}
	return s
}

// interval reads the feed's current cadence, defending against a nil or
// non-positive value (a bare `for {}` over a zero-delay timer would be a hot
// loop against a third-party origin).
func (s *Scheduler) interval() time.Duration {
	if s.cfg.Interval == nil {
		return DefaultBackoffMax
	}
	d := s.cfg.Interval()
	if d <= 0 {
		return DefaultBackoffMax
	}
	return d
}

// backoffCeiling is BackoffMax clamped to the live interval — see New. Read per
// round because Interval is a function and may be re-resolved by an admin edit.
func (s *Scheduler) backoffCeiling() time.Duration {
	ceil := s.cfg.BackoffMax
	if iv := s.interval(); ceil > iv {
		ceil = iv
	}
	if ceil < s.cfg.BackoffMin {
		ceil = s.cfg.BackoffMin
	}
	return ceil
}

// NextDelay computes the delay after a round with the given outcome and
// advances the consecutive-failure count. Exported for the feeds' own tests to
// pin the cadence contract without driving a loop.
func (s *Scheduler) NextDelay(ok bool) time.Duration {
	if ok {
		s.failures = 0
		return s.jitter(s.interval())
	}
	s.failures++
	return s.jitter(s.backoffDelay(s.failures))
}

// Failures reports the current consecutive-failure count (0 after any success).
func (s *Scheduler) Failures() int { return s.failures }

// backoffDelay is bounded exponential backoff: min<<(n-1) clamped at the
// interval-aware ceiling.
func (s *Scheduler) backoffDelay(failures int) time.Duration {
	if failures < 1 {
		failures = 1
	}
	shift := failures - 1
	if shift > backoffShift {
		shift = backoffShift
	}
	ceil := s.backoffCeiling()
	// shift is clamped to [0, backoffShift]; a signed non-negative shift count
	// is valid Go, so no unsigned conversion (and no G115 suppression) is needed.
	d := s.cfg.BackoffMin << shift
	if d > ceil || d <= 0 {
		return ceil
	}
	return d
}

// Run drives the loop until ctx is cancelled. It blocks; callers own the
// goroutine.
func (s *Scheduler) Run(ctx context.Context) {
	if s.cfg.RunNow != nil && s.cfg.RunNow() {
		if ctx.Err() != nil {
			return
		}
		s.scheduleAfter(ctx, s.round(ctx))
		return
	}
	s.loop(ctx, s.jitter(s.interval()))
}

// scheduleAfter continues the loop with the delay implied by an outcome that
// has already been observed (the immediate cold-start round).
func (s *Scheduler) scheduleAfter(ctx context.Context, ok bool) {
	s.loop(ctx, s.NextDelay(ok))
}

// loop waits `first`, runs a round, and repeats at the outcome-derived delay.
// The timer is always stopped on exit, so no timer outlives the loop.
func (s *Scheduler) loop(ctx context.Context, first time.Duration) {
	timer := s.clock.NewTimer(first)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C():
		}
		if ctx.Err() != nil {
			return
		}
		timer.Reset(s.NextDelay(s.round(ctx)))
	}
}

// round runs one feed round with panic containment. A panic is charged as a
// FAILURE, so a systematically panicking body backs off instead of hot-looping,
// and the loop survives to try the next window.
func (s *Scheduler) round(ctx context.Context) (ok bool) {
	defer func() {
		if v := recover(); v != nil {
			ok = false
			if s.cfg.OnPanic != nil {
				s.cfg.OnPanic(v)
			} else {
				obs.Warnf("feedsched: %s round panicked (recovered, charged as a failed round): %s",
					obs.Sanitize(s.cfg.Name), obs.Sanitize(fmt.Sprint(v)))
			}
		}
	}()
	if s.cfg.Run == nil {
		return true
	}
	return s.cfg.Run(ctx)
}
