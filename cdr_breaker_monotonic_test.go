package main

// cdr_breaker_monotonic_test.go — the breaker's timers run on a monotonic
// clock, and an outcome only counts for the episode its reservation came from
// (PR #1611, Codex P2 on b1b128c).
//
// Probe age used to be a difference of UnixNano wall readings while the
// probe's own deadline ran on Go's monotonic clock. A forward wall-clock step
// of HalfOpenProbeTimeout (NTP correction, VM resume) declared a live probe
// stale and admitted a replacement; the original's late OnFailure, which was
// not generation-aware, then reopened the breaker under the replacement — a
// fail-open window under the default FailMode. Both halves are pinned here:
// the wall step no longer reclaims, and a reclaimed probe's late report no
// longer decides the episode even when the reclaim is legitimate.

import (
	"testing"
	"time"
)

// splitClock drives a breaker's wall and monotonic clocks independently.
type splitClock struct {
	wall time.Time
	mono time.Duration
}

func newSplitClockBreaker(t *testing.T, cfg cdrBreakerConfig) (*cdrCircuitBreaker, *splitClock) {
	t.Helper()
	b := newCDRCircuitBreaker(cfg)
	c := &splitClock{wall: time.Unix(1_700_000_000, 0)}
	b.setClocks(func() time.Time { return c.wall }, func() time.Duration { return c.mono })
	return b, c
}

// elapse advances real (monotonic) time and the wall clock together.
func (c *splitClock) elapse(d time.Duration) { c.mono += d; c.wall = c.wall.Add(d) }

// stepWall moves only the wall clock, as an NTP step or a VM resume does.
func (c *splitClock) stepWall(d time.Duration) { c.wall = c.wall.Add(d) }

func tripOpenGen0(t *testing.T, b *cdrCircuitBreaker) {
	t.Helper()
	for i := 0; i < b.cfg.FailureThreshold; i++ {
		b.OnFailure(cdrProbeReservation{})
	}
	if b.State() != cbStateOpen {
		t.Fatalf("setup: state %s after %d failures, want open", breakerStateName(b.State()), b.cfg.FailureThreshold)
	}
}

// TestCDRBreaker_WallClockStepForwardDoesNotReclaimLiveProbe is the reported
// schedule: a probe is in flight, the wall clock jumps far past
// HalfOpenProbeTimeout while only a second really elapses. The probe is live
// (its context deadline is monotonic), so no replacement may be admitted.
func TestCDRBreaker_WallClockStepForwardDoesNotReclaimLiveProbe(t *testing.T) {
	b, clk := newSplitClockBreaker(t, cdrBreakerConfig{})
	tripOpenGen0(t, b)
	clk.elapse(b.cfg.ResetTimeout + time.Second)
	ok, probe := b.Reserve()
	if !ok || b.State() != cbStateHalfOpen {
		t.Fatalf("setup: Reserve = %v in %s, want the half-open probe", ok, breakerStateName(b.State()))
	}

	clk.elapse(time.Second)
	clk.stepWall(10 * b.cfg.HalfOpenProbeTimeout)

	if b.Available() {
		t.Error("Available() reports a free probe slot after a wall-clock step: the live probe was judged stale")
	}
	if ok, r := b.Reserve(); ok {
		t.Fatalf("REGRESSION: a forward wall-clock step of %s reclaimed a probe that has been "+
			"in flight for 1s and admitted a replacement (gen %d -> %d)",
			10*b.cfg.HalfOpenProbeTimeout, probe.gen, r.gen)
	}
	if n := b.Stats().StaleProbes; n != 0 {
		t.Fatalf("StaleProbes = %d after a wall-clock step, want 0", n)
	}
	b.OnSuccess(probe)
	if b.State() != cbStateClosed {
		t.Fatalf("the live probe's success left the breaker %s, want closed", breakerStateName(b.State()))
	}
}

// TestCDRBreaker_WallClockStepBackwardDoesNotHoldBreakerOpen is the mirror
// image: a backward wall step must neither extend the open window nor stop
// the wedge escape from reclaiming a genuinely abandoned probe.
func TestCDRBreaker_WallClockStepBackwardDoesNotHoldBreakerOpen(t *testing.T) {
	b, clk := newSplitClockBreaker(t, cdrBreakerConfig{})
	tripOpenGen0(t, b)
	openedWall := clk.wall
	if got := b.Stats().OpenedAt; got != openedWall.UnixNano() {
		t.Fatalf("Stats().OpenedAt = %d, want the wall-clock open time %d (display stays wall time)", got, openedWall.UnixNano())
	}

	clk.stepWall(-time.Hour)
	clk.elapse(b.cfg.ResetTimeout + time.Second)
	ok, abandoned := b.Reserve()
	if !ok {
		t.Fatal("REGRESSION: a backward wall-clock step held the breaker open past ResetTimeout of real time")
	}

	clk.stepWall(-time.Hour)
	clk.elapse(b.cfg.HalfOpenProbeTimeout + time.Second)
	ok, replacement := b.Reserve()
	if !ok || replacement.gen == abandoned.gen {
		t.Fatalf("REGRESSION: a backward wall-clock step stopped the wedge escape (Reserve = %v, gen %d)", ok, replacement.gen)
	}
}

// halfOpenReclaimed returns a breaker whose first probe was legitimately
// reclaimed by the wedge escape and replaced: (stale, current).
func halfOpenReclaimed(t *testing.T) (b *cdrCircuitBreaker, stale, current cdrProbeReservation) {
	t.Helper()
	b, clk := newSplitClockBreaker(t, cdrBreakerConfig{})
	tripOpenGen0(t, b)
	clk.elapse(b.cfg.ResetTimeout + time.Second)
	ok, stale := b.Reserve()
	if !ok {
		t.Fatal("setup: first probe denied")
	}
	clk.elapse(b.cfg.HalfOpenProbeTimeout + time.Second)
	ok, current = b.Reserve()
	if !ok || current.gen == stale.gen || b.Stats().StaleProbes != 1 {
		t.Fatalf("setup: wedge escape did not re-arm (ok=%v gen %d -> %d)", ok, stale.gen, current.gen)
	}
	return b, stale, current
}

// TestCDRBreaker_StaleProbeLateFailureCannotReopenUnderReplacement: the
// reclaimed probe's late failure must not reopen the breaker while the
// replacement is in flight, and the replacement's success must close it.
func TestCDRBreaker_StaleProbeLateFailureCannotReopenUnderReplacement(t *testing.T) {
	b, stale, current := halfOpenReclaimed(t)

	b.OnFailure(stale)
	if b.State() != cbStateHalfOpen {
		t.Fatalf("REGRESSION: a reclaimed probe's late OnFailure moved the breaker to %s while the "+
			"replacement probe is in flight — under fail-open, documents now skip CDR", breakerStateName(b.State()))
	}
	if n := b.halfOpenTried.Load(); n != 1 {
		t.Fatalf("the replacement's slot was disturbed by a stale outcome (held %d, want 1)", n)
	}
	if n := b.Stats().StaleOutcomes; n != 1 {
		t.Fatalf("StaleOutcomes = %d, want 1", n)
	}

	b.OnSuccess(current)
	if b.State() != cbStateClosed {
		t.Fatalf("the replacement probe's success left the breaker %s, want closed", breakerStateName(b.State()))
	}
}

// TestCDRBreaker_StaleProbeLateSuccessCannotDecideTheEpisode: a late success
// from the reclaimed probe must not close the breaker past the probe budget,
// and the replacement's failure must still reopen it.
func TestCDRBreaker_StaleProbeLateSuccessCannotDecideTheEpisode(t *testing.T) {
	b, stale, current := halfOpenReclaimed(t)

	b.OnSuccess(stale)
	if b.State() != cbStateHalfOpen {
		t.Fatalf("REGRESSION: a reclaimed probe's late OnSuccess moved the breaker to %s, "+
			"overriding the replacement probe still in flight", breakerStateName(b.State()))
	}
	b.OnFailure(current)
	if b.State() != cbStateOpen {
		t.Fatalf("the replacement probe's failure left the breaker %s, want open", breakerStateName(b.State()))
	}
	// After the episode ended, the stale probe still cannot reach in.
	b.OnSuccess(stale)
	if b.State() != cbStateOpen || b.consecFails.Load() != int64(b.cfg.FailureThreshold) {
		t.Fatalf("a stale outcome after the episode changed the breaker: %s, consecFails %d",
			breakerStateName(b.State()), b.consecFails.Load())
	}
}

// TestCDRBreaker_PreOpenRequestLateOutcomeCannotDecideHalfOpen: a request
// admitted while closed (gen 0) whose RPC outlives the open window is not the
// recovery probe, and its late report must not decide the half-open episode.
func TestCDRBreaker_PreOpenRequestLateOutcomeCannotDecideHalfOpen(t *testing.T) {
	b, clk := newSplitClockBreaker(t, cdrBreakerConfig{})
	ok, preOpen := b.Reserve()
	if !ok || preOpen.gen != 0 {
		t.Fatalf("setup: closed Reserve = (%v, gen %d), want (true, 0)", ok, preOpen.gen)
	}
	tripOpenGen0(t, b)
	clk.elapse(b.cfg.ResetTimeout + time.Second)
	ok, probe := b.Reserve()
	if !ok {
		t.Fatal("setup: recovery probe denied")
	}

	b.OnFailure(preOpen)
	b.OnSuccess(preOpen)
	if b.State() != cbStateHalfOpen || b.halfOpenTried.Load() != 1 {
		t.Fatalf("REGRESSION: a pre-open request's late outcome decided the half-open episode: %s, held %d",
			breakerStateName(b.State()), b.halfOpenTried.Load())
	}
	b.OnSuccess(probe)
	if b.State() != cbStateClosed {
		t.Fatalf("the probe's success left the breaker %s, want closed", breakerStateName(b.State()))
	}
}

// TestCDRMarkOutcome_CarriesTheReservation pins the production reporting path:
// cdrMarkOutcome forwards the RPC's reservation, so a stale report through the
// pool is dropped exactly as a direct one is.
func TestCDRMarkOutcome_CarriesTheReservation(t *testing.T) {
	b, stale, current := halfOpenReclaimed(t)
	withTempPool(t, &cdrPooledClient{Name: "mono", Breaker: b})

	cdrMarkOutcome("mono", stale, true)
	if b.State() != cbStateHalfOpen {
		t.Fatalf("REGRESSION: cdrMarkOutcome let a stale failure reopen the breaker (%s)", breakerStateName(b.State()))
	}
	cdrMarkOutcome("mono", current, false)
	if b.State() != cbStateClosed {
		t.Fatalf("cdrMarkOutcome of the current probe's success left the breaker %s, want closed", breakerStateName(b.State()))
	}
}
