package upstream

// CHAOS-71 — the parent-proxy circuit breaker across a backward wall-clock step.
//
// openedAt is a UnixMilli int64, so `time.UnixMilli(...)` reconstructs a Time
// with NO monotonic reading and `time.Since` on it is a wall-clock subtraction.
// A backward step of Δ makes the measured open duration negative, so the
// open→half-open transition — the breaker's ONLY route back to service — can
// never fire until the clock catches up.
//
// That matters more here than in an ordinary breaker, because Pool.Next falls
// back to DIRECT when no parent is eligible (the PX-2 posture). A step that
// pins every tripped breaker open therefore leaves the appliance egressing
// around the enterprise's parent-proxy chain for the duration of the step,
// long after the parents came back.

import (
	"testing"
	"time"
)

// TestChaos71_BreakerHalfOpensAfterABackwardClockStep is the DEFECT gate.
func TestChaos71_BreakerHalfOpensAfterABackwardClockStep(t *testing.T) {
	const timeout = 50 * time.Millisecond
	cb := newCircuitBreaker(1, timeout)

	if !cb.RecordFailure() {
		t.Fatal("RecordFailure did not trip the breaker open")
	}
	if cb.Allow() {
		t.Fatal("breaker allowed a request immediately after tripping")
	}

	// The clock steps back an hour: openedAt, written before the step, now
	// reads an hour into the future.
	cb.openedAt.Store(time.Now().Add(time.Hour).UnixMilli())

	// First call after the step must NOT short-circuit the reset timeout into
	// an instant probe at a parent that may still be down.
	if cb.Allow() {
		t.Fatal("breaker half-opened instantly on the step itself — the reset timeout must still be served")
	}

	// ...but one full reset timeout after the step it must recover.
	deadline := time.Now().Add(2 * time.Second)
	for !cb.Allow() {
		if time.Now().After(deadline) {
			t.Fatal("breaker never left open after a backward clock step — the parent-proxy chain " +
				"stays bypassed (Pool.Next falls back to direct) until the wall clock catches up")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestChaos71_BreakerStillHoldsOpenForItsTimeout is the CONTROL that the guard
// did not turn the breaker into a pass-through.
func TestChaos71_BreakerStillHoldsOpenForItsTimeout(t *testing.T) {
	cb := newCircuitBreaker(1, time.Hour)
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("breaker allowed a request well inside its reset timeout")
	}
	// A sane clock must leave openedAt alone, so the reported trip instant stays
	// the operator-visible truth on /api/diagnostics.
	if got := cb.OpenedAt(); time.Since(got) < 0 || time.Since(got) > time.Minute {
		t.Fatalf("OpenedAt() = %v, want the recent trip instant", got)
	}
}

// TestChaos71_BreakerRecoveryIsBoundedFromTheStep pins the RECOVERY SHAPE: the
// guard re-anchors the trip instant to the stepped clock, so recovery takes one
// reset timeout measured FROM the step — never zero (a probe flood) and never
// unbounded (the defect).
func TestChaos71_BreakerRecoveryIsBoundedFromTheStep(t *testing.T) {
	const timeout = 300 * time.Millisecond
	cb := newCircuitBreaker(1, timeout)
	cb.RecordFailure()
	cb.openedAt.Store(time.Now().Add(time.Hour).UnixMilli())

	start := time.Now()
	cb.Allow() // observes the future stamp and re-anchors
	for !cb.Allow() {
		if time.Since(start) > 5*time.Second {
			t.Fatal("breaker never recovered")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if elapsed := time.Since(start); elapsed < timeout {
		t.Fatalf("breaker recovered in %v, before a full reset timeout (%v) had been served from the step", elapsed, timeout)
	}
}
