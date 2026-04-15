package main

// Unit tests for the circuit breaker state machine (cdr_breaker.go).
// Uses a mocked clock so time-based transitions are deterministic.

import (
	"testing"
	"time"
)

// newTestBreaker builds a breaker with tight defaults and a mock clock
// whose `now()` returns the shared `current` value.  Tests mutate
// `current` to simulate time passing.
func newTestBreaker(t *testing.T, cfg cdrBreakerConfig) (*cdrCircuitBreaker, *time.Time) {
	t.Helper()
	b := newCDRCircuitBreaker(cfg)
	current := time.Unix(0, 0)
	b.setNowFn(func() time.Time { return current })
	return b, &current
}

func TestBreaker_StartsClosed(t *testing.T) {
	b := newCDRCircuitBreaker(cdrBreakerConfig{})
	if b.State() != cbStateClosed {
		t.Fatalf("state = %d, want closed (0)", b.State())
	}
	if !b.Allow() {
		t.Fatal("closed breaker must Allow")
	}
}

func TestBreaker_OpensAfterThreshold(t *testing.T) {
	b, _ := newTestBreaker(t, cdrBreakerConfig{FailureThreshold: 3})
	for i := 0; i < 3; i++ {
		b.OnFailure()
	}
	if b.State() != cbStateOpen {
		t.Fatalf("state = %d after 3 failures, want open (1)", b.State())
	}
	if b.Allow() {
		t.Fatal("open breaker must deny")
	}
}

func TestBreaker_SuccessResetsFailCounter(t *testing.T) {
	b, _ := newTestBreaker(t, cdrBreakerConfig{FailureThreshold: 3})
	b.OnFailure()
	b.OnFailure()
	b.OnSuccess()
	b.OnFailure() // 1, not 3 — breaker still closed
	if b.State() != cbStateClosed {
		t.Fatalf("state = %d, want closed — OnSuccess should have reset counter", b.State())
	}
}

func TestBreaker_OpenToHalfOpenAfterTimeout(t *testing.T) {
	b, now := newTestBreaker(t, cdrBreakerConfig{FailureThreshold: 2, ResetTimeout: 10 * time.Second})
	b.OnFailure()
	b.OnFailure()
	if b.State() != cbStateOpen {
		t.Fatal("not opened")
	}
	// 5s elapsed — still open, deny.
	*now = now.Add(5 * time.Second)
	if b.Allow() {
		t.Fatal("should still be open 5s in")
	}
	// 11s elapsed — transition to half-open, allow first probe.
	*now = now.Add(6 * time.Second)
	if !b.Allow() {
		t.Fatal("should have transitioned to half-open and allowed probe")
	}
	if b.State() != cbStateHalfOpen {
		t.Fatalf("state = %d, want half_open (2)", b.State())
	}
}

func TestBreaker_HalfOpenProbeBudget(t *testing.T) {
	b, now := newTestBreaker(t, cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 10 * time.Second, HalfOpenProbes: 1})
	b.OnFailure()
	*now = now.Add(11 * time.Second)
	if !b.Allow() {
		t.Fatal("first probe should pass")
	}
	if b.Allow() {
		t.Fatal("second probe must be denied (budget=1)")
	}
}

func TestBreaker_HalfOpenSuccessClosesBreaker(t *testing.T) {
	b, now := newTestBreaker(t, cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 10 * time.Second})
	b.OnFailure()
	*now = now.Add(11 * time.Second)
	_ = b.Allow() // transition to half-open
	b.OnSuccess()
	if b.State() != cbStateClosed {
		t.Fatalf("state = %d, want closed after half-open success", b.State())
	}
}

func TestBreaker_HalfOpenFailureReopens(t *testing.T) {
	b, now := newTestBreaker(t, cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: 10 * time.Second})
	b.OnFailure()
	*now = now.Add(11 * time.Second)
	_ = b.Allow() // → half-open
	b.OnFailure()
	if b.State() != cbStateOpen {
		t.Fatalf("state = %d, want open after half-open failure", b.State())
	}
	// Should require a fresh 10s wait.
	*now = now.Add(5 * time.Second)
	if b.Allow() {
		t.Fatal("fresh timer didn't start after re-open")
	}
}

func TestBreaker_ResetForcesClosed(t *testing.T) {
	b, _ := newTestBreaker(t, cdrBreakerConfig{FailureThreshold: 2})
	b.OnFailure()
	b.OnFailure()
	b.Reset()
	if b.State() != cbStateClosed {
		t.Fatalf("Reset didn't move to closed: %d", b.State())
	}
	if !b.Allow() {
		t.Fatal("Reset breaker should Allow")
	}
}

func TestBreaker_StatsCapturesActivity(t *testing.T) {
	b, now := newTestBreaker(t, cdrBreakerConfig{FailureThreshold: 2, ResetTimeout: 10 * time.Second})
	b.OnFailure()
	b.OnFailure() // opens
	_ = b.Allow() // trip
	_ = b.Allow() // trip
	stats := b.Stats()
	if stats.State != "open" {
		t.Fatalf("state = %q", stats.State)
	}
	if stats.TotalOpens != 1 || stats.TotalTrips != 2 {
		t.Fatalf("stats = %+v", stats)
	}
	_ = now // keep linter happy
}

func TestBreakerStateName(t *testing.T) {
	cases := map[int32]string{
		cbStateClosed:   "closed",
		cbStateOpen:     "open",
		cbStateHalfOpen: "half_open",
		99:              "unknown",
	}
	for s, want := range cases {
		if got := breakerStateName(s); got != want {
			t.Errorf("breakerStateName(%d) = %q, want %q", s, got, want)
		}
	}
}
