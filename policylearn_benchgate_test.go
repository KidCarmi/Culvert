//go:build benchgate

package main

// M2/M5A hot-path allocation gates (ADR-0025 §8 / the F3-qualification
// discipline) — the three product states (M5A §1):
//
//   - learning DISABLED (the production posture): the adapter is one atomic
//     load + a predicted branch — ZERO allocations, no observation built.
//   - feature ENABLED but IDLE (no Learning session): TWO atomic loads —
//     ZERO allocations, the gate fires BEFORE any Observation construction,
//     group copy, or enqueue.
//   - learning ENABLED with an active session: the enqueue is bounded — at
//     most the single groups-copy allocation (plus nothing when the request
//     carries no groups). No string rebuilding, no logging, no I/O.
//
// Alloc gates are hardware-independent (the benchgate convention).

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/policylearn"
)

func TestBenchGate_LearnObserveDisabledZeroAlloc(t *testing.T) {
	prev := policyLearnEngine.Load()
	policyLearnEngine.Store(nil)
	defer policyLearnEngine.Store(prev)
	auth := authOutcome{identity: "alice", source: "test-idp", groups: []string{"engineering", "sec"}}
	allocs := testing.AllocsPerRun(2000, func() {
		learnObserveDecision(auth, "host.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)
	})
	if allocs != 0 {
		t.Fatalf("disabled learnObserveDecision allocates %.1f/op, want 0 — the off posture must be free", allocs)
	}
	if allocs := testing.AllocsPerRun(2000, func() {
		learnObservePreDispatch(auth, "host.example", "GET", "BLOCKED")
	}); allocs != 0 {
		t.Fatalf("disabled learnObservePreDispatch allocates %.1f/op, want 0", allocs)
	}
}

// TestBenchGate_LearnObserveEnabledIdleZeroAlloc pins the M5A §1 contract:
// feature enabled + no active Learning session costs zero allocations and
// builds no Observation (gate before DTO construction).
func TestBenchGate_LearnObserveEnabledIdleZeroAlloc(t *testing.T) {
	eng, err := policylearn.New(policylearn.Config{Now: time.Now})
	if err != nil {
		t.Fatal(err)
	}
	prev := policyLearnEngine.Load()
	policyLearnEngine.Store(eng)
	defer func() {
		policyLearnEngine.Store(prev)
		_ = eng.Close()
	}()
	auth := authOutcome{identity: "alice", source: "test-idp", groups: []string{"engineering", "sec"}}
	if allocs := testing.AllocsPerRun(2000, func() {
		learnObserveDecision(auth, "host.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)
	}); allocs != 0 {
		t.Fatalf("enabled-idle learnObserveDecision allocates %.1f/op, want 0 — the idle posture must be free", allocs)
	}
	if allocs := testing.AllocsPerRun(2000, func() {
		learnObservePreDispatch(auth, "host.example", "GET", "BLOCKED")
	}); allocs != 0 {
		t.Fatalf("enabled-idle learnObservePreDispatch allocates %.1f/op, want 0", allocs)
	}
	// And no transport activity of any kind was recorded (nothing was built).
	if s := eng.ObservationStats(); s.Accepted != 0 || s.Rejected != 0 || s.Dropped != 0 {
		t.Fatalf("enabled-idle produced transport activity: %+v", s)
	}
}

func TestBenchGate_LearnObserveEnabledBoundedAllocs(t *testing.T) {
	eng, err := policylearn.New(policylearn.Config{Now: time.Now}) // nil sink: drain discards
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eng.StartSession("bench"); err != nil {
		t.Fatal(err)
	}
	prev := policyLearnEngine.Load()
	policyLearnEngine.Store(eng)
	defer func() {
		policyLearnEngine.Store(prev)
		_ = eng.Close()
	}()

	authNoGroups := authOutcome{identity: "alice", source: "test-idp"}
	if got := testing.AllocsPerRun(2000, func() {
		learnObserveDecision(authNoGroups, "host.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)
	}); got > 0 {
		t.Fatalf("enabled enqueue (no groups) allocates %.1f/op, want 0", got)
	}

	authGroups := authOutcome{identity: "alice", source: "test-idp", groups: []string{"engineering", "security", "vpn"}}
	if got := testing.AllocsPerRun(2000, func() {
		learnObserveDecision(authGroups, "host.example", "GET", nil, "OK", "Bypass", learnDecisionKey{}, false)
	}); got > 1 {
		t.Fatalf("enabled enqueue (3 groups) allocates %.1f/op, want <=1 (the bounded groups copy)", got)
	}
}
