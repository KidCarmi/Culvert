//go:build benchgate

package main

// M2 hot-path allocation gates (ADR-0025 §8 / the F3-qualification discipline):
//
//   - learning DISABLED (the production posture): the adapter is one atomic
//     load + a predicted branch — ZERO allocations, no observation built.
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
		learnObserveDecision(auth, "host.example", "GET", nil, "OK", "Bypass")
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
		learnObserveDecision(authNoGroups, "host.example", "GET", nil, "OK", "Bypass")
	}); got > 0 {
		t.Fatalf("enabled enqueue (no groups) allocates %.1f/op, want 0", got)
	}

	authGroups := authOutcome{identity: "alice", source: "test-idp", groups: []string{"engineering", "security", "vpn"}}
	if got := testing.AllocsPerRun(2000, func() {
		learnObserveDecision(authGroups, "host.example", "GET", nil, "OK", "Bypass")
	}); got > 1 {
		t.Fatalf("enabled enqueue (3 groups) allocates %.1f/op, want <=1 (the bounded groups copy)", got)
	}
}
