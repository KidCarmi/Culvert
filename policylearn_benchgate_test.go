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
		learnObserveDecision(auth, "host.example", "GET", nil, "OK", "Bypass", learnDecisionCtx{}, false)
	})
	if allocs != 0 {
		t.Fatalf("disabled learnObserveDecision allocates %.1f/op, want 0 — the off posture must be free", allocs)
	}
	if allocs := testing.AllocsPerRun(2000, func() {
		learnObservePreDispatch(auth, "host.example", "GET", "BLOCKED", learnDecisionCtx{}, false)
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
		learnObserveDecision(auth, "host.example", "GET", nil, "OK", "Bypass", learnDecisionCtx{}, false)
	}); allocs != 0 {
		t.Fatalf("enabled-idle learnObserveDecision allocates %.1f/op, want 0 — the idle posture must be free", allocs)
	}
	if allocs := testing.AllocsPerRun(2000, func() {
		learnObservePreDispatch(auth, "host.example", "GET", "BLOCKED", learnDecisionCtx{}, false)
	}); allocs != 0 {
		t.Fatalf("enabled-idle learnObservePreDispatch allocates %.1f/op, want 0", allocs)
	}
	// And no transport activity of any kind was recorded (nothing was built).
	if s := eng.ObservationStats(); s.Accepted != 0 || s.Rejected != 0 || s.Dropped != 0 {
		t.Fatalf("enabled-idle produced transport activity: %+v", s)
	}
}

func TestBenchGate_LearnObserveEnabledBoundedAllocs(t *testing.T) {
	// This gate measures the allocations of the ENQUEUE CALL ITSELF (Observe on
	// the request goroutine), which is the documented M5A §1 contract: 0 with no
	// groups, ≤1 (the bounded groups copy) otherwise. It must NOT measure the
	// single async drain goroutine's per-observation aggregation
	// (aggregateLocked: pseudonym HMAC, category resolution, cell maps), which
	// allocates by design OFF the request path.
	//
	// testing.AllocsPerRun reads runtime.MemStats.Mallocs, which is
	// PROCESS-WIDE — it attributes every heap allocation by ANY goroutine during
	// the sampling window to the measured op. With a nil sink the drain consumed
	// and aggregated the enqueued observations concurrently, so whenever Go's
	// async preemption scheduled the drain inside the window its aggregation
	// allocations leaked into the per-op figure (a nondeterministic ~12/op,
	// likelier under the full benchgate suite's load/GC pressure than in
	// isolation). That was a MEASUREMENT ARTIFACT, never an enqueue-path
	// regression: the enqueue path is 0-alloc, proven by the deterministic
	// 0.0000/op this test now yields with the drain parked.
	//
	// To measure only the caller, the drain is PARKED before the window: a
	// blocking sink halts the single drain goroutine after it consumes its first
	// (priming) observation, so it allocates nothing during measurement. Later
	// enqueues just fill the bounded queue (overflow drops are alloc-free), so
	// the figure reflects the enqueue path alone. The sink is released before
	// Close so the drain can be joined.
	sinkEntered := make(chan struct{}, 1)
	releaseSink := make(chan struct{})
	eng, err := policylearn.New(policylearn.Config{
		Now: time.Now,
		Sink: func(policylearn.Observation) {
			// Signal that the drain has consumed the priming observation and is
			// now parked here, then block until the test releases it.
			select {
			case sinkEntered <- struct{}{}:
			default:
			}
			<-releaseSink
		},
	})
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
		close(releaseSink) // unblock the parked drain so Close can join it
		_ = eng.Close()
	}()

	benchCtx, benchOK := learnDecisionSnapshot()
	if !benchOK {
		t.Fatal("learnDecisionSnapshot refused with an active session")
	}
	authNoGroups := authOutcome{identity: "alice", source: "test-idp"}
	// Prime one observation and wait for the drain to park in the blocking sink
	// BEFORE any measurement, so no aggregation runs during either window.
	learnObserveDecision(authNoGroups, "host.example", "GET", nil, "OK", "Bypass", benchCtx, true)
	<-sinkEntered
	if got := testing.AllocsPerRun(2000, func() {
		learnObserveDecision(authNoGroups, "host.example", "GET", nil, "OK", "Bypass", benchCtx, true)
	}); got > 0 {
		t.Fatalf("enabled enqueue (no groups) allocates %.1f/op, want 0", got)
	}

	authGroups := authOutcome{identity: "alice", source: "test-idp", groups: []string{"engineering", "security", "vpn"}}
	if got := testing.AllocsPerRun(2000, func() {
		learnObserveDecision(authGroups, "host.example", "GET", nil, "OK", "Bypass", benchCtx, true)
	}); got > 1 {
		t.Fatalf("enabled enqueue (3 groups) allocates %.1f/op, want <=1 (the bounded groups copy)", got)
	}
}
