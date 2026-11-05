package scanner

// inflight_cost_test.go — what the CHAOS-110 gate COSTS, and the thresholds
// that report it.
//
// inflight_chaos110_test.go holds the gate's safety invariants (the cap is
// never exceeded, an abandoned worker stays counted, a refusal fails closed).
// These are the complementary contracts: the price a response pays when the
// gate is full, that slots survive repeated abandonment, that a deployment with
// no DPI patterns never reaches the gate at all, and that the
// approaching-saturation lead indicator does not cry wolf on the smallest gate.

import (
	"regexp"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestChaos110_SaturationStallIsWaitPlusBudget measures what the new gate costs a
// response that arrives while the engine is occupied. Two questions the
// committed CHAOS-110 gates do not answer:
//
//  1. A refused scan waits the FULL budget before failing closed, so the
//     refusal is not free — it stalls the request goroutine (and keeps the
//     response body reachable) for that whole window.
//  2. A scan that waits and then WINS a slot is given a fresh budget, so the
//     worst-case non-cancellable duration of one DPI scan is wait + budget,
//     not budget.
func TestChaos110_SaturationStallIsWaitPlusBudget(t *testing.T) {
	withGate(t, 1)
	const budget = 120 * time.Millisecond

	hold := make(chan struct{})
	var entered atomic.Int64
	blocker := gatedSet(&entered, hold)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); blocker.scan([]byte("body"), budget) }()
	waitFor(t, "the only slot to be taken", func() bool { return entered.Load() >= 1 })

	// (1) refusal path: a clean body, no pattern it could ever match.
	clean := &patternSet{raw: []string{"zzz"}, compiled: []*regexp.Regexp{regexp.MustCompile("zzz")}}
	clean.matcher = func(*regexp.Regexp, []byte) bool { return false }
	start := time.Now()
	pattern, hit := clean.scan([]byte("harmless"), budget)
	stall := time.Since(start)
	if !hit || pattern != SaturatedReason {
		t.Fatalf("refusal verdict = (%q, %v), want (%q, true) — fail-closed is the contract", pattern, hit, SaturatedReason)
	}
	if stall < budget {
		t.Fatalf("refused after %v, want >= the %v wait: the gate is supposed to WAIT for a slot before refusing", stall, budget)
	}
	t.Logf("refused clean content after a %v stall (budget %v)", stall.Round(time.Millisecond), budget)

	// (2) wait-then-win path: release the holder mid-wait and time the winner.
	go func() { time.Sleep(budget / 2); close(hold) }()
	start = time.Now()
	pattern, hit = clean.scan([]byte("harmless"), budget)
	total := time.Since(start)
	if hit {
		t.Fatalf("clean content blocked after winning a slot: (%q, %v)", pattern, hit)
	}
	t.Logf("wait-then-win total %v (ceiling is wait+budget = %v)", total.Round(time.Millisecond), 2*budget)
	if total > 2*budget+500*time.Millisecond {
		t.Fatalf("wait-then-win took %v, past the wait+budget ceiling %v", total, 2*budget)
	}

	wg.Wait()
	if got := waitInflight(t, 0); got != 0 {
		t.Fatalf("Inflight() = %d after every worker returned, want 0 — a slot leaked", got)
	}
}

// TestChaos110_NoSlotTakenWithoutPatterns confirms a gateway that configures no
// DPI patterns never touches the gate, so the new fail-closed refusal cannot
// fire on a deployment that does not use the engine.
func TestChaos110_NoSlotTakenWithoutPatterns(t *testing.T) {
	withGate(t, 1)
	s := New(1 << 20) // New seeds an empty pattern set
	if _, hit := s.Scan([]byte("anything")); hit {
		t.Fatalf("empty pattern set produced a hit")
	}
	if got := Inflight(); got != 0 {
		t.Fatalf("Inflight() = %d after an empty-pattern scan, want 0", got)
	}
	if got := SaturationBlocks(); got != 0 {
		t.Fatalf("SaturationBlocks() = %d after an empty-pattern scan, want 0", got)
	}
}

// TestChaos110_AbandonedWorkersDoNotLeakSlots drives the abandonment path at the
// cap repeatedly: every abandoned worker must hand its slot back when its match
// finally returns, or the engine fails closed forever after enough timeouts.
func TestChaos110_AbandonedWorkersDoNotLeakSlots(t *testing.T) {
	withGate(t, 2)
	const budget = 40 * time.Millisecond
	for round := 0; round < 5; round++ {
		hold := make(chan struct{})
		var entered atomic.Int64
		ps := gatedSet(&entered, hold)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, hit := ps.scan([]byte("body"), budget); !hit {
					t.Error("abandoned scan did not fail closed")
				}
			}()
		}
		waitFor(t, "both slots taken", func() bool { return entered.Load() >= 2 })
		wg.Wait() // parents have given up; workers still hold their slots
		if got := Inflight(); got != 2 {
			t.Fatalf("round %d: Inflight() = %d while two abandoned workers are blocked, want 2", round, got)
		}
		close(hold)
		if got := waitInflight(t, 0); got != 0 {
			t.Fatalf("round %d: Inflight() = %d after the abandoned matches returned, want 0 — slots leaked", round, got)
		}
	}
	if got := AbandonedWorkers(); got != 10 {
		t.Fatalf("AbandonedWorkers() = %d, want 10", got)
	}
}

// The approaching-saturation line is the lead indicator for the gate's
// fail-closed refusal, so it must not fire at no load. Truncating 80% DOWN made
// the threshold 1 on the two-slot gate a single-vCPU container gets
// (inflightFloor), which is one ordinary scan — a permanent warning an operator
// learns to ignore, and with it the only notice they get before clean content
// starts being blocked uninspected.
func TestChaos110_ApproachingThresholdDoesNotFireOnOneOrdinaryScan(t *testing.T) {
	for _, tc := range []struct {
		limit int
		want  int64
	}{
		{1, 1}, // a one-slot gate: full IS approaching
		{2, 2}, // inflightFloor, GOMAXPROCS=1: never on a single scan
		{3, 3}, // no lead time to be had at three slots
		{4, 4},
		{8, 7}, // 2 vCPU x ... : lead of one slot
		{16, 13},
		{64, 52}, // large gate keeps real lead time
	} {
		if got := approachingThreshold(tc.limit); got != tc.want {
			t.Errorf("approachingThreshold(%d) = %d, want %d", tc.limit, got, tc.want)
		}
		if got := approachingThreshold(tc.limit); got > int64(tc.limit) {
			t.Errorf("approachingThreshold(%d) = %d, past the cap", tc.limit, got)
		}
	}
	if got := approachingThreshold(0); got != 0 {
		t.Errorf("approachingThreshold(0) = %d, want 0", got)
	}
	// Negative control: the old truncating form warned at one of two.
	if old := int64(2 * 80 / 100); old != 1 {
		t.Fatalf("negative control broken: truncating 80%% of 2 gave %d, expected the 1 this test exists to reject", old)
	}
}
