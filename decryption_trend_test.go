package main

import (
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/decryptobs"
)

// decryption_trend_test.go — ADR-0011 §3 coverage-trend backend. Pins the per-interval
// delta sampling, the ratio semantics (failures excluded), the ring cap, and the
// seed-baseline (no first-sample jump).

// fakeTotals is a mutable cumulative-totals source for the trend sampler.
type fakeTotals struct{ i, b, f int64 }

func newTrend(ft *fakeTotals, clk *[]time.Time, idx *int) *decCoverageTrend {
	return &decCoverageTrend{
		now:    func() time.Time { t := (*clk)[*idx]; *idx++; return t },
		totals: func() (int64, int64, int64) { return ft.i, ft.b, ft.f },
	}
}

func TestDecTrend_DeltaSamplingAndRatio(t *testing.T) {
	ft := &fakeTotals{i: 100, b: 50, f: 10} // pre-existing lifetime totals
	clk := []time.Time{time.Unix(1000, 0), time.Unix(1060, 0), time.Unix(1120, 0)}
	idx := 0
	tr := newTrend(ft, &clk, &idx)

	// Seed the baseline: the first sample must NOT count the pre-existing 100/50/10.
	tr.seedBaseline()

	// Interval 1: +8 inspected, +2 bypassed, +1 failed.
	ft.i, ft.b, ft.f = 108, 52, 11
	tr.sample()
	// Interval 2: +6 inspected, +6 bypassed, +0 failed.
	ft.i, ft.b, ft.f = 114, 58, 11
	tr.sample()

	s := tr.snapshot()
	if len(s) != 2 {
		t.Fatalf("samples = %d, want 2 (seed emits none)", len(s))
	}
	// Interval 1: delta 8/2/1; ratio 8/(8+2)=0.8 (failure excluded from denominator).
	if s[0].Inspected != 8 || s[0].Bypassed != 2 || s[0].Failed != 1 {
		t.Fatalf("interval 1 deltas = %+v", s[0])
	}
	if s[0].Ratio != 0.8 {
		t.Fatalf("interval 1 ratio = %v, want 0.8", s[0].Ratio)
	}
	// Interval 2: delta 6/6/0; ratio 0.5.
	if s[1].Inspected != 6 || s[1].Bypassed != 6 || s[1].Ratio != 0.5 {
		t.Fatalf("interval 2 = %+v", s[1])
	}
	// seedBaseline does not consume a clock tick; the two samples take clk[0]/clk[1].
	if s[0].TS != time.Unix(1000, 0).UnixMilli() || s[1].TS != time.Unix(1060, 0).UnixMilli() {
		t.Fatalf("timestamps wrong: %d %d", s[0].TS, s[1].TS)
	}
}

func TestDecTrend_RingCap(t *testing.T) {
	ft := &fakeTotals{}
	// Enough clock ticks for the cap+extra samples.
	clk := make([]time.Time, decTrendCap+20)
	for i := range clk {
		clk[i] = time.Unix(int64(i), 0)
	}
	idx := 0
	tr := newTrend(ft, &clk, &idx)
	tr.seedBaseline()
	for i := 0; i < decTrendCap+10; i++ {
		ft.i++ // +1 inspected per interval
		tr.sample()
	}
	s := tr.snapshot()
	if len(s) != decTrendCap {
		t.Fatalf("ring len = %d, want capped at %d", len(s), decTrendCap)
	}
	// Every retained sample is a +1-inspected interval (ratio 1.0).
	for _, x := range s {
		if x.Inspected != 1 || x.Ratio != 1.0 {
			t.Fatalf("unexpected retained sample: %+v", x)
		}
	}
}

func TestDecTrend_SampleBeforeSeedDoesNotJump(t *testing.T) {
	ft := &fakeTotals{i: 500, b: 300} // large pre-existing totals
	clk := []time.Time{time.Unix(1, 0), time.Unix(2, 0)}
	idx := 0
	tr := newTrend(ft, &clk, &idx)
	// sample() with no prior seed must seed (not emit a 500/300 jump).
	tr.sample()
	if len(tr.snapshot()) != 0 {
		t.Fatal("first sample() before seed emitted a jump sample")
	}
	ft.i, ft.b = 510, 305
	tr.sample()
	s := tr.snapshot()
	if len(s) != 1 || s[0].Inspected != 10 || s[0].Bypassed != 5 {
		t.Fatalf("post-seed delta wrong: %+v", s)
	}
}

// TestCoverageTotals_Folding pins the outcome→bucket folding used by the sampler.
func TestCoverageTotals_Folding(t *testing.T) {
	beforeI, beforeB, beforeF := coverageTotals()
	recordDecryptSession(&DecryptionOutcome{Outcome: decryptobs.OutcomeInspected, DecisionSource: decryptobs.DecisionPolicyInspect, TLSVersion: decryptobs.TLSVersion13})
	recordDecryptSession(&DecryptionOutcome{Outcome: decryptobs.OutcomeBypassManual, DecisionSource: decryptobs.DecisionManualSSLBypass})
	recordDecryptSession(&DecryptionOutcome{Outcome: decryptobs.OutcomeRescued, DecisionSource: decryptobs.DecisionAutoexcludeRescue})
	recordDecryptFailure(&DecryptionOutcome{Outcome: decryptobs.OutcomeFailed, DecisionSource: decryptobs.DecisionNoFailOpen502, FailStage: decryptobs.FailStageUpstreamHandshake, FailCategory: decryptobs.FailCategoryOther})

	i, b, f := coverageTotals()
	if i-beforeI != 1 {
		t.Fatalf("inspected delta = %d, want 1", i-beforeI)
	}
	if b-beforeB != 2 { // bypass_manual + rescued both fold to bypassed
		t.Fatalf("bypassed delta = %d, want 2", b-beforeB)
	}
	if f-beforeF != 1 {
		t.Fatalf("failed delta = %d, want 1", f-beforeF)
	}
}
