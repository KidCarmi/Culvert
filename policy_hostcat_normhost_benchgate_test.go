//go:build benchgate

package main

// Wall-clock COST gate for the per-scan normalized-host hoist.
//
// It lives behind the `benchgate` tag, and that is a correctness requirement
// rather than tidiness. A timing ratio is only meaningful on an UNINSTRUMENTED
// binary, and the Fast/QA gates run the root suite under `-race` WITH coverage.
// Measured on this change, 50 armed rules, canonical host:
//
//	uninstrumented      pre-hoist   10550 ns/op   hoisted  5728 ns/op   ratio 0.54
//	-race + coverage    pre-hoist  168774 ns/op   hoisted 203631 ns/op   ratio 1.21
//
// Instrumentation makes the scan ~30x dearer, so the ~2.5 µs this hoist actually
// saves across 50 rules is ~1.5% of the measurement — below the noise — and the
// overhead is not symmetric between the two arms (they traverse different
// numbers of instrumented function entries), so the instrumented ratio can
// invert and did. The gate reported the hoisted path as SLOWER and failed the
// race shard on a change that is 46% faster.
//
// So: do NOT move this gate into the default suite, and do not "fix" it by
// loosening the bound — a bound loose enough to survive instrumentation cannot
// detect the regression it exists to catch. The repo's standing rule is that a
// gate which can flake gets muted; the structural gates that DO belong in the
// default suite are
// TestBenchGate_CategoryScanAllocationsAreFlatInRuleCount (allocation counts are
// a property of the code, not the clock — it passes unchanged under `-race` plus
// coverage) and TestNormHost_PerRuleMatchersReadTheMemo (which names the call
// site that regressed).
//
// Run it the way CLAUDE.md documents for this lane:
//
//	go test -tags benchgate -run 'TestBenchGate_' -count=1 .

import "testing"

// TestBenchGate_CategoryScanBeatsPreHoistBody is the policy-level cost gate: a
// same-run RATIO, machine-independent by construction, asserting only the
// DIRECTION and a conservative margin at a realistic rule count.
//
// It is deliberately NOT an absolute ns bound — those get re-baselined per
// machine and then muted. The margin is loose because the claim under test is
// "the hoist is a real saving at rule scale", not "the saving equals X".
func TestBenchGate_CategoryScanBeatsPreHoistBody(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	seedCategoryTaxonomy(t, 12, 40)
	benchArmView(t, true)
	cats := benchScanCats(50)

	// Sanity: both arms must agree on the verdict, or the gate is comparing two
	// different computations.
	for _, host := range []string{benchCategoryScanHostCanonical, benchCategoryScanHost} {
		if runCategoryScanOn(host, cats) != runCategoryScanLegacyOn(host, cats) {
			t.Fatalf("arms disagree on the verdict for %q; the cost comparison would be meaningless", host)
		}
	}

	measure := func(fn func()) float64 {
		best := -1.0
		for trial := 0; trial < 4; trial++ {
			r := testing.Benchmark(func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					fn()
				}
			})
			ns := float64(r.NsPerOp())
			if best < 0 || ns < best {
				best = ns
			}
		}
		return best
	}

	// BOTH host representations are gated. The canonical one is the conservative
	// case (CPU only, no allocation to remove) and is where a regression would
	// hide if the gate sampled the non-canonical shape alone — the
	// representation-sampling rule from CHAOS-69. Its bound is looser for exactly
	// that reason: there is less to win, so there is less margin above noise.
	cases := []struct {
		name     string
		host     string
		maxRatio float64
	}{
		{"canonical", benchCategoryScanHostCanonical, 0.90},
		{"non-canonical", benchCategoryScanHost, 0.85},
	}
	for _, tc := range cases {
		var sink bool
		legacy := measure(func() { sink = runCategoryScanLegacyOn(tc.host, cats) })
		hoisted := measure(func() { sink = runCategoryScanOn(tc.host, cats) })
		_ = sink

		ratio := hoisted / legacy
		t.Logf("50-rule armed scan, %s host: pre-hoist %.0f ns/op, hoisted %.0f ns/op, ratio %.2f (%.0f%% saved)",
			tc.name, legacy, hoisted, ratio, (1-ratio)*100)
		if ratio >= tc.maxRatio {
			t.Errorf("%s host: hoisted scan is not materially cheaper than the pre-hoist body: "+
				"%.0f vs %.0f ns/op (ratio %.2f, want < %.2f). Either a call site in "+
				"matchesCategory stopped reading normHost(), or hostutil.NormalizeHost "+
				"became free — check TestNormHost_PerRuleMatchersReadTheMemo first, since "+
				"it names the site.", tc.name, hoisted, legacy, ratio, tc.maxRatio)
		}
	}
}
