//go:build benchgate

package urlcat

// Wall-clock COST gate for the normalized-host entry points.
//
// Behind the `benchgate` tag for the same measured reason as the root gate
// (policy_hostcat_normhost_benchgate_test.go): a timing ratio means nothing on an
// instrumented binary, and CI runs this package's suite under `-race` with
// coverage. On the root half of this change the instrumented ratio INVERTED —
// 0.54 uninstrumented against 1.21 under `-race` plus coverage — reporting a
// 46%-faster change as slower, because instrumentation is ~30x the real cost and
// is not symmetric between the two arms.
//
// The gates that belong in this package's default suite are the DIFFERENTIAL
// (which decides a verdict, not a duration) and
// TestBenchGate_MatchesNormalizedHostIsAllocationFree (AllocsPerRun counts a
// property of the code). Do not move this one beside them, and do not loosen its
// bound to survive instrumentation — a bound that loose cannot see the
// regression it exists to catch.
//
//	go test -tags benchgate -run 'TestBenchGate_' -count=1 ./internal/urlcat/

import "testing"

// TestBenchGate_NormalizedEntryPointIsCheaperThanNormalizing is the COST gate,
// and it is a same-run RATIO rather than an absolute bound: both arms are timed
// in one process on one machine, so the clock cancels. An absolute ns bound gets
// re-baselined per machine and then muted (the standing rule recorded for
// sanitizeLog, connlimit and the latency histogram).
//
// It asserts only the DIRECTION and a conservative margin: skipping
// hostutil.NormalizeHost must make the probe materially cheaper. The margin is
// deliberately loose (10%) because the point is that the saving exists and is
// not noise, not that it equals any particular figure — the figures belong in
// the benchmark output.
func TestBenchGate_NormalizedEntryPointIsCheaperThanNormalizing(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	s := New(DefaultEntries())
	cat := Category("Social Media")
	const host = "uncategorized.example.net"

	// Best-of-N on both arms, interleaved, to blunt scheduler noise. Taking the
	// MINIMUM of each arm is the right statistic for "how cheap can this be":
	// the maximum is set by preemption, which is not a property of the code.
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

	var sink bool
	// Baseline is the FROZEN pre-split body, never MatchesHost — see
	// legacyMatchesHost for why that distinction is load-bearing.
	withNorm := measure(func() { sink = legacyMatchesHost(s, cat, host) })
	preNorm := measure(func() { sink = s.MatchesNormalizedHost(cat, host) })
	_ = sink

	t.Logf("legacy (fused normalize+probe) %.1f ns/op; MatchesNormalizedHost %.1f ns/op; ratio %.2f",
		withNorm, preNorm, preNorm/withNorm)
	if preNorm >= withNorm*0.90 {
		t.Errorf("pre-normalized probe is not materially cheaper: %.1f vs %.1f ns/op (ratio %.2f, want < 0.90). "+
			"If hostutil.NormalizeHost became free this gate is obsolete — delete it rather than loosening it, "+
			"and revisit normHost() in policy_hostcat.go, which exists only for this saving.",
			preNorm, withNorm, preNorm/withNorm)
	}
}
