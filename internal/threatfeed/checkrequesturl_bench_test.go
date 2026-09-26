package threatfeed

// Per-request cost of the full-URL threat check (Performance Guardian).
//
// preDispatchBlocked (proxy.go) runs this check on every forwarded plain-HTTP
// request, on the request goroutine, before the policy engine. It used to be
// called as CheckURL(r.URL.String()) — so a *url.URL net/http had just parsed
// was serialised and this package parsed it straight back.
//
// The benchmarks below measure BOTH shapes in ONE run, so the comparison stays
// reproducible in-tree on any runner rather than living in a commit message —
// the convention BenchmarkHTTPForward_LegacyClientPerRequest and
// BenchmarkPolicyDecisionLine_Legacy already follow. The _Legacy arms are the
// baseline, never the thing under test.
//
// BenchmarkFeedCheckDomain_Miss is the CONTROL to read these against: it does
// the same amount of real work (canonicalise a host, probe one map) and costs
// ~115 ns at 0 allocs. The gap between it and the legacy URL arm was the
// re-derivation.
//
//	go test -run '^$' -bench 'BenchmarkFeedCheckRequestURL' -benchmem -count=6 ./internal/threatfeed/

import (
	"net/url"
	"testing"
)

// gateSink keeps the ratio gate's two arms symmetric — see its comment.
var gateSink bool

// benchProxyURL is the shape a forward proxy actually sees on the plain-HTTP
// path: an absolute-form URL with a real path and a query string. The query is
// present deliberately — NormaliseURL strips it, so it is bytes the legacy
// shape serialises and re-parses purely to throw away.
func benchProxyURL(tb testing.TB) *url.URL {
	tb.Helper()
	u, err := url.Parse("http://files.example.com/downloads/report/q3-2026.pdf?token=abc123&v=2")
	if err != nil {
		tb.Fatalf("parse: %v", err)
	}
	return u
}

// BenchmarkFeedCheckRequestURL_MissLegacy freezes the PRE-CHANGE call shape:
// the proxy serialising a parsed URL so the feed can parse it back.
func BenchmarkFeedCheckRequestURL_MissLegacy(b *testing.B) {
	tf := benchFeed(100000)
	u := benchProxyURL(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if hit, _ := tf.CheckURL(u.String()); hit {
			b.Fatal("unexpected hit")
		}
	}
}

// BenchmarkFeedCheckRequestURL_Miss is the shipped shape.
func BenchmarkFeedCheckRequestURL_Miss(b *testing.B) {
	tf := benchFeed(100000)
	u := benchProxyURL(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if hit, _ := tf.CheckRequestURL(u); hit {
			b.Fatal("unexpected hit")
		}
	}
}

// BenchmarkFeedCheckRequestURL_MissLegacyParallel and its sibling are the
// scaling halves. Neither shape takes a lock (the read view predates this
// change), so the expected result is that both scale — the point is that the
// shipped shape scales from a far lower fixed cost, and that removing three
// allocations per request removes that much GC pressure from every core at
// once.
func BenchmarkFeedCheckRequestURL_MissLegacyParallel(b *testing.B) {
	tf := benchFeed(100000)
	u := benchProxyURL(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if hit, _ := tf.CheckURL(u.String()); hit {
				b.Fatal("unexpected hit")
			}
		}
	})
}

func BenchmarkFeedCheckRequestURL_MissParallel(b *testing.B) {
	tf := benchFeed(100000)
	u := benchProxyURL(b)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if hit, _ := tf.CheckRequestURL(u); hit {
				b.Fatal("unexpected hit")
			}
		}
	})
}

// ── Regression gates ─────────────────────────────────────────────────────────

// TestBenchGate_CheckRequestURLAllocs is keyed on ALLOCATIONS PER OP, not
// ns/op, for the reason bench_regression_test.go states: allocation counts are
// deterministic and hardware-independent, so the gate means the same thing on
// any runner, under -race, at any load. ns/op on a shared CI box does not.
//
// The bound is the exact measured steady state with no headroom. Every
// remaining allocation is accounted for: net.ParseIP builds a parse error for
// every hostname that is not an IP literal (its failure path allocates), and
// the canonical key is one string concatenation. A change that needs another
// one should say so here with its justification rather than slip past a padded
// bound.
//
// The legacy arm is asserted too, and it is not decoration: it is what makes
// the gate's number mean "this is cheaper than what it replaced" rather than
// "this is some number someone wrote down".
func TestBenchGate_CheckRequestURLAllocs(t *testing.T) {
	tf := benchFeed(1000)
	u := benchProxyURL(t)

	fast := testing.AllocsPerRun(200, func() {
		if hit, _ := tf.CheckRequestURL(u); hit {
			t.Fatal("unexpected hit")
		}
	})
	if fast > 2 {
		t.Errorf("CheckRequestURL = %.0f allocs/op, want <= 2", fast)
	}

	legacy := testing.AllocsPerRun(200, func() {
		if hit, _ := tf.CheckURL(u.String()); hit {
			t.Fatal("unexpected hit")
		}
	})
	if legacy <= fast {
		t.Errorf("legacy CheckURL(u.String()) = %.0f allocs/op vs CheckRequestURL %.0f — "+
			"the parsed-URL path is no longer cheaper than the round trip it replaced", legacy, fast)
	}
}

// TestBenchGate_CheckRequestURLBeatsLegacy is the timing half, expressed as a
// RATIO measured in ONE run so it is machine-independent and needs no
// re-baselining. Its job is to catch the round trip coming back, not to police
// a few nanoseconds.
//
// It does NOT run under the race detector, and that is a statement about the
// instrument rather than about the code. Race instrumentation inflates both
// arms by roughly an order of magnitude and, far more importantly, widens their
// variance enough to swallow the ~2.3x margin being measured. Measured here on
// the same box, same 200 iterations, two samples each:
//
//	          no -race        with -race
//	legacy    775 ns          4217 / 9246 ns
//	fast      330 ns           912 / 1670 ns
//
// Without -race the two are cleanly 2.3x apart and the comparison means what it
// says. With -race the fast arm's spread alone (912-1670) is wider than the
// whole margin, so the verdict is decided by scheduling. CI proved it: the
// sharded race lane failed at 7243 ns/op against 7150 ns/op — a 1.3% inversion
// — and failed again at 7139 against 7115 on the attempt before, with both arms
// pinned near 7.15 us regardless of which function was running.
//
// That last detail is what rules out a transient: an interleaved best-of-three
// was tried first, on the theory that the arms ran a second apart and drift
// decided the sign, and it STILL reported 7243 against 7150. A minimum over
// repeated rounds cannot filter noise that is not transient. The inflation is
// the instrumentation, present in every sample, and no sampling strategy
// recovers a 2.3x signal from underneath it.
//
// This repository has already reached this conclusion twice. The read-view note
// in CLAUDE.md records that a scaling-ratio gate for this very package was
// built and rejected "because its margin narrows to 1.35x under -race, too thin
// for a per-PR runner", and stress_helpers_test.go skips its RSS leak
// assertion under -race with the same shape of reasoning: the race detector
// makes that particular measurement meaningless while the other checks still
// apply. Same here.
//
// The property itself is NOT unguarded in CI.
// TestBenchGate_CheckRequestURLAllocs above runs under -race, is deterministic,
// and asserts the same thing this arm asserts (4 allocs/op for the round trip
// against 2 for the parsed-URL path) — and the regression this exists to catch,
// the fast path reverting to a String()/Parse() round trip, changes the
// allocation count by construction. This arm is corroboration on a runner where
// the clock can be trusted; it must not be the reason a PR is red at random.
//
// Do NOT "fix" this by widening the bound into a tolerance. The regression
// lands the two arms at parity, which is exactly what a tolerance would pass.
func TestBenchGate_CheckRequestURLBeatsLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	if raceDetectorOn {
		t.Skip("timing gate: the race detector's overhead exceeds the margin being measured — " +
			"TestBenchGate_CheckRequestURLAllocs carries this property deterministically under -race")
	}
	tf := benchFeed(1000)
	u := benchProxyURL(t)

	// Both arms assign into the same package-level sink so neither can be
	// optimised away differently from the other; the verdict itself is not
	// under test here (the differential covers it).
	fast := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gateSink, _ = tf.CheckRequestURL(u)
		}
	})
	legacy := testing.Benchmark(func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			gateSink, _ = tf.CheckURL(u.String())
		}
	})
	if fast.NsPerOp() >= legacy.NsPerOp() {
		t.Errorf("CheckRequestURL %d ns/op is not faster than CheckURL(u.String()) %d ns/op",
			fast.NsPerOp(), legacy.NsPerOp())
	}
}
