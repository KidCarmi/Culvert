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

// gateTimingRounds / gateTimingMargin govern the timing gate below.
//
// Each arm is measured SEVERAL times and the FASTEST result is kept: noise only
// ever makes a measurement slower — a descheduled goroutine, a noisy neighbour,
// a GC pause — so the minimum is the closest available estimate of the intrinsic
// cost, and it is the standard robust estimator when the box is not idle. The
// arms are interleaved round by round so a load spike lands on both rather than
// on whichever happened to run during it.
const (
	gateTimingRounds = 5
	gateTimingMargin = 1.2
)

// bestNsPerOp returns the fastest of gateTimingRounds measurements of one arm.
func bestNsPerOp(rounds []testing.BenchmarkResult) int64 {
	best := rounds[0].NsPerOp()
	for _, r := range rounds[1:] {
		if n := r.NsPerOp(); n < best {
			best = n
		}
	}
	return best
}

// TestBenchGate_CheckRequestURLBeatsLegacy is the timing half, expressed as a
// RATIO so it is machine-independent and needs no re-baselining. Its job is to
// catch the serialise-and-reparse round trip coming back, not to police a few
// nanoseconds.
//
// IT USED TO BE A SINGLE MEASUREMENT PER ARM COMPARED WITH `>=`, i.e. with no
// margin at all — while its own comment claimed the bound was "deliberately
// loose". A comparison of two timings with zero tolerance is a coin flip
// whenever noise exceeds the true gap, and on a loaded CI runner it duly failed
// with BOTH arms inflated about twentyfold over their documented ~376 ns and
// ~887 ns (8387 vs 7551 ns/op), where the ordering is pure scheduling noise. A
// gate that can flake gets muted, which is this repo's standing rule and the
// reason the allocation gate beside this one is deliberately structural.
//
// The substantive claim is now measured as best-of-N per arm against an explicit
// margin, so the comment and the code say the same thing. The real saving is
// ~2.3x, so a 1.2x bound still catches a regression that reintroduces the round
// trip while tolerating a saturated machine.
func TestBenchGate_CheckRequestURLBeatsLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	tf := benchFeed(1000)
	u := benchProxyURL(t)

	// Both arms assign into the same package-level sink so neither can be
	// optimised away differently from the other; the verdict itself is not
	// under test here (the differential covers it).
	fastRounds := make([]testing.BenchmarkResult, 0, gateTimingRounds)
	legacyRounds := make([]testing.BenchmarkResult, 0, gateTimingRounds)
	for i := 0; i < gateTimingRounds; i++ {
		fastRounds = append(fastRounds, testing.Benchmark(func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				gateSink, _ = tf.CheckRequestURL(u)
			}
		}))
		legacyRounds = append(legacyRounds, testing.Benchmark(func(b *testing.B) {
			for j := 0; j < b.N; j++ {
				gateSink, _ = tf.CheckURL(u.String())
			}
		}))
	}
	fast, legacy := bestNsPerOp(fastRounds), bestNsPerOp(legacyRounds)
	if fast <= 0 || legacy <= 0 {
		t.Skipf("unusable measurement (fast=%d legacy=%d ns/op)", fast, legacy)
	}
	if ratio := float64(legacy) / float64(fast); ratio < gateTimingMargin {
		t.Errorf("CheckRequestURL %d ns/op vs CheckURL(u.String()) %d ns/op = %.2fx, want >= %.2fx — "+
			"the parsed-URL path is no longer meaningfully cheaper than the serialise-and-reparse round trip it replaced",
			fast, legacy, ratio, gateTimingMargin)
	}
}
