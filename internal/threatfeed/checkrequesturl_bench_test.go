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
	"math"
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
// The two arms are INTERLEAVED and each is scored by its MINIMUM sample, and
// that is a correctness property of the gate rather than a refinement. The
// first shape measured each arm exactly once, back to back, and compared them
// strictly (`fast >= legacy` fails) — which reads as a tight gate and is in
// fact a coin flip on a contended runner. Observed on CI: 7139 ns/op against
// 7115 ns/op, a 0.3% inversion, where the honest margin is ~2.3x (this box:
// 318-465 ns fast against 821-921 ns legacy).
//
// Read those numbers and the failure mode is plain. The fast arm came out ~19x
// its true cost, so the benchmark was not measuring the function; and both arms
// landed within 0.3% of each other rather than staying 2.3x apart, so the
// interference was ADDITIVE per op, not a multiplicative slowdown — additive
// noise compresses any ratio toward 1.0. The arms then run about a second
// apart, so whichever one happened to straddle a load change lost, and the
// SIGN of a 0.3% difference is decided by drift rather than by the code.
//
// Interleaving puts both arms under the same conditions round by round, and the
// minimum is the least-contaminated sample of each — noise only ever adds. The
// assertion itself is UNCHANGED and still strict: the fast path must come out
// ahead. This makes the measurement trustworthy; it does not make the bound
// forgiving, and it must not be "simplified" into a tolerance. A permissive
// ratio would be the wrong repair in the other direction — the regression this
// exists to catch (the parsed-URL fast path reverting to a String()/Parse()
// round trip) lands the two arms at parity, which is precisely what a
// tolerance would wave through.
//
// TestBenchGate_CheckRequestURLAllocs above is the hardware-independent half
// and carries the same property deterministically; this arm is the corroborating
// one, so it must not be the reason a PR is red at random.
func TestBenchGate_CheckRequestURLBeatsLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	tf := benchFeed(1000)
	u := benchProxyURL(t)

	// Both arms assign into the same package-level sink so neither can be
	// optimised away differently from the other; the verdict itself is not
	// under test here (the differential covers it).
	measure := func(fn func()) int64 {
		return testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				fn()
			}
		}).NsPerOp()
	}

	const rounds = 3
	fast, legacy := int64(math.MaxInt64), int64(math.MaxInt64)
	for i := 0; i < rounds; i++ {
		// Alternate within the round so a load change between the two
		// measurements cannot systematically favour either arm.
		fast = min(fast, measure(func() { gateSink, _ = tf.CheckRequestURL(u) }))
		legacy = min(legacy, measure(func() { gateSink, _ = tf.CheckURL(u.String()) }))
	}
	if fast >= legacy {
		t.Errorf("CheckRequestURL %d ns/op is not faster than CheckURL(u.String()) %d ns/op "+
			"(best of %d interleaved rounds each)", fast, legacy, rounds)
	}
}
