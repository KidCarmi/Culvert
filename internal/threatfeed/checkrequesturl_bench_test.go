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
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gateSink keeps the ratio gate's two arms symmetric — see its comment.
var gateSink bool

// raceDetectorOn is set true by the //go:build race companion file
// (race_on_test.go).
var raceDetectorOn = false

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

// TestBenchGate_CheckRequestURLTakesNoRoundTrip is the STRUCTURAL half of the
// cost contract: CheckRequestURL must reach its verdict from the *url.URL it was
// handed, and may serialise-and-reparse only on the documented fallback path.
//
// IT USED TO BE A TIMING COMPARISON, and that criterion is not measurable in the
// lane that runs it. Two CI failures, both with zero real regressions:
//
//   - a single measurement per arm compared with `>=`, i.e. no margin at all
//     while its own comment claimed the bound was "deliberately loose", INVERTED
//     on a saturated runner (8387 vs 7551 ns/op, against documented ~376 and
//     ~887);
//   - with best-of-5 per arm the inversion was fixed but the RATIO COMPRESSED to
//     1.17x against a 1.20x bound (9957 vs 11627 ns/op).
//
// The compression could not be reproduced locally: under full CPU saturation the
// ratio HELD (4.61x loaded against 4.42x idle under -race, the measured per-op
// floor moving only 15 -> 19 ns with b.N in the tens of millions), so neither
// additive noise nor an overhead-dominated iteration count explains it. A bound
// loose enough to survive whatever the lane does to this measurement would be too
// loose to catch the regression — this repo's recorded conclusion for exactly this
// wall, which internal/threatfeed is named among the packages to have hit, and a
// gate that can flake gets muted.
//
// So the verdict is the structural property, which is load-invariant. Nothing is
// left unasserted: the substantive claim is covered by two further gates that
// cannot flake — TestBenchGate_CheckRequestURLAllocs (AllocsPerRun: the fast path
// at <= 2 allocs AND the legacy round trip strictly more) and
// TestCheckRequestURL_FastPathIsActuallyTaken (normaliseParsedURL reports handled
// for ordinary traffic). What is gone is a verdict the environment cannot support.
//
// The NUMBERS have a home that does not cost the race lane 12 s per run to log
// something nobody gates on — the four BenchmarkFeedCheckRequestURL{,_Legacy}
// arms at the top of this file, invoked as the header documents.
func TestBenchGate_CheckRequestURLTakesNoRoundTrip(t *testing.T) {
	// u.String() is the serialise step of the round trip this optimisation
	// removes; it must appear ONLY inside the `!handled` fallback. Deleting the
	// fast path would make it unconditional, which is precisely the regression
	// the timing comparison existed to catch.
	src, err := os.ReadFile(filepath.Join(pkgSourceDir(), "threatfeed.go")) //nolint:gosec // fixed in-package path
	if err != nil {
		t.Fatalf("read threatfeed.go: %v", err)
	}
	body, err := funcBody(string(src), "func (tf *Feed) CheckRequestURL(")
	if err != nil {
		t.Fatalf("locate CheckRequestURL: %v", err)
	}
	if !strings.Contains(body, "normaliseParsedURL(u)") {
		t.Error("CheckRequestURL no longer consults normaliseParsedURL — the parsed-URL fast path is gone, " +
			"so every call serialises and reparses the URL net/http already parsed")
	}
	fallback := strings.Index(body, "if !handled {")
	if fallback < 0 {
		t.Fatal("CheckRequestURL no longer has an `if !handled {` fallback — this wall must be updated with it")
	}
	// CONFINE the serialisation, do not merely order it against the fallback.
	// The first version of this wall asserted only that no u.String() appeared
	// BEFORE the fallback, which is a weaker claim than the sentence above it
	// makes: a SECOND, unconditional u.String() added AFTER the fallback block
	// restores the exact round trip and sailed straight through (Codex, round 9;
	// reproduced — the wall reported ok while CheckRequestURL had gone back to
	// 6 allocs/op). Counting and locating is what makes the assertion match the
	// claim; a gap in a wall is how the class it guards returns by another route.
	if n := strings.Count(body, "u.String()"); n != 1 {
		t.Errorf("CheckRequestURL serialises the URL %d times, want exactly 1 (inside the `!handled` fallback) — "+
			"a second u.String() makes the round trip unconditional again however it is guarded", n)
		return
	}
	blockEnd := strings.Index(body[fallback:], "\n\t}")
	if blockEnd < 0 {
		t.Fatal("cannot delimit the `if !handled {` block — this wall must be updated with it")
	}
	blockEnd += fallback
	if at := strings.Index(body, "u.String()"); at < fallback || at > blockEnd {
		t.Error("CheckRequestURL's only u.String() is OUTSIDE the `!handled` fallback — " +
			"the serialise-and-reparse round trip runs on every call again")
	}
}

// TestBenchGate_CheckRequestURLBeatsLegacy is the timing half, expressed as a
// RATIO measured in ONE run so it is machine-independent and needs no
// re-baselining. The bound is deliberately loose (the measured saving is far
// larger) because its job is to catch the round trip coming back, not to police
// a few nanoseconds.
//
// It does not run under -race. The saving it measures is mostly the legacy
// arm's extra allocations, and the race detector's per-access instrumentation
// costs far more than those, so both arms converge (measured on the Fast gate's
// race lane: 12054 vs 11830 and 7316 vs 7271 ns/op, ~1% apart) and the verdict
// becomes a coin toss in either direction. Nothing is lost by stepping aside:
// TestBenchGate_CheckRequestURLAllocs pins the same regression on every lane
// (allocation counts are race-independent), and this gate still runs,
// uninstrumented and twice, in the determinism job.
func TestBenchGate_CheckRequestURLBeatsLegacy(t *testing.T) {
	if testing.Short() {
		t.Skip("timing gate")
	}
	if raceDetectorOn {
		t.Skip("timing gate: -race instrumentation swamps the allocation saving being timed; the allocs gate covers this lane")
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

// funcBody returns the source of the function whose declaration starts with
// prefix, delimited by the closing brace at column 0.
func funcBody(src, prefix string) (string, error) {
	i := strings.Index(src, prefix)
	if i < 0 {
		return "", fmt.Errorf("declaration %q not found", prefix)
	}
	rest := src[i:]
	j := strings.Index(rest, "\n}\n")
	if j < 0 {
		return "", fmt.Errorf("could not delimit %q", prefix)
	}
	return rest[:j], nil
}

// pkgSourceDir returns this package's source directory, so the structural read
// above cannot be flaked by a concurrent os.Chdir in the same test binary — the
// anchoring rule the root package's static_read_wall_test.go enforces.
func pkgSourceDir() string {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(self)
}
