package hostutil

import (
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// Equivalence proof + regression gates for the StripHostPort already-portless
// fast path.
//
//	go test -bench 'BenchmarkStripHostPort' -benchmem ./internal/hostutil/
//
// Measured on Intel Xeon @ 2.10GHz, linux/amd64, -count=5 (mean). "before" is
// BenchmarkStripHostPort_Baseline, which runs the pre-fast-path body in the
// SAME binary, so the comparison needs no checkout of the parent commit.
//
//	                          before                after
//	  BareHost            41.3 ns  32 B  1      9.3 ns   0 B  0    -77%
//	  LongBareHost        61.1 ns  32 B  1     28.6 ns   0 B  0    -53%
//	  IPv4Literal         39.5 ns  32 B  1      7.7 ns   0 B  0    -81%
//	  Empty               29.5 ns  32 B  1      1.5 ns   0 B  0    -95%
//	  HostWithPort        19.6 ns   0 B  0     20.7 ns   0 B  0     +6%
//	  IPv4WithPort        20.6 ns   0 B  0     22.8 ns   0 B  0    +11%
//	  BracketedV6WithPort 19.2 ns   0 B  0     20.5 ns   0 B  0     +7%
//	  BracketedV6         40.3 ns  32 B  1     41.3 ns  32 B  1     +2%
//	  BareV6              36.5 ns  32 B  1     40.3 ns  32 B  1    +10%
//
//	  RequestFanout (x5) 243.8 ns 160 B  5     63.8 ns   0 B  0    -74%
//
// Stated plainly, including the part that got worse: every shape that CARRIES a
// colon now pays one extra LastIndexByte scan (+1-2 ns) before taking the same
// body it always took. That is accepted because those shapes never allocated —
// they were not the problem — and because the portless shape is the one the
// request path actually produces: the dispatch gate splits the port off r.Host
// before any engine looks at the destination. The trade is ~2 ns on the shape
// that is rare on the hot path, for 32 ns and an allocation on the shape that
// is not.
//
// The two portless-IPv6 shapes are unchanged-and-still-allocating by design;
// see the stripShapes ceilings for why they are deliberately left alone.

// referenceStripHostPort is StripHostPort's body as it stood BEFORE the fast
// path was added — the oracle for every equivalence assertion below.
func referenceStripHostPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.Trim(host, "[]")
}

// stripShapes are the host shapes that reach scan/bypass/feed lookups, ordered
// by how much of real traffic they represent. maxAllocs is the per-shape
// ceiling enforced by TestStripHostPort_AllocRegression.
var stripShapes = []struct {
	name string
	host string
	// maxAllocs is the allocations/op ceiling. Zero means the fast path (or an
	// already-allocation-free body branch) must fully cover the shape. A
	// non-zero ceiling is documented in why with the reason the allocation is
	// NOT reachable by this change.
	maxAllocs float64
	why       string
}{
	// The dominant request-path shape: the dispatch gate has already split the
	// port off, so every downstream engine strips a port that is not there.
	{"BareHost", "www.example.com", 0, ""},
	{"LongBareHost", "r3---sn-apo3qvuoxuxbt-j5pe.googlevideo.com", 0, ""},
	{"IPv4Literal", "203.0.113.10", 0, ""},
	{"Empty", "", 0, ""},
	// Port-carrying shapes take the unchanged body, which already allocates
	// nothing because SplitHostPort SUCCEEDS (no error to construct).
	{"HostWithPort", "www.example.com:443", 0, ""},
	{"IPv4WithPort", "203.0.113.10:8080", 0, ""},
	{"BracketedV6WithPort", "[2001:db8::1]:443", 0, ""},
	// Port-LESS IPv6 shapes are the one case the fast path cannot reach: they
	// carry colons, so the body must run, and SplitHostPort then FAILS on them
	// ("too many colons" / "missing port") and builds the AddrError that
	// allocates. Measured at 1/op BOTH before and after this change — the
	// ceiling records existing behaviour, it is not a regression introduced
	// here. Left alone deliberately: covering it means reimplementing
	// SplitHostPort's IPv6 parsing for a shape that is a small minority of
	// proxied destinations, which is a worse trade than the allocation.
	{"BracketedV6", "[2001:db8::1]", 1, "SplitHostPort errors on a portless IPv6 literal"},
	{"BareV6", "2001:db8::1", 1, "SplitHostPort errors on a portless IPv6 literal"},
}

// stripCorpus is the hand-written half of the equivalence proof: every shape
// the doc comment promises to accept, plus the malformed and boundary inputs
// that decide which branch of the body runs.
func stripCorpus() []string {
	return []string{
		// Fast-path shapes (no ':' and no bracket).
		"", "example.com", "www.example.com", "203.0.113.10", "localhost",
		"trailing.", ".leading", "a..b", "under_score.com", "-lead.com",
		"EXAMPLE.COM", strings.Repeat("a", 300) + ".com", "\x00.com",
		// Port-carrying and bracketed shapes (slow path).
		"example.com:443", "203.0.113.10:8080", "[2001:db8::1]:443",
		"[2001:db8::1]", "[::1]", "[::1]:80", "2001:db8::1", "::1",
		// Malformed / adversarial: these decide whether SplitHostPort errors and
		// whether the Trim still fires. Each is a shape where a naive fast path
		// (e.g. "no colon at all") would silently diverge.
		":", "::", ":443", "example.com:", "example.com::443",
		"[", "]", "[]", "[example.com", "example.com]", "][",
		"[2001:db8::1", "2001:db8::1]", "[[::1]]", "a:b:c",
		"host:port", "host:99999", "host:-1", "[]:443", "[]:",
		"[v6]", "[v6]:1", ":[", "]:", "a]b", "a[b", "a:b]c",
	}
}

// TestStripHostPort_MatchesReference is the closed-form half of the equivalence
// proof: over the hand-written corpus, the optimized function and the
// pre-fast-path body must agree exactly.
func TestStripHostPort_MatchesReference(t *testing.T) {
	for _, in := range stripCorpus() {
		if got, want := StripHostPort(in), referenceStripHostPort(in); got != want {
			t.Errorf("StripHostPort(%q) = %q, pre-fast-path reference = %q", in, got, want)
		}
	}
}

// TestStripHostPort_DocumentedShapes pins the shapes the doc comment promises,
// independently of the reference oracle — so a change that broke BOTH the body
// and the reference in the same way would still fail here.
func TestStripHostPort_DocumentedShapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{"host:port", "host"},
		{"example.com:443", "example.com"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"}, // bare v6 must NOT be truncated
		{"example.com", "example.com"},
		{"203.0.113.10", "203.0.113.10"},
		{"", ""},
	}
	for _, c := range cases {
		if got := StripHostPort(c.in); got != c.want {
			t.Errorf("StripHostPort(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// FuzzStripHostPort is the open-ended half of the equivalence proof: for
// ARBITRARY input the fast path must agree with the pre-fast-path body. This is
// the gate that catches a fast-path condition the hand-written corpus misses.
func FuzzStripHostPort(f *testing.F) {
	for _, s := range stripCorpus() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, host string) {
		if got, want := StripHostPort(host), referenceStripHostPort(host); got != want {
			t.Fatalf("StripHostPort(%q) = %q, reference = %q", host, got, want)
		}
	})
}

// TestStripHostPort_FastPathOnlySkipsNoOps is the direct proof of the claim the
// fast path rests on: whenever hasHostPortSyntax is false, the ORIGINAL body is
// the identity function. If that ever stops holding, the fast path is returning
// something the body would have transformed.
func TestStripHostPort_FastPathOnlySkipsNoOps(t *testing.T) {
	for _, in := range stripCorpus() {
		if hasHostPortSyntax(in) {
			continue
		}
		if got := referenceStripHostPort(in); got != in {
			t.Errorf("fast path claims %q needs no work, but the body maps it to %q", in, got)
		}
	}
}

// TestStripHostPort_AllocRegression is the hard, hardware-independent gate.
// ns/op varies by runner; allocations do not. The pre-fix body allocated 1/op
// for every portless host — the dominant request-path shape — so reintroducing
// an allocation here fails immediately.
func TestStripHostPort_AllocRegression(t *testing.T) {
	for _, s := range stripShapes {
		host, ceiling, why := s.host, s.maxAllocs, s.why
		t.Run(s.name, func(t *testing.T) {
			got := testing.AllocsPerRun(200, func() { benchStrip = StripHostPort(host) })
			if got <= ceiling {
				return
			}
			detail := "the already-portless fast path no longer covers this shape"
			if why != "" {
				detail = "expected at most the inherent cost (" + why + ")"
			}
			t.Errorf("REGRESSION: StripHostPort(%q) allocates %.0f/op, ceiling %.0f — %s. "+
				"This runs several times per proxied request across the threat feed, "+
				"DPI scanner, scan-exclusion matcher, autoexclude cache and traffic "+
				"redactor, so an allocation here is several per request.",
				host, got, ceiling, detail)
		})
	}
}

// TestStripHostPort_FastPathBeatsBaseline proves the fast path actually bypasses
// net.SplitHostPort rather than merely duplicating it. It asserts the
// ALLOCATION difference (deterministic) rather than a timing ratio (flaky on a
// shared CI runner).
func TestStripHostPort_FastPathBeatsBaseline(t *testing.T) {
	const host = "www.example.com"
	baseline := testing.AllocsPerRun(200, func() { benchStrip = referenceStripHostPort(host) })
	optimized := testing.AllocsPerRun(200, func() { benchStrip = StripHostPort(host) })
	if baseline <= optimized {
		t.Fatalf("expected the pre-fast-path body to allocate MORE than the optimized one; "+
			"baseline=%.0f optimized=%.0f — is net.SplitHostPort still on the fast path?",
			baseline, optimized)
	}
	t.Logf("allocs/op: baseline(net.SplitHostPort)=%.0f optimized(fast path)=%.0f", baseline, optimized)
}

// TestStripHostPort_ConcurrentStress is the concurrency/stress test: the fast
// path adds no shared state, so concurrent stripping of mixed shapes must stay
// race-free and agree with the single-threaded reference. Run under -race.
func TestStripHostPort_ConcurrentStress(t *testing.T) {
	corpus := stripCorpus()
	want := make([]string, len(corpus))
	for i, h := range corpus {
		want[i] = referenceStripHostPort(h)
	}

	const goroutines, iterations = 16, 500
	var mismatches atomic.Int64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for it := 0; it < iterations; it++ {
				for i, h := range corpus {
					if StripHostPort(h) != want[i] {
						mismatches.Add(1)
					}
				}
			}
		}()
	}
	wg.Wait()
	if n := mismatches.Load(); n != 0 {
		t.Fatalf("%d concurrent results diverged from the single-threaded reference", n)
	}
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

var benchStrip string

func BenchmarkStripHostPort(b *testing.B) {
	for _, s := range stripShapes {
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchStrip = StripHostPort(s.host)
			}
		})
	}
}

// BenchmarkStripHostPort_Baseline measures the PRE-optimization body on the
// identical inputs, so benchstat over this file alone gives the honest
// before/after without checking out the parent commit.
func BenchmarkStripHostPort_Baseline(b *testing.B) {
	for _, s := range stripShapes {
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchStrip = referenceStripHostPort(s.host)
			}
		})
	}
}

// BenchmarkStripHostPort_RequestFanout approximates ONE proxied request: the
// destination host is independently re-stripped by each engine that defensively
// normalizes its own input. This is the number that matters for throughput.
func BenchmarkStripHostPort_RequestFanout(b *testing.B) {
	// threat feed + DPI scanner + scan-exclusion matcher + autoexclude +
	// traffic redaction — each calling StripHostPort on the same destination.
	const perRequestStrips = 5
	const host = "sub.cdn.assets.example.com"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < perRequestStrips; j++ {
			benchStrip = StripHostPort(host)
		}
	}
}

// BenchmarkStripHostPort_RequestFanoutBaseline is the same fan-out through the
// pre-fast-path body — the per-request garbage the fix removes.
func BenchmarkStripHostPort_RequestFanoutBaseline(b *testing.B) {
	const perRequestStrips = 5
	const host = "sub.cdn.assets.example.com"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < perRequestStrips; j++ {
			benchStrip = referenceStripHostPort(host)
		}
	}
}

// benchStripParallelSink keeps parallel results alive against dead-code
// elimination without a shared package-level write in the measured loop (which
// would be a data race under -race AND would measure false sharing instead of
// the function).
var benchStripParallelSink atomic.Int64

// BenchmarkStripHostPort_Parallel is the concurrency benchmark: the fast path
// must stay lock-free and allocation-free under the goroutine-per-request
// fan-out the proxy runs at, with no shared state to contend on.
func BenchmarkStripHostPort_Parallel(b *testing.B) {
	hosts := []string{
		"www.example.com", "sub.cdn.assets.example.com", "api.service.example.org",
		"203.0.113.10", "static.assets.example.net",
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var local int64 // goroutine-local: no shared write in the measured loop
		i := 0
		for pb.Next() {
			local += int64(len(StripHostPort(hosts[i%len(hosts)])))
			i++
		}
		benchStripParallelSink.Add(local)
	})
}
