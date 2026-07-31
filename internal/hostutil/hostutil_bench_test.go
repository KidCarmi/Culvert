package hostutil

import (
	"sync"
	"sync/atomic"
	"testing"
)

// Benchmarks for the NormalizeHostStrict already-canonical fast path.
//
//	go test -bench 'BenchmarkNormalizeHost' -benchmem ./internal/hostutil/
//
// Measured on the CI reference box (Intel Xeon @ 2.80GHz, linux/amd64):
//
//	                          before (idna.ToASCII)   after (fast path)
//	  ASCII hostname            333 ns/op  96 B  2      46 ns/op   0 B  0
//	  IP literal                 55 ns/op   0 B  0      55 ns/op   0 B  0   (unchanged)
//	  IDN / ACE label           ~1.4 µs/op          unchanged (slow path)
//
// The win compounds on the proxy hot path: the SAME destination host is
// normalized ~10x per request by engines that each defensively normalize their
// own input (strict dispatch gate, blocklist, threat feed, policy FQDN matching,
// category lookup, SSL-bypass matcher, autoexclude, auth policy).

var (
	benchNorm string
	benchOK   bool
)

// hostShapes are the destination shapes a forward proxy actually sees, ordered
// by how much of real traffic they represent. maxAllocs is the per-shape
// allocation ceiling enforced by TestNormalizeHostStrict_AllocRegression.
var hostShapes = []struct {
	name string
	host string
	// maxAllocs is the allocations/op ceiling for this shape. Zero means the
	// already-canonical fast path must fully cover it. A non-zero ceiling is
	// documented below with WHY the allocation is irreducible.
	maxAllocs float64
	why       string
}{
	{"ShortASCII", "example.com", 0, ""},
	{"TypicalASCII", "sub.cdn.assets.example.com", 0, ""},
	{"LongASCII", "r3---sn-apo3qvuoxuxbt-j5pe.googlevideo.com", 0, ""},
	{"IPv4Literal", "203.0.113.10", 0, ""},
	{"IPv6Literal", "[2001:db8::1]", 0, ""},
	// A host that is not already lowercase cannot be canonicalized without
	// building the lowered string; that single allocation is inherent to the
	// contract, not to the fast path. The fast path still removes the other two
	// (both net.ParseIP failures) and skips idna entirely.
	{"MixedCaseASCII", "Sub.CDN.Example.COM", 1, "strings.ToLower must build the lowered host"},
	// IDN/ACE hosts legitimately take the slow path: idna.ToASCII genuinely has
	// work to do. Bounded generously — this gate is here to catch an ORDER-of-
	// magnitude regression in the slow path, not to pin an x/net implementation
	// detail that may shift between releases.
	{"ACELabel", "xn--bcher-kva.example.com", 24, "idna.ToASCII decodes and validates the ACE label"},
	{"UnicodeIDN", "bücher.example.com", 24, "idna.ToASCII punycode-encodes the non-ASCII label"},
}

func BenchmarkNormalizeHostStrict(b *testing.B) {
	for _, s := range hostShapes {
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchNorm, benchOK = NormalizeHostStrict(s.host)
			}
		})
	}
}

// BenchmarkNormalizeHostStrict_Baseline measures the PRE-optimization body on
// the identical inputs, so `benchstat` over this file alone gives the honest
// before/after comparison without needing to check out the parent commit.
func BenchmarkNormalizeHostStrict_Baseline(b *testing.B) {
	for _, s := range hostShapes {
		b.Run(s.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchNorm, benchOK = referenceNormalizeHostStrict(s.host)
			}
		})
	}
}

// BenchmarkNormalizeHost covers the fail-open wrapper the stores use as their
// key-canonicalization entry point.
func BenchmarkNormalizeHost(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchNorm = NormalizeHost("sub.cdn.assets.example.com")
	}
}

// BenchmarkNormalizeHostStrict_RequestFanout approximates ONE proxied request:
// the strict dispatch gate plus the ~9 independent engines that each normalize
// the same destination. This is the number that matters for proxy throughput.
func BenchmarkNormalizeHostStrict_RequestFanout(b *testing.B) {
	const perRequestNormalizations = 10
	const host = "sub.cdn.assets.example.com"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		for j := 0; j < perRequestNormalizations; j++ {
			benchNorm, benchOK = NormalizeHostStrict(host)
		}
	}
}

// benchParallelSink keeps the parallel benchmark's results alive against
// dead-code elimination. It is deliberately NOT the plain benchNorm/benchOK
// globals the serial benchmarks use: writing a shared package-level sink from
// every RunParallel worker is a data race under -race AND makes the benchmark
// measure false sharing on that cache line instead of normalization cost —
// precisely the contention this benchmark exists to prove is absent.
var benchParallelSink atomic.Int64

// BenchmarkNormalizeHostStrict_Parallel is the concurrency benchmark: the fast
// path must stay lock-free and allocation-free under the goroutine-per-request
// fan-out the proxy runs at, with no shared state to contend on. Each worker
// therefore accumulates into a GOROUTINE-LOCAL variable inside the measured
// loop and folds its total in exactly once on the way out, so the only
// synchronized write is O(workers), not O(b.N).
func BenchmarkNormalizeHostStrict_Parallel(b *testing.B) {
	hosts := []string{
		"example.com", "sub.cdn.assets.example.com", "api.service.example.org",
		"203.0.113.10", "static.assets.example.net",
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var local int64 // goroutine-local: no shared write in the measured loop
		i := 0
		for pb.Next() {
			norm, ok := NormalizeHostStrict(hosts[i%len(hosts)])
			local += int64(len(norm))
			if ok {
				local++
			}
			i++
		}
		benchParallelSink.Add(local)
	})
}

// allocCount reports allocations per call for fn, used by the regression gate.
func allocCount(fn func()) float64 {
	return testing.AllocsPerRun(200, fn)
}

// TestNormalizeHostStrict_AllocRegression is the hard, hardware-independent
// regression gate. ns/op varies by runner; allocations do not. The pre-fix body
// allocated 2/op for every ASCII hostname on a path that runs ~10x per request —
// reintroducing an allocation here (e.g. by normalizing before the fast-path
// test, or by widening the fast path back into idna.ToASCII) fails immediately.
func TestNormalizeHostStrict_AllocRegression(t *testing.T) {
	for _, s := range hostShapes {
		host, ceiling, why := s.host, s.maxAllocs, s.why
		t.Run(s.name, func(t *testing.T) {
			got := allocCount(func() { benchNorm, benchOK = NormalizeHostStrict(host) })
			if got <= ceiling {
				return
			}
			detail := "the already-canonical fast path no longer covers this shape"
			if why != "" {
				detail = "expected at most the inherent cost (" + why + ")"
			}
			t.Errorf("REGRESSION: NormalizeHostStrict(%q) allocates %.0f/op, ceiling %.0f — %s. "+
				"This path runs ~10x per proxied request, so an allocation here is ~10 per request.",
				host, got, ceiling, detail)
		})
	}
}

// TestNormalizeHost_AllocRegression pins the same contract on the fail-open
// wrapper, which is what the blocklist/category/bypass stores actually call.
func TestNormalizeHost_AllocRegression(t *testing.T) {
	if got := allocCount(func() { benchNorm = NormalizeHost("sub.cdn.assets.example.com") }); got != 0 {
		t.Errorf("REGRESSION: NormalizeHost allocates %.0f/op on a plain ASCII host, want 0", got)
	}
}

// TestNormalizeHostStrict_FastPathIsFasterThanToASCII is the coarse, non-flaky
// proof that the fast path actually bypasses idna.ToASCII rather than merely
// duplicating it: it asserts the ALLOCATION difference (deterministic), not a
// timing ratio (which would be flaky on a shared CI runner).
func TestNormalizeHostStrict_FastPathIsFasterThanToASCII(t *testing.T) {
	const host = "sub.cdn.assets.example.com"
	baseline := allocCount(func() { benchNorm, benchOK = referenceNormalizeHostStrict(host) })
	optimized := allocCount(func() { benchNorm, benchOK = NormalizeHostStrict(host) })
	if baseline <= optimized {
		t.Fatalf("expected the pre-fast-path body to allocate MORE than the optimized one; "+
			"baseline=%.0f optimized=%.0f — is idna.ToASCII still on the fast path?", baseline, optimized)
	}
	t.Logf("allocs/op: baseline(idna.ToASCII)=%.0f optimized(fast path)=%.0f", baseline, optimized)
}

// TestNormalizeHostStrict_ConcurrentStress is the concurrency/stress test: the
// fast path introduces no shared state, so concurrent normalization of mixed
// host shapes must stay race-free and return identical results to the
// single-threaded reference.
func TestNormalizeHostStrict_ConcurrentStress(t *testing.T) {
	corpus := fastPathCorpus()
	want := make([]string, len(corpus))
	wantOK := make([]bool, len(corpus))
	for i, h := range corpus {
		want[i], wantOK[i] = referenceNormalizeHostStrict(h)
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
					norm, ok := NormalizeHostStrict(h)
					if norm != want[i] || ok != wantOK[i] {
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
