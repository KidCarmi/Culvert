//go:build benchgate

package main

// Allocation-regression gate for the SSL_INNER inner-request trace line
// (proxy_sslinner_line.go).
//
// Correctness contracts for that line live in proxy_sslinner_line_test.go and
// run in the normal suite; this file holds the PERFORMANCE contract only, in
// the repository's benchgate convention:
//
//	go test -tags benchgate -run 'TestBenchGate_' -v .
//
// Keyed on allocations per op, which are deterministic and hardware
// independent, rather than ns/op, which is not. The one wall-clock assertion
// here is a RATIO between two forms measured in the same run (see
// TestBenchGate_SSLInnerLineLongPathIsNotSlower), which is what makes it safe in
// a tagged file: a slow or differently-tuned runner cannot make the comparison
// lie, because it slows both arms.

import (
	"testing"
)

// TestBenchGate_SSLInnerLineAllocs locks in the object count for the shipped
// emitter, at both ends of the request-path range.
//
// Measured (go1.27.3, linux/amd64): 1 alloc/op at every path length from 8
// bytes through the 2 KiB retention bound, against 6 alloc/op for the
// pre-change logger.Printf form. The bounds sit above the measured value so
// stdlib churn across Go releases, or a pool miss on a cold P, does not flip
// the gate, and below the legacy 6 so reintroducing per-operand boxing fails
// here. The bound is looser at the retention bound because a line that outgrows
// its pooled carrier pays growth allocations until the pool warms.
//
// The gate deliberately asserts the RELATIONSHIP as well as the absolute bound:
// both shapes are measured in the same run on the same machine.
func TestBenchGate_SSLInnerLineAllocs(t *testing.T) {
	cases := []struct {
		name      string
		pathLen   int
		maxAllocs int64
	}{
		{"TypicalPath", 40, 2},
		{"LongAssetPath", 500, 2},
		{"AtRetentionBound", 2048, 4},
	}
	match := ruleWithProfile("executables")
	for _, c := range cases {
		path := sslInnerBenchPath(c.pathLen)
		after := testing.Benchmark(func(b *testing.B) {
			benchSSLInnerLogger(b)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				logSSLInnerRequest(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
			}
		})
		before := testing.Benchmark(func(b *testing.B) {
			benchSSLInnerLogger(b)
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sslInnerLineLegacyEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
			}
		})
		afterAllocs, beforeAllocs := after.AllocsPerOp(), before.AllocsPerOp()
		t.Logf("%s: after %d allocs/op, %d B/op (bound %d) | before %d allocs/op, %d B/op",
			c.name, afterAllocs, after.AllocedBytesPerOp(), c.maxAllocs,
			beforeAllocs, before.AllocedBytesPerOp())

		if afterAllocs > c.maxAllocs {
			t.Errorf("%s: SSL_INNER line allocates %d/op, bound %d — per-operand boxing (or a line-sized string) is back on the inspected-request path",
				c.name, afterAllocs, c.maxAllocs)
		}
		if afterAllocs >= beforeAllocs {
			t.Errorf("%s: the emitter (%d allocs/op) is no cheaper than the pre-change format string (%d allocs/op); the optimization has been undone",
				c.name, afterAllocs, beforeAllocs)
		}
	}
}

// TestBenchGate_SSLInnerLineLongPathIsNotSlower is the gate this change exists
// to leave behind, and it guards the mistake that was nearly shipped.
//
// The obvious implementation — render with appends, hand logger.Output a
// string — is FASTER on a short path and 2.3x SLOWER at a 500-byte one, because
// log.Logger.Printf appends into its own reused buffer and never materializes
// the line while `string(b)` allocates and copies all of it. A future refactor
// that reintroduces a line-sized allocation would still pass an
// allocations-only gate (it is 1-2 objects) and would still regress ordinary
// CDN-asset traffic.
//
// So the long-path arm is gated on WALL CLOCK, as a ratio against the
// pre-change form measured in the same run. The threshold is deliberately loose
// (the shipped form must merely not be materially slower, 1.25x); it is a
// REGRESSION gate, not a target. The rejected form is measured alongside purely
// so a failure report shows what the failing shape looks like.
func TestBenchGate_SSLInnerLineLongPathIsNotSlower(t *testing.T) {
	const maxRatio = 1.25
	match := ruleWithProfile("executables")

	for _, pathLen := range []int{200, 500, 2048} {
		path := sslInnerBenchPath(pathLen)
		run := func(emit func()) testing.BenchmarkResult {
			return testing.Benchmark(func(b *testing.B) {
				benchSSLInnerLogger(b)
				for i := 0; i < b.N; i++ {
					emit()
				}
			})
		}
		after := run(func() {
			logSSLInnerRequest(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
		})
		before := run(func() {
			sslInnerLineLegacyEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
		})
		rejected := run(func() {
			sslInnerLineRejectedEmit(benchSSLInnerIP, benchSSLInnerMethod, benchSSLInnerHost, path, match)
		})

		afterNs, beforeNs := after.NsPerOp(), before.NsPerOp()
		if beforeNs <= 0 {
			t.Skipf("path %d: unusable baseline measurement (%d ns/op)", pathLen, beforeNs)
		}
		ratio := float64(afterNs) / float64(beforeNs)
		t.Logf("path %d: after %d ns/op, before %d ns/op, rejected-string-form %d ns/op — ratio %.2f (max %.2f)",
			pathLen, afterNs, beforeNs, rejected.NsPerOp(), ratio, maxRatio)

		if ratio > maxRatio {
			t.Errorf("path %d: the emitter is %.2fx the pre-change form (%d vs %d ns/op), max %.2f — a line-sized allocation is back; see the rejected form at %d ns/op",
				pathLen, ratio, afterNs, beforeNs, maxRatio, rejected.NsPerOp())
		}
	}
}
