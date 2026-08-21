//go:build benchgate

package main

// Allocation-regression gate for the DPI content-scan hot path.
//
//	go test -tags benchgate -run 'TestBenchGate_DPIScan' -v .

import (
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/scanner"
)

// TestBenchGate_DPIScanAllocsConstantInPatternCount locks in the CONSTANT-overhead
// contract on scanner.ContentScanner.Scan, which runs on every SSL-inspected
// response body (proxy_tunnel.go safeDPIScan).
//
// Scan bounds each regex match with a ReDoS timeout, and enforcing that needs a
// goroutine — re.Match is not interruptible. That harness used to be per PATTERN:
// one goroutine + channel + timer each, measured at 6 allocs/448 B per pattern, so
// a 20-pattern policy charged 120 allocs/9.0 KB to every inspected body and a
// 50-pattern policy charged 300 allocs/22.4 KB. It is now hoisted to ONE worker
// for the whole pattern list (per-pattern budget preserved via the progress stamp
// in patternSet.scan), making the overhead a small constant: measured 7 allocs/op
// at 1, 10, 20 and 50 patterns.
//
// The bound is therefore a CONSTANT, deliberately not a function of pattern count
// — that is the whole point. Any reintroduction of per-pattern harness cost blows
// through it immediately (10 patterns would land at ~60).
func TestBenchGate_DPIScanAllocsConstantInPatternCount(t *testing.T) {
	// Measured 7 allocs/op, flat across pattern counts. Bound 12 leaves headroom
	// for escape-analysis differences across Go releases while staying far below
	// the O(patterns) failure mode.
	const maxAllocs int64 = 12

	// Cheap literal patterns over a tiny body: the measurement is then almost
	// entirely the timeout harness, which is what this gate is about. None match,
	// so every scan walks the full list (the worst case, and the common one).
	body := []byte("clean")
	for _, patterns := range []int{1, 10, 20, 50} {
		sc := scanner.New(1 << 20)
		pats := make([]string, 0, patterns)
		for i := 0; i < patterns; i++ {
			pats = append(pats, fmt.Sprintf("zzz-no-match-%d", i))
		}
		if err := sc.Set(pats); err != nil {
			t.Fatalf("Set(%d patterns): %v", patterns, err)
		}
		if _, hit := sc.Scan(body); hit {
			t.Fatalf("patterns=%d: clean body matched — the benchmark is not measuring the miss path", patterns)
		}

		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = sc.Scan(body)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Scan patterns=%d: %d allocs/op (bound %d), %d B/op, %d ns/op",
			patterns, allocs, maxAllocs, res.AllocedBytesPerOp(), res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: Scan with %d patterns allocates %d/op, exceeds constant bound %d — "+
				"the ReDoS timeout harness (goroutine + channel + timer) is being paid PER PATTERN again "+
				"instead of once per scan, on every SSL-inspected response body. "+
				"See internal/scanner/scanner.go patternSet.scan.", patterns, allocs, maxAllocs)
		}
	}
}
