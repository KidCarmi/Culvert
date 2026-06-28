//go:build benchgate

package main

// Deterministic benchmark-regression gate (CI quality program — PR-3).
//
// Pairs with the benchstat artifact the weekly workflow produces. benchstat
// reports ns/op deltas vs the PR-2 baseline (informational — ns/op is
// hardware-sensitive and not a reliable cross-runner gate). THIS test is the
// hard gate, keyed on ALLOCATIONS PER OP, which are deterministic and
// hardware-independent: a change that adds an allocation to the per-request
// policy hot path fails here regardless of runner speed.
//
// Baseline (PR-2, testdata/bench/policy-baseline.txt): policy Evaluate allocates
// ~2 allocs/rule on the no-match full scan, and scrubForwardedHeaders ~13
// allocs/op. The bounds below add modest headroom; a per-rule allocation
// regression (→ ~3 allocs/rule) blows past them.
//
//   go test -tags benchgate -run 'TestBenchGate_' -v .

import (
	"net/http"
	"testing"
)

// TestBenchGate_PolicyEvalAllocs fails if policy evaluation's per-op allocation
// count regresses beyond a small headroom over the PR-2 baseline.
func TestBenchGate_PolicyEvalAllocs(t *testing.T) {
	cases := []struct {
		rules     int
		maxAllocs int64 // 2*rules baseline + headroom
	}{
		{10, 24},       // baseline 20
		{100, 220},     // baseline 200
		{1000, 2200},   // baseline 2000
		{10000, 22000}, // baseline 20000
	}
	for _, tc := range cases {
		ps := buildPolicyStore(tc.rules)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Evaluate rules=%d: %d allocs/op (bound %d), %d ns/op", tc.rules, allocs, tc.maxAllocs, res.NsPerOp())
		if allocs > tc.maxAllocs {
			t.Errorf("REGRESSION: Evaluate rules=%d allocates %d/op, exceeds bound %d (baseline ~%d). "+
				"Per-request allocation growth on the policy hot path — see docs/ci/proxy-quality-architecture.md.",
				tc.rules, allocs, tc.maxAllocs, tc.rules*2)
		}
	}
}

// TestBenchGate_ScrubAllocs guards the per-request header-scrub hot path.
func TestBenchGate_ScrubAllocs(t *testing.T) {
	const maxAllocs = 16 // baseline 13
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			r, _ := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
			r.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.9, 192.168.1.1")
			r.Header.Set("X-Real-IP", "10.1.2.3")
			r.Header.Set("X-User-Identity", "spoofed@evil.example")
			scrubForwardedHeaders(r)
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("scrubForwardedHeaders: %d allocs/op (bound %d)", allocs, maxAllocs)
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: scrubForwardedHeaders allocates %d/op, exceeds bound %d (baseline ~13)", allocs, maxAllocs)
	}
}
