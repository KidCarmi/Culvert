package sslbypass

// sslbypass_bench_test.go — benchmarks for the per-CONNECT bypass matcher.
// Matches sits on the SSL-decision hot path (main's resolveSSLDecision): it
// runs for every CONNECT whose matched rule says inspect, so its cost scales
// with HTTPS request rate × pattern count.
//
// Measured outcome (4-core, 2026-07): precomputing the glob's normalized form
// at compile time (pattern.norm + MatchFQDNNorm, mirroring the policy
// engine's PolicyRule.normFQDN precompute) cut the no-match full scan from
// ~735 ns + 4 allocs PER PATTERN (20 patterns: 14.9 µs, 82 allocs, 3.9 KB per
// inspected CONNECT) to a flat ~2 allocs per call — the single host
// normalization — independent of pattern count. The empty-list fast path
// additionally makes the unconfigured default (no bypass patterns) free of
// the IDNA pass entirely.
//
// Run locally:
//   go test -run '^$' -bench 'BenchmarkMatches' -benchmem ./internal/sslbypass/
//
// The deterministic allocs/op regression gate lives in main's
// bench_regression_test.go (TestBenchGate_SSLBypassMatchesAllocs), which is
// what CI's benchgate job runs.

import (
	"fmt"
	"testing"
)

// benchMatcher returns a matcher with n glob patterns plus one regex pattern,
// none of which match the benchmark host — the worst case: a full scan.
func benchMatcher(b *testing.B, n int) *Matcher {
	b.Helper()
	pats := make([]string, 0, n+1)
	for i := 0; i < n; i++ {
		pats = append(pats, fmt.Sprintf("*.bypass-%d.example.com", i))
	}
	pats = append(pats, `~^.*\.internal\.example\.org$`)
	m := &Matcher{}
	if err := m.Set(pats); err != nil {
		b.Fatal(err)
	}
	return m
}

// BenchmarkMatches_NoMatch measures the serial full-scan cost — the dominant
// case (most inspected hosts are not on the bypass list).
func BenchmarkMatches_NoMatch(b *testing.B) {
	for _, n := range []int{5, 20, 50} {
		b.Run(fmt.Sprintf("patterns=%d", n), func(b *testing.B) {
			m := benchMatcher(b, n)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m.Matches("www.no-match.example.net") {
					b.Fatal("unexpected match")
				}
			}
		})
	}
}

// BenchmarkMatches_NoMatchParallel measures the full scan under concurrent
// CONNECT goroutines — the production shape (the matcher is a process-global
// consulted under RLock by every inspected tunnel).
func BenchmarkMatches_NoMatchParallel(b *testing.B) {
	m := benchMatcher(b, 20)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if m.Matches("www.no-match.example.net") {
				b.Fatal("unexpected match")
			}
		}
	})
}

// BenchmarkMatches_Empty measures the unconfigured default: no bypass
// patterns. With the empty-list fast path this must not pay the IDNA
// normalization.
func BenchmarkMatches_Empty(b *testing.B) {
	m := &Matcher{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if m.Matches("www.no-match.example.net") {
			b.Fatal("unexpected match")
		}
	}
}
