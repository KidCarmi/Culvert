package scanner

import (
	"fmt"
	"testing"
)

// Benchmarks for the DPI scan hot path (SSL-inspect response bodies).
//
// The contract these pin: Scan's FIXED overhead — the goroutine + channel +
// timer that enforce the ReDoS budget — is CONSTANT in the pattern count, not
// O(patterns). It used to be one goroutine/channel/timer per pattern, which
// charged 6 allocs per pattern per body to every inspected response.
//
// Deliberately driven through the exported Scan API only, so the same file
// benchmarks the pre- and post-hoist implementations for a before/after
// comparison:
//
//	go test -run XXX -bench 'BenchmarkScan' -benchmem ./internal/scanner/

// benchPatterns is a realistic operator DPI set: a mix of literal-prefixed
// patterns (secret formats — Go's regexp takes a memchr fast path, a few hundred
// ns) and prefix-free ones (\b classes and (?i) literals — a full walk, ~100 us
// on 8 KiB). The mix matters: with cheap patterns the timeout harness cost more
// than the match it guarded, which is what made the per-pattern overhead visible.
var benchPatterns = []string{
	`-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`,
	`AKIA[0-9A-Z]{16}`,
	`\b\d{3}-\d{2}-\d{4}\b`,
	`ghp_[0-9A-Za-z]{36}`,
	`xoxb-[0-9]{10,}`,
	`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
	`\b4[0-9]{12}(?:[0-9]{3})?\b`,
	`(?i)confidential`,
	`(?i)internal use only`,
	`(?i)do not distribute`,
}

// benchBody builds an n-byte text/html-ish body that matches no pattern (the
// overwhelmingly common case — a hit blocks the request and is terminal).
func benchBody(n int) []byte {
	chunk := []byte("GET /index.html HTTP/1.1 Host: www.example.com Accept: text/html,application/xhtml+xml ")
	b := make([]byte, 0, n+len(chunk))
	for len(b) < n {
		b = append(b, chunk...)
	}
	return b[:n]
}

// benchScanner returns a scanner loaded with n patterns cycled from benchPatterns.
func benchScanner(tb testing.TB, n int) *ContentScanner {
	tb.Helper()
	pats := make([]string, 0, n)
	for i := 0; i < n; i++ {
		pats = append(pats, benchPatterns[i%len(benchPatterns)])
	}
	s := New(1 << 20)
	if err := s.Set(pats); err != nil {
		tb.Fatalf("Set: %v", err)
	}
	return s
}

// BenchmarkScan is the primary latency + allocation benchmark. Sweeping the
// pattern count is the point: the per-pattern harness made allocs/op scale with
// it, so a regression shows up as allocs/op climbing with `patterns=`.
func BenchmarkScan(b *testing.B) {
	for _, patterns := range []int{1, 10, 20} {
		for _, size := range []int{512, 4096, 32768} {
			s := benchScanner(b, patterns)
			body := benchBody(size)
			b.Run(fmt.Sprintf("patterns=%d/size=%d", patterns, size), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(body)))
				for i := 0; i < b.N; i++ {
					if pat, hit := s.Scan(body); hit {
						b.Fatalf("unexpected DPI hit on clean body: %q", pat)
					}
				}
			})
		}
	}
}

// BenchmarkScanAllocs isolates the fixed overhead from the regex work: a single
// trivially-cheap literal pattern over a tiny body, so ns/op and allocs/op are
// almost entirely the timeout harness. This is the sharpest before/after signal.
func BenchmarkScanAllocs(b *testing.B) {
	body := []byte("clean")
	for _, patterns := range []int{1, 10, 20, 50} {
		s := New(1 << 20)
		pats := make([]string, 0, patterns)
		for i := 0; i < patterns; i++ {
			pats = append(pats, fmt.Sprintf("zzz-no-match-%d", i))
		}
		if err := s.Set(pats); err != nil {
			b.Fatalf("Set: %v", err)
		}
		b.Run(fmt.Sprintf("patterns=%d", patterns), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, hit := s.Scan(body); hit {
					b.Fatal("unexpected hit")
				}
			}
		})
	}
}

// BenchmarkScanParallel is the concurrency benchmark. The inspect path scans
// many response bodies at once, so the per-pattern design's goroutine spawn rate
// (patterns x concurrent responses) showed up as scheduler pressure on top of
// the allocation cost.
func BenchmarkScanParallel(b *testing.B) {
	for _, patterns := range []int{10, 20} {
		s := benchScanner(b, patterns)
		body := benchBody(512)
		b.Run(fmt.Sprintf("patterns=%d", patterns), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if _, hit := s.Scan(body); hit {
						b.Fatal("unexpected hit")
					}
				}
			})
		})
	}
}

// BenchmarkScanHit covers the terminal path (a match blocks the request), so the
// hit case is measured too and not just optimized-for-miss.
func BenchmarkScanHit(b *testing.B) {
	s := benchScanner(b, 20)
	body := append(benchBody(4096), []byte("AKIAIOSFODNN7EXAMPLE")...)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		if _, hit := s.Scan(body); !hit {
			b.Fatal("expected a DPI hit")
		}
	}
}
