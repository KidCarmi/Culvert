package main

import (
	"net"
	"net/http"
	"strings"
	"testing"
)

// Benchmarks for the per-request forwarded-header scrub (scrubForwardedHeaders).
//
// The scrub runs on EVERY plain-HTTP request, EVERY WebSocket upgrade, and —
// the highest-volume site — EVERY decrypted inner exchange of an SSL-inspected
// tunnel (runInspectExchange). An allocation here is an allocation on essentially
// every proxied request, not per connection.
//
// Each shape is measured against legacyScrubForwardedHeaders (the verbatim
// pre-change implementation, defined in proxy_scrub_test.go) so the before/after
// comparison is reproducible from the tree instead of quoted from a commit
// message. Run:
//
//	go test -run '^$' -bench 'ScrubHeaderShapes|SanitizeForwardedFor' -benchmem .

// scrubShapes are the X-Forwarded-For / X-Real-IP pairs that matter in
// production: no forwarded headers at all (direct client), an all-public proxy
// chain (front-door load balancer), a mixed chain (internal LB in front of a
// public edge), and a deep CDN chain.
var scrubShapes = []struct {
	name string
	xff  string
	xri  string
}{
	{"NoForwardedHeaders", "", ""},
	{"SingleHop", "203.0.113.9", "203.0.113.9"},
	{"AllPublicChain", "203.0.113.9, 198.51.100.4, 192.0.2.33", "203.0.113.9"},
	{"MixedChain", "10.0.0.1, 203.0.113.9, 192.168.1.1", "10.1.2.3"},
	{"AllPrivateChain", "10.0.0.1, 192.168.1.1, 172.16.0.1", "10.1.2.3"},
	{"NonCanonicalSpacing", "203.0.113.9,198.51.100.4,192.0.2.33", "203.0.113.9"},
	{"LongChain", "203.0.113.1, 203.0.113.2, 203.0.113.3, 203.0.113.4, 203.0.113.5, " +
		"203.0.113.6, 203.0.113.7, 203.0.113.8", "203.0.113.1"},
	{"IPv6Chain", "2001:db8::1, fe80::1, 2001:db8::2", "2001:db8::1"},
}

// benchScrubShape times one scrub implementation over one header shape. The
// header set is restored per iteration (the scrub mutates it), which costs the
// same fixed Header.Set overhead for both implementations — so the DELTA between
// the New/Legacy pair is the honest signal, and BenchmarkSanitizeForwardedFor_*
// below isolates the scrub's own cost with no fixture at all.
func benchScrubShape(b *testing.B, scrub func(*http.Request), xff, xri string) {
	b.ReportAllocs()
	r, err := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if xff != "" {
			r.Header["X-Forwarded-For"] = []string{xff}
		}
		if xri != "" {
			r.Header["X-Real-IP"] = []string{xri}
		}
		r.Header["X-User-Identity"] = []string{"spoofed@evil.example"}
		scrub(r)
	}
}

func BenchmarkScrubHeaderShapes(b *testing.B) {
	for _, s := range scrubShapes {
		b.Run(s.name+"/New", func(b *testing.B) {
			benchScrubShape(b, scrubForwardedHeaders, s.xff, s.xri)
		})
		b.Run(s.name+"/Legacy", func(b *testing.B) {
			benchScrubShape(b, legacyScrubForwardedHeaders, s.xff, s.xri)
		})
	}
}

// BenchmarkScrubHeaderShapesParallel is the concurrency shape: the scrub is
// per-request, so contention and GC pressure under load matter as much as serial
// cost. Each goroutine owns its own request, mirroring real traffic.
func BenchmarkScrubHeaderShapesParallel(b *testing.B) {
	run := func(b *testing.B, scrub func(*http.Request)) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			r, err := http.NewRequest(http.MethodGet, "http://target.example.com/", nil)
			if err != nil {
				b.Fatal(err)
			}
			for pb.Next() {
				r.Header["X-Forwarded-For"] = []string{"203.0.113.9, 198.51.100.4, 192.0.2.33"}
				r.Header["X-Real-IP"] = []string{"203.0.113.9"}
				r.Header["X-User-Identity"] = []string{"spoofed@evil.example"}
				scrub(r)
			}
		})
	}
	b.Run("New", func(b *testing.B) { run(b, scrubForwardedHeaders) })
	b.Run("Legacy", func(b *testing.B) { run(b, legacyScrubForwardedHeaders) })
}

// ─── The filter in isolation ─────────────────────────────────────────────────

// legacySanitizeForwardedFor is the pre-change X-Forwarded-For filter lifted out
// of the header plumbing verbatim (same strings.Split / net.ParseIP / ip.String /
// strings.Join calls), so the two filters can be compared with zero fixture
// overhead inside the timed region.
func legacySanitizeForwardedFor(in string) string {
	var public []string
	for _, raw := range strings.Split(in, ",") {
		ip := net.ParseIP(strings.TrimSpace(raw))
		if ip != nil && !isPrivateIP(ip) {
			public = append(public, ip.String())
		}
	}
	return strings.Join(public, ", ")
}

func BenchmarkSanitizeForwardedFor(b *testing.B) {
	for _, s := range scrubShapes {
		if s.xff == "" {
			continue
		}
		b.Run(s.name+"/New", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, _ = sanitizeForwardedFor(s.xff)
			}
		})
		b.Run(s.name+"/Legacy", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = legacySanitizeForwardedFor(s.xff)
			}
		})
	}
}

// ─── Classification and parsing primitives ───────────────────────────────────

// BenchmarkIsPrivateIP_PublicV4 is the worst case for the linear guard table: a
// public address matches nothing, so every range is tested. This is the inner
// loop of the scrub, run once per hop.
func BenchmarkIsPrivateIP_PublicV4(b *testing.B) {
	b.ReportAllocs()
	ip := net.ParseIP("203.0.113.9")
	for i := 0; i < b.N; i++ {
		if isPrivateIP(ip) {
			b.Fatal("public address classified private")
		}
	}
}

func BenchmarkIsPrivateIP_PrivateV4(b *testing.B) {
	b.ReportAllocs()
	ip := net.ParseIP("10.0.0.1")
	for i := 0; i < b.N; i++ {
		if !isPrivateIP(ip) {
			b.Fatal("private address classified public")
		}
	}
}

// BenchmarkParseHop contrasts the two parsers on the exact inputs the scrub
// feeds them: net.ParseIP heap-allocates a 16-byte net.IP per call, while
// netip.ParseAddr returns a value.
func BenchmarkParseHop(b *testing.B) {
	b.Run("New", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok := parsePublicAddr("203.0.113.9"); !ok {
				b.Fatal("parse failed")
			}
		}
	})
	b.Run("Legacy", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if net.ParseIP("203.0.113.9") == nil {
				b.Fatal("parse failed")
			}
		}
	})
}
