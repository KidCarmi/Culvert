package main

import (
	"strings"
	"testing"
)

// Before/after comparison for sanitizeLog (proxy.go).
//
// The pre-change four-scan shape is kept in-tree as legacySanitizeLog
// (proxy_sanitizelog_test.go, where it also serves as the differential oracle)
// so the comparison stays REPRODUCIBLE: both forms are measured in the same
// run, on the same hardware, under the same allocator state. A number quoted
// from a commit message ages; a benchmark that still runs does not.
//
//	go test -run '^$' -bench 'BenchmarkSanitizeLog' -benchmem .
//
// Shapes are the ones the request path actually passes: a rule name, a
// hostname, a matched-conditions summary, an identity, a long URL, the empty
// string (very common — unauthenticated identity, unset conditions), and a
// control-carrying string (the attack/edge case).

var sanitizeLogBenchShapes = []struct {
	name string
	in   string
}{
	{"RuleName15B", "allow-corp-saas"},
	{"Hostname15B", "www.example.com"},
	{"Identity17B", "user@corp.example"},
	{"Conditions57B", "destFQDN=*.example.com destCat=Business destCountry=US,CA"},
	{"LongURL270B", "https://cdn.example.com/" + strings.Repeat("segment/", 30) + "asset.js"},
	{"Empty", ""},
	{"WithControls28B", "bad\nrule\rname\twith\x01controls"},
}

var sanitizeLogSink string

func BenchmarkSanitizeLog(b *testing.B) {
	for _, sh := range sanitizeLogBenchShapes {
		b.Run(sh.name+"/after", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sanitizeLogSink = sanitizeLog(sh.in)
			}
		})
		b.Run(sh.name+"/before", func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				sanitizeLogSink = legacySanitizeLog(sh.in)
			}
		})
	}
}

// BenchmarkSanitizeLogParallel is the concurrency half. sanitizeLog is reached
// from every request goroutine, so a form that shared state — a package-level
// buffer, a sync.Pool used wrongly — would show up here as a cost that RISES
// with core count even though the serial figure improved. The single-pass form
// touches nothing outside its own frame, so this must scale flat.
func BenchmarkSanitizeLogParallel(b *testing.B) {
	for _, sh := range []struct {
		name string
		in   string
	}{sanitizeLogBenchShapes[0], sanitizeLogBenchShapes[3], sanitizeLogBenchShapes[6]} {
		b.Run(sh.name+"/after", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				var local string
				for pb.Next() {
					local = sanitizeLog(sh.in)
				}
				sanitizeLogSink = local
			})
		})
		b.Run(sh.name+"/before", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				var local string
				for pb.Next() {
					local = legacySanitizeLog(sh.in)
				}
				sanitizeLogSink = local
			})
		})
	}
}

// BenchmarkSanitizeLogPolicyAllowLine measures the sanitiser in situ: the five
// values handleRequest passes through it to build the one POLICY_ALLOW line it
// emits per proxied request. This is the figure that translates to per-request
// CPU, as opposed to the per-call figures above.
func BenchmarkSanitizeLogPolicyAllowLine(b *testing.B) {
	const (
		ruleName = "allow-corp-saas"
		host     = "www.example.com"
		conds    = "destFQDN=*.example.com destCat=Business destCountry=US,CA"
		identity = "user@corp.example"
	)
	b.Run("after", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sanitizeLogSink = sanitizeLog(ruleName) + sanitizeLog(host) +
				sanitizeLog(conds) + sanitizeLog(identity) + sanitizeLog(ruleName)
		}
	})
	b.Run("before", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			sanitizeLogSink = legacySanitizeLog(ruleName) + legacySanitizeLog(host) +
				legacySanitizeLog(conds) + legacySanitizeLog(identity) + legacySanitizeLog(ruleName)
		}
	})
}
