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

// TestBenchGate_PolicyEvalAllocs locks in the O(1)-allocation policy hot path.
// Before the host-normalize-once + precomputed-normFQDN optimization, Evaluate
// allocated ~2/rule (2000 allocs/op at 1000 rules); it is now a small CONSTANT
// regardless of rule count. The bound is therefore a constant, not a function of
// rule count — any reintroduction of per-rule allocation fails this gate.
func TestBenchGate_PolicyEvalAllocs(t *testing.T) {
	// Post-optimization: 1 alloc/op (the single per-request host normalization),
	// independent of rule count. Headroom of a few absorbs runtime noise while
	// still catching an O(rules) regression immediately.
	const maxAllocs int64 = 4
	for _, rules := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(rules)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Evaluate rules=%d: %d allocs/op (bound %d), %d ns/op", rules, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: Evaluate rules=%d allocates %d/op, exceeds constant bound %d — "+
				"per-rule allocation has returned to the policy hot path (host/pattern re-normalization?). "+
				"See docs/ci/proxy-quality-architecture.md §8a.", rules, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_PolicyEvalSourceCIDRAllocs locks in the O(1)-allocation
// source-CIDR policy path. Before the precomputed-srcIPNet optimization every
// CIDR-scoped rule re-ran net.ParseCIDR + net.ParseIP per request (~4
// allocs/rule — 40k allocs/op and ~720 KB/op at 10000 rules); it is now a
// small CONSTANT (host normalization + one lazy client-IP parse) regardless of
// rule count. Any reintroduction of per-rule CIDR parsing fails this gate.
func TestBenchGate_PolicyEvalSourceCIDRAllocs(t *testing.T) {
	// Post-optimization: 3 allocs/op independent of rule count. Headroom of a
	// few absorbs runtime noise while still catching an O(rules) regression
	// immediately.
	const maxAllocs int64 = 8
	for _, rules := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStoreSourceCIDR(rules)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("10.1.2.3", "", "unauth", "target.example.com", nil)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Evaluate(sourceCIDR) rules=%d: %d allocs/op (bound %d), %d ns/op", rules, allocs, maxAllocs, res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: Evaluate(sourceCIDR) rules=%d allocates %d/op, exceeds constant bound %d — "+
				"per-rule CIDR parsing has returned to the policy hot path (net.ParseCIDR/net.ParseIP per rule?). "+
				"See docs/ci/proxy-quality-architecture.md §8a.", rules, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_UpstreamInspectTLSConfigAllocs locks in the shared-root-pool
// contract on the SSL-inspect upstream leg. Before the optimization every
// inspected CONNECT tunnel called x509.SystemCertPool(), which clones the
// cached system pool per call — 162 allocs/op and ~26.7 KB/op measured with a
// standard Linux ca-certificates bundle. With upstreamVerifyRoots the steady
// state is the single tls.Config allocation; any reintroduction of a per-tunnel
// pool clone blows through the constant bound immediately.
func TestBenchGate_UpstreamInspectTLSConfigAllocs(t *testing.T) {
	const maxAllocs int64 = 4 // steady state 1 (the tls.Config); pre-fix 162
	// Warm the once-loaded pool so the measurement is steady state, not the
	// first-call pool load.
	if cfg := upstreamInspectTLSConfig("warm.example.com", false); cfg.RootCAs == nil {
		t.Fatal("nil RootCAs on the verifying path")
	}
	res := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			cfg := upstreamInspectTLSConfig("origin.example.com", false)
			if cfg.RootCAs == nil {
				b.Fatal("nil RootCAs on the verifying path")
			}
		}
	})
	allocs := res.AllocsPerOp()
	t.Logf("upstreamInspectTLSConfig: %d allocs/op (bound %d), %d ns/op", allocs, maxAllocs, res.NsPerOp())
	if allocs > maxAllocs {
		t.Errorf("REGRESSION: upstreamInspectTLSConfig allocates %d/op, exceeds bound %d — "+
			"a per-tunnel system-cert-pool clone (x509.SystemCertPool per call) has returned to the SSL-inspect hot path", allocs, maxAllocs)
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
