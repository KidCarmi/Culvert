package main

// Policy-engine performance benchmarks (CI quality program — PR-2).
//
// These are the first benchmarks in the repository. They answer a concrete
// production question from docs/ci/proxy-quality-architecture.md: "does latency
// stay stable as the policy set grows to 1000 / 10000 rules?" The proxy hot
// path calls policyStore.Evaluate on EVERY request, so its scaling with rule
// count is a first-order latency factor.
//
// Benchmarks only run under `go test -bench`, never during the normal
// `go test ./...` that qa-gate.yml runs — so they add zero cost to the required
// gates. The nightly workflow runs them with -benchmem and emits the output as
// a benchstat-ready artifact and a baseline for the PR-3 regression gate.
//
// Run locally:
//   go test -run '^$' -bench 'BenchmarkPolicy|BenchmarkScrub' -benchmem .

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

// buildPolicyStore returns a store with n non-matching access rules. With a
// query host that matches none of them, Evaluate performs a full O(n) scan and
// returns nil (default deny) — the worst case, and the honest measure of how
// rule count taxes the hot path.
func buildPolicyStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	// ReplaceAll sorts ONCE; an Add-per-rule loop would sort on every insert
	// (O(n^2 log n) — pathological at n=10000, multi-minute build).
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_NoMatch measures the full-scan / default-deny path at
// increasing rule counts. A flat ns/op-per-rule across sizes means the engine
// scales linearly with no pathological per-rule blowup.
func BenchmarkPolicyEvaluate_NoMatch(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil); m != nil {
					b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
				}
			}
		})
	}
}

// BenchmarkPolicyEvaluate_MatchLast measures the cost when the matching rule is
// the lowest-priority (last-evaluated) one — i.e. the scan must traverse every
// preceding rule before the allow. This is the worst case for a request that is
// ultimately allowed, and exercises first-match-wins ordering at scale.
func BenchmarkPolicyEvaluate_MatchLast(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(n)
		// Lowest priority number is evaluated first; give the catch-all the
		// highest number so it is evaluated last.
		ps.Add(PolicyRule{Priority: n + 1, Name: "catch-all", DestFQDN: "*", Action: ActionAllow})
		b.Run(fmt.Sprintf("rules=%d", n+1), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				m := ps.Evaluate("203.0.113.7", "", "unauth", "target.example.com", nil)
				if m == nil || m.Rule.Name != "catch-all" {
					b.Fatalf("expected catch-all match, got %v", m)
				}
			}
		})
	}
}

// BenchmarkScrubForwardedHeaders measures the per-request header-scrub hot path
// (X-Forwarded-For / X-Real-IP private-IP stripping + X-User-Identity removal),
// run for every forwarded HTTP request.
func BenchmarkScrubForwardedHeaders(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://target.example.com/", http.NoBody)
		r.Header.Set("X-Forwarded-For", "10.0.0.1, 203.0.113.9, 192.168.1.1")
		r.Header.Set("X-Real-IP", "10.1.2.3")
		r.Header.Set("X-User-Identity", "spoofed@evil.example")
		scrubForwardedHeaders(r)
	}
}

// buildPolicyStoreSourceCIDR returns a store with n access rules scoped to a
// source CIDR the benchmark client IP is INSIDE (so the CIDR check fully
// executes on every rule) and a destination FQDN that never matches (so the
// scan continues through all n rules — the worst case).
func buildPolicyStoreSourceCIDR(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority: i + 1,
			Name:     fmt.Sprintf("cidr-rule-%d", i),
			SourceIP: "10.0.0.0/8",
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_NoMatch_SourceCIDR measures the full-scan cost when
// every rule carries a source-CIDR condition — the common enterprise shape
// (rules scoped to office/VPN/VLAN subnets).
func BenchmarkPolicyEvaluate_NoMatch_SourceCIDR(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStoreSourceCIDR(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("10.1.2.3", "", "unauth", "target.example.com", nil); m != nil {
					b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
				}
			}
		})
	}
}
