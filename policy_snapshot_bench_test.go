package main

// Policy-evaluation snapshot benchmarks: how the per-request cost of
// PolicyStore.Evaluate scales with rule count when the matching rule is found
// EARLY, which is how a well-ordered enterprise ruleset behaves.
//
// The existing BenchmarkPolicyEvaluate_NoMatch / _MatchLast cases both traverse
// every rule, so the O(n) work evaluationSnapshot did before the scan was
// invisible against the O(n) scan itself. These cases isolate it: a request
// that matches the HIGHEST-priority rule does O(1) of matching, and anything
// that still scales with the rule set is overhead on it.
//
// Run locally:
//   go test -run '^$' -bench 'BenchmarkPolicyEvaluate_MatchFirst|BenchmarkPolicyEvaluationSnapshot' -benchmem .

import (
	"fmt"
	"testing"
)

// buildPolicyStoreMatchFirst returns a store whose highest-priority rule is a
// catch-all allow, followed by n non-matching rules the scan must never reach.
func buildPolicyStoreMatchFirst(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, 0, n+1)
	rules = append(rules, PolicyRule{Priority: 1, Name: "catch-all", DestFQDN: "*", Action: ActionAllow})
	for i := 0; i < n; i++ {
		rules = append(rules, PolicyRule{
			Priority: i + 2,
			Name:     fmt.Sprintf("rule-%d", i),
			DestFQDN: fmt.Sprintf("no-match-%d.example.invalid", i),
			Action:   ActionAllow,
		})
	}
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_MatchFirst measures the cost when the FIRST rule
// evaluated matches. The scan is O(1) here, so a cost that keeps growing with
// the rule set is per-request overhead around the scan, not the scan.
func BenchmarkPolicyEvaluate_MatchFirst(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStoreMatchFirst(n)
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

// BenchmarkPolicyEvaluationSnapshot isolates the snapshot itself — the step
// both Stage-1 (resolveAuthOutcome) and Stage-2 (Evaluate) take per request
// before any matching happens. On a published revision it must be flat in the
// rule count and allocation-free.
func BenchmarkPolicyEvaluationSnapshot(b *testing.B) {
	for _, n := range []int{10, 100, 1000, 10000} {
		ps := buildPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if got := len(ps.evaluationSnapshot()); got != n {
					b.Fatalf("snapshot length %d, want %d", got, n)
				}
			}
		})
	}
}

// BenchmarkPolicyEvaluationSnapshot_Parallel measures the snapshot under
// concurrency: it takes the store's reader lock, so a walk held proportional to
// the rule count also queued the config plane behind it.
func BenchmarkPolicyEvaluationSnapshot_Parallel(b *testing.B) {
	for _, n := range []int{1000, 10000} {
		ps := buildPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if got := len(ps.evaluationSnapshot()); got != n {
						b.Fatalf("snapshot length %d, want %d", got, n)
					}
				}
			})
		})
	}
}
