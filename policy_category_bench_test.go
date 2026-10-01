package main

// Policy-engine category-matching benchmarks.
//
// Evaluate already hoists the per-request-invariant work out of the rule scan
// (normalized host, parsed client IP, one clock read). The DESTINATION CATEGORY
// of the request host is the same class of value — it depends only on the host,
// not on the rule — but it was resolved INSIDE the scan, once per
// category-scoped rule. These benchmarks measure that scan so the hoist is
// justified by evidence rather than inspection.
//
// Run locally:
//   go test -run '^$' -bench 'BenchmarkPolicyEvaluate_Category' -benchmem .

import (
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// seedCategoryTaxonomy installs a taxonomy of roughly production shape into the
// process-wide catStore: a handful of categories, each holding a realistic
// number of host patterns. The benchmark host belongs to NONE of them, which is
// the honest case — an uncategorized destination is what forces every tier of
// the lookup to run to completion.
//
// It returns a restore func; the store is process-global, so a benchmark that
// swapped it must put the original back.
func seedCategoryTaxonomy(tb testing.TB, categories, hostsPerCategory int) {
	tb.Helper()
	prev := catStore
	entries := make([]*urlcat.Entry, 0, categories)
	for c := 0; c < categories; c++ {
		hosts := make([]string, 0, hostsPerCategory)
		for h := 0; h < hostsPerCategory; h++ {
			hosts = append(hosts, fmt.Sprintf("host-%d-%d.example.com", c, h))
		}
		entries = append(entries, &urlcat.Entry{
			Name:  fmt.Sprintf("Category %d", c),
			Hosts: hosts,
		})
	}
	catStore = urlcat.New(entries)
	tb.Cleanup(func() { catStore = prev })
}

// buildCategoryPolicyStore returns n rules that all pass the source check and
// then test the destination CATEGORY — the per-rule call into the two-tier
// lookup.
func buildCategoryPolicyStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority:     i + 1,
			Name:         fmt.Sprintf("cat-rule-%d", i),
			DestCategory: URLCategory(fmt.Sprintf("Category %d", i)),
			Action:       ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// The category-GROUP store builder is shared with policy_bench_test.go
// (buildCategoryGroupPolicyStore) — the two benchmark files landed from
// separate PRs and were reconciled to one declaration.

func BenchmarkPolicyEvaluate_CategoryRules(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	for _, n := range []int{10, 50, 200} {
		ps := buildCategoryPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "uncategorized.example.net", nil); m != nil {
					b.Fatalf("expected no match, got %q", m.Rule.Name)
				}
			}
		})
	}
}

func BenchmarkPolicyEvaluate_CategoryGroupRulesSynthetic(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	for _, n := range []int{10, 50, 200} {
		ps := buildCategoryGroupPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "uncategorized.example.net", nil); m != nil {
					b.Fatalf("expected no match, got %q", m.Rule.Name)
				}
			}
		})
	}
}

// BenchmarkPolicyEvaluate_CategoryRulesParallel is the end-to-end instrument for
// the per-RULE category-membership probe, and it is the one to read for how that
// cost MOVES with core count rather than what it is at one core.
//
// A DestCategory rule reaches hostCatScratch.matchesCategory, which calls
// catStore.MatchesHost (or MatchesHostAdmin) once per rule and deliberately does
// not memoize. Until internal/urlcat's read lock was sharded that was one
// process-wide RWMutex read acquisition per rule per request, so this scan was
// CAPPED: measured on a 4-core Xeon @ 2.10GHz at 50 rules, four cores delivered
// 1.10x the throughput of one (5134 / 4635 / 4664 ns/op at 1/2/4) — adding cores
// bought almost nothing, because each one only added traffic to the single cache
// line all of them had to write. Sharded: 5954 / 3810 / 2153 ns/op, 2.77x from
// one core to four and 2.17x faster in absolute terms at four, with the curve
// still climbing on the wider hardware the appliance ships to.
//
// Those two rows come from different runs, so read the SHAPE and not the
// constants; the machine-independent same-run readings live on
// internal/urlcat/BenchmarkMatchesHostScaling{,_Baseline} and
// internal/hotlock/BenchmarkRLock{Hot,Single}. See internal/urlcat/hotread.go
// for the full finding, the rejected atomic.Pointer view, and the ~11%
// one-core cost that buys it.
//
//	go test -run '^$' -bench 'BenchmarkPolicyEvaluate_CategoryRulesParallel' -benchmem -cpu 1,2,4 .
func BenchmarkPolicyEvaluate_CategoryRulesParallel(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	for _, n := range []int{10, 50} {
		ps := buildCategoryPolicyStore(n)
		b.Run(fmt.Sprintf("rules=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if m := ps.Evaluate("203.0.113.7", "", "unauth", "uncategorized.example.net", nil); m != nil {
						b.Fatalf("expected no match, got %q", m.Rule.Name)
					}
				}
			})
		})
	}
}

// BenchmarkPolicyEvaluate_CategoryGroupRulesParallel measures the same scan
// under concurrency. The fusion takes catStore's RLock once per rule, so a
// per-rule lookup also multiplies lock traffic by the rule count on every
// core serving traffic.
func BenchmarkPolicyEvaluate_CategoryGroupRulesParallel(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	ps := buildCategoryGroupPolicyStore(50)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if m := ps.Evaluate("203.0.113.7", "", "unauth", "uncategorized.example.net", nil); m != nil {
				b.Fatalf("expected no match, got %q", m.Rule.Name)
			}
		}
	})
}
