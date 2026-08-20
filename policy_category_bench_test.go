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

// buildCategoryGroupPolicyStore returns n rules scoped by category GROUP. Each
// one resolves the host→category fusion (lookupHostCategory) before the O(1)
// group-membership check, so the fusion runs once per rule per request.
func buildCategoryGroupPolicyStore(n int) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority:          i + 1,
			Name:              fmt.Sprintf("catgroup-rule-%d", i),
			DestCategoryGroup: fmt.Sprintf("group-%d", i),
			Action:            ActionAllow,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

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

func BenchmarkPolicyEvaluate_CategoryGroupRules(b *testing.B) {
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
