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
	// rules=1 is the boundary the normalization hoist is weakest at — with one
	// category rule the per-rule saving is a single probe, so it is where the
	// scratch's own bookkeeping is most visible. It is measured rather than
	// argued about.
	for _, n := range []int{1, 10, 50, 200} {
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

// BenchmarkPolicyEvaluate_CategoryRulesParallel is the production-shaped
// instrument for the destination-host normalization hoist, and the one to read
// instead of a tight single-probe loop.
//
// The micro-benchmark urlcat.BenchmarkStoreMatchesHostNorm_Parallel measures
// nothing but the membership probe, so at 4 cores every core does nothing but
// acquire catStore's RLock — the maximally contended case no gateway is in,
// where removing CPU work from the op simply moves the bottleneck onto the lock
// and the saving is masked (measured: hoisted 167.8 ns vs the normalizing
// wrapper 162.4 ns at -cpu 4, i.e. equal throughput). That is this repo's
// standing methodology note from the topHosts work — speeding one component
// only raises the arrival rate at the next contended one — so the scan, which
// separates each probe with real per-rule work, is the honest denominator.
// (That catStore RLock measurement predates the urlcat forward read view; the
// probe now takes no lock, see below.)
//
// It is also the end-to-end instrument for the urlcat forward read view
// (internal/urlcat forwardView). It is deliberately the DestCategory path and
// not the category-GROUP one. matchesCategory reaches catStore.MatchesHostNorm /
// MatchesHostAdminNorm once per category-scoped rule and nothing else
// contended, so this benchmark isolates that cost.
// BenchmarkPolicyEvaluate_CategoryGroupRulesParallel below also reaches
// catgroup.Store.GetByName. That used to take a per-rule RLock which dominated
// the measurement — a profile of that benchmark on a tree carrying the view put
// 91.9% of samples in GetByName with 68.6% in its RLock atomic — so it measured
// that ceiling rather than this one. The catgroup finding it exposed is fixed
// (catgroup readView: both group matchers now read a lock-free published view),
// and that benchmark is the end-to-end instrument for it.
//
//	go test -run '^$' -bench 'CategoryRulesParallel' -benchmem -cpu 1,2,4 .
func BenchmarkPolicyEvaluate_CategoryRulesParallel(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	ps := buildCategoryPolicyStore(50)
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

// BenchmarkPolicyEvaluate_CategoryGroupRulesParallel measures the same scan
// under concurrency. A per-rule lookup multiplies whatever it touches by the
// rule count on every core serving traffic, which is why this benchmark is the
// end-to-end instrument for the catgroup read view. Measured here, 50
// category-group rules, uncategorized destination, medians of n=5 on a 4-core
// Xeon @2.80GHz, go1.26.9:
//
//	GOMAXPROCS │    1    │    2    │    4    │ 1→4 throughput
//	RLock      │ 1926 ns │ 3699 ns │ 3996 ns │ 0.48x  (cores SUBTRACTED it)
//	read view  │ 1748 ns │  980 ns │  537 ns │ 3.25x
//
// so 7.4x the throughput at four cores, and a curve that improves with core
// count instead of degrading — the property that matters on the 16- and
// 32-core hardware this appliance ships onto. Those figures are one machine on
// one revision; re-measure rather than quoting them as a current result.
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
