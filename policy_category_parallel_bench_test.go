package main

import (
	"fmt"
	"testing"
)

// BenchmarkPolicyEvaluate_CategoryRulesParallel is the END-TO-END instrument for
// the per-rule DestCategory read path (urlcat.Store.MatchesHost /
// MatchesHostAdmin, reached once per category-scoped rule per request via
// hostCatScratch.matchesCategory).
//
// It exists because the pre-existing coverage could not see the finding it is
// here to measure. BenchmarkPolicyEvaluate_CategoryRules is SERIAL, and a
// read-lock contention ceiling is invisible at one core by construction;
// BenchmarkPolicyEvaluate_CategoryGroupRulesParallel is parallel but exercises
// DestCategoryGroup rules, which resolve through internal/catgroup and urlcat's
// REVERSE index (LookupHost, memoized once per scan by hostCatScratch) rather
// than through MatchesHost at all. So neither instrument covered this path under
// concurrency.
//
// Read it as throughput against CORE COUNT, not as ns/op at one core:
//
//	go test -run '^$' -bench CategoryRulesParallel -cpu 1,2,4 .
//
// The uncategorized destination is deliberate: clean traffic cannot
// short-circuit, so it is what every ALLOWED request pays.
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
