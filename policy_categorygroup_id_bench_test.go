package main

// Policy-engine benchmark for the ID-AUTHORITATIVE category-group match.
//
// categoryGroupMatchesHostScratch resolves a rule's group by
// DestCategoryGroupID first (references-by-id S2, rename-safe) and falls back
// to the denormalized name only when the ID resolves to nothing. The ID is
// stamped name->id on every interactive/import write, so the ID path is the
// one production rules take, once per category-group rule per request.
//
// The pre-existing category-group benchmarks could not see that path's cost:
// buildCategoryGroupPolicyStore sets DestCategoryGroup (the NAME) and never
// DestCategoryGroupID, and they evaluate an UNCATEGORIZED host, which returns
// from MatchesCategoryByID before it looks a group up at all. So the shape
// that mattered most — ID-stamped rules against a host that DID resolve to a
// category — was unmeasured, which is how an O(groups) walk behind a comment
// claiming an O(1) lookup survived. These benchmarks cover it, and vary the
// GROUP count independently of the rule count because that was the term the
// cost actually scaled with.
//
// Run:
//
//	go test -run '^$' -bench 'BenchmarkPolicyEvaluate_CategoryGroupByID' -benchmem .

import (
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
)

// seedCategoryGroupsByID installs groups whose IDs the rules below reference.
// Group i holds "Category i+1", so a host resolving to "Category 0" matches
// NONE of them: every rule in the scan performs its group match and declines,
// which is the per-request cost this measures (a scan that exits on rule 1
// would measure one call, not the posture).
func seedCategoryGroupsByID(tb testing.TB, groups int) func(i int) string {
	tb.Helper()
	prev := globalCategoryGroups
	tb.Cleanup(func() { globalCategoryGroups = prev })

	gs := make([]CategoryGroup, groups)
	for i := 0; i < groups; i++ {
		gs[i] = CategoryGroup{
			ID:         fmt.Sprintf("grp-%08d", i),
			Name:       fmt.Sprintf("group-%d", i),
			Categories: []string{fmt.Sprintf("Category %d", i+1)},
		}
	}
	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.ReplaceAll(gs)
	return func(i int) string { return fmt.Sprintf("grp-%08d", i) }
}

// buildCategoryGroupByIDPolicyStore returns n rules carrying the AUTHORITATIVE
// group ID (as a written rule does), spread over the available groups.
func buildCategoryGroupByIDPolicyStore(n, groups int, idFor func(int) string) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		g := i % groups
		rules[i] = PolicyRule{
			Priority:            i + 1,
			Name:                fmt.Sprintf("catgroup-id-rule-%d", i),
			DestCategoryGroup:   fmt.Sprintf("group-%d", g),
			DestCategoryGroupID: idFor(g),
			Action:              ActionBlockPage,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// BenchmarkPolicyEvaluate_CategoryGroupByID_Groups holds the RULE count fixed
// and varies the number of configured GROUPS — the term the ID resolution used
// to scale with, and the one no existing benchmark varied.
func BenchmarkPolicyEvaluate_CategoryGroupByID_Groups(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	const rules = 50
	for _, groups := range []int{1, 8, 32, 128} {
		idFor := seedCategoryGroupsByID(b, groups)
		ps := buildCategoryGroupByIDPolicyStore(rules, groups, idFor)
		b.Run(fmt.Sprintf("groups=%d", groups), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// host-0-0 resolves to "Category 0", which no group holds.
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "host-0-0.example.com", nil); m != nil {
					b.Fatalf("expected no match, got %q", m.Rule.Name)
				}
			}
		})
	}
}

// BenchmarkPolicyEvaluate_CategoryGroupByID_Rules holds the group count at a
// realistic 32 and varies the RULE count, so the per-request total is visible.
func BenchmarkPolicyEvaluate_CategoryGroupByID_Rules(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	const groups = 32
	idFor := seedCategoryGroupsByID(b, groups)
	for _, rules := range []int{10, 50, 200} {
		ps := buildCategoryGroupByIDPolicyStore(rules, groups, idFor)
		b.Run(fmt.Sprintf("rules=%d", rules), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", "host-0-0.example.com", nil); m != nil {
					b.Fatalf("expected no match, got %q", m.Rule.Name)
				}
			}
		})
	}
}

// BenchmarkPolicyEvaluate_CategoryGroupByID_Parallel is the concurrency shape:
// every core serving traffic takes the group store's read lock once per
// category-group rule.
func BenchmarkPolicyEvaluate_CategoryGroupByID_Parallel(b *testing.B) {
	seedCategoryTaxonomy(b, 12, 40)
	const groups = 32
	idFor := seedCategoryGroupsByID(b, groups)
	ps := buildCategoryGroupByIDPolicyStore(50, groups, idFor)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if m := ps.Evaluate("203.0.113.7", "", "unauth", "host-0-0.example.com", nil); m != nil {
				b.Fatalf("expected no match, got %q", m.Rule.Name)
			}
		}
	})
}
