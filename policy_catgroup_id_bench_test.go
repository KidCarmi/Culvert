package main

// End-to-end measure of the AUTHORITATIVE, rename-safe category-group link.
//
// THE BLIND SPOT THIS FILLS. Every pre-existing category-group benchmark
// (buildCategoryGroupPolicyStore, policy_bench_test.go /
// policy_category_bench_test.go) builds rules that set DestCategoryGroup — the
// denormalized NAME — and leave DestCategoryGroupID empty. So all of them
// exercised catgroup's O(1) GetByName fallback. Production is the opposite:
// stampObjectRefIDs (ui_policy.go) stamps the ID on every rule saved against
// an existing group, and categoryGroupMatchesHostScratch prefers the ID, so
// essentially 100% of real category-group rules took the path NO benchmark
// covered — which was a walk of the whole group map, per rule, per request,
// with the store's read lock held across it.
//
// The ID shape is therefore the one a gateway actually runs, and these arms
// measure it. The _ByName arms stay beside them as the reference and as the
// standing reminder that a benchmark covering only the fallback proves nothing
// about the path in production.
//
//	go test -run '^$' -bench 'BenchmarkPolicyEvaluate_CategoryGroupByID' -benchmem .

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// buildCategoryGroupIDPolicyStore mirrors buildCategoryGroupPolicyStore but
// stamps DestCategoryGroupID the way the admin API does, so the scan takes the
// authoritative branch.
func buildCategoryGroupIDPolicyStore(n int, ids []string) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority:            i + 1,
			Name:                fmt.Sprintf("catgroup-id-rule-%d", i),
			DestCategoryGroup:   fmt.Sprintf("group-%d", i),
			DestCategoryGroupID: ids[i],
			Action:              ActionBlockPage,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// seedCategoryGroups installs n groups and returns their stable IDs in rule
// order. groupsInStore lets the benchmark hold the RULE count fixed while
// varying how many groups the resolve has to look past — the axis the old walk
// was linear in and nothing measured.
func seedCategoryGroups(b *testing.B, rules, groupsInStore int) []string {
	b.Helper()
	globalCategoryGroups = catgroup.New()
	groups := make([]CategoryGroup, 0, groupsInStore)
	for i := 0; i < groupsInStore; i++ {
		groups = append(groups, CategoryGroup{
			ID:         fmt.Sprintf("grpid%07d", i),
			Name:       fmt.Sprintf("group-%d", i),
			Categories: []string{"Streaming", "Gambling"},
		})
	}
	globalCategoryGroups.ReplaceAll(groups)

	ids := make([]string, 0, rules)
	for i := 0; i < rules; i++ {
		// Rules reference the LAST groups, so a walk cannot get lucky on the
		// first bucket it visits.
		ids = append(ids, fmt.Sprintf("grpid%07d", groupsInStore-1-(i%groupsInStore)))
	}
	return ids
}

// benchGroupHosts are the two shapes the probe sees.
//
// CATEGORIZED is the honest worst case FOR THIS COMPONENT: facebook.com
// resolves to "Social Media" in the shipped taxonomy, which none of the seeded
// groups holds, so the fusion returns a non-empty category, every rule runs a
// real group-membership probe, and no rule matches (so the scan runs to
// completion). Note this is the OPPOSITE of the worst case for the urlcat
// fusion that the older benchmarks target with an uncategorized host: there a
// miss cannot short-circuit, here a miss is precisely what short-circuits.
//
// UNCATEGORIZED is the common gateway shape and, since the call-site guard,
// the one where the per-rule probe disappears entirely.
const (
	benchHostCategorized   = "facebook.com"
	benchHostUncategorized = "uncategorized.example.invalid"
)

func benchGroupScanEnv(b *testing.B) {
	b.Helper()
	origCat, origGroups := catStore, globalCategoryGroups
	b.Cleanup(func() { catStore, globalCategoryGroups = origCat, origGroups })
	catStore = newCategoryStore(urlcat.DefaultEntries())
	catStore.SetPathForTest(filepath.Join(b.TempDir(), "categories.json"))
}

// BenchmarkPolicyEvaluate_CategoryGroupByID holds the rule count at a realistic
// category-driven posture and varies the store size, which is the axis the
// resolve used to be linear in. maxSnapCategoryGroups caps the store at 1000.
func BenchmarkPolicyEvaluate_CategoryGroupByID(b *testing.B) {
	benchGroupScanEnv(b)
	const rules = 20
	for _, host := range []string{benchHostCategorized, benchHostUncategorized} {
		for _, groups := range []int{8, 64, 256, 1000} {
			ids := seedCategoryGroups(b, rules, groups)
			ps := buildCategoryGroupIDPolicyStore(rules, ids)
			b.Run(fmt.Sprintf("host=%s/rules=%d/groups=%d", benchHostLabel(host), rules, groups), func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if m := ps.Evaluate("203.0.113.7", "", "unauth", host, nil); m != nil {
						b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
					}
				}
			})
		}
	}
}

func benchHostLabel(host string) string {
	if host == benchHostCategorized {
		return "categorized"
	}
	return "uncategorized"
}

// BenchmarkPolicyEvaluate_CategoryGroupByName is the same scan on the
// denormalized-name fallback: the shape every pre-existing benchmark measured.
func BenchmarkPolicyEvaluate_CategoryGroupByName(b *testing.B) {
	benchGroupScanEnv(b)
	const rules = 20
	for _, groups := range []int{8, 64, 256, 1000} {
		seedCategoryGroups(b, rules, groups)
		ps := &PolicyStore{}
		rs := make([]PolicyRule, rules)
		for i := 0; i < rules; i++ {
			rs[i] = PolicyRule{
				Priority:          i + 1,
				Name:              fmt.Sprintf("catgroup-name-rule-%d", i),
				DestCategoryGroup: fmt.Sprintf("group-%d", groups-1-(i%groups)),
				Action:            ActionBlockPage,
			}
		}
		ps.ReplaceAll(rs)
		b.Run(fmt.Sprintf("rules=%d/groups=%d", rules, groups), func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if m := ps.Evaluate("203.0.113.7", "", "unauth", benchHostCategorized, nil); m != nil {
					b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
				}
			}
		})
	}
}

// BenchmarkPolicyEvaluate_CategoryGroupByIDParallel measures the same scan
// under concurrency: the walk was paid with catgroup's read lock held, so
// shortening it shortens the critical section every core serving traffic
// contends on.
//
//	go test -run '^$' -bench 'CategoryGroupByIDParallel' -benchmem -cpu 1,2,4 .
func BenchmarkPolicyEvaluate_CategoryGroupByIDParallel(b *testing.B) {
	benchGroupScanEnv(b)
	const rules, groups = 20, 256
	ids := seedCategoryGroups(b, rules, groups)
	ps := buildCategoryGroupIDPolicyStore(rules, ids)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if m := ps.Evaluate("203.0.113.7", "", "unauth", benchHostCategorized, nil); m != nil {
				b.Fatalf("expected no match (default deny), got rule %q", m.Rule.Name)
			}
		}
	})
}
