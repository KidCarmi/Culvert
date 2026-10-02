package main

import (
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
)

// categoryGroupMatchesHostScratch answers an UNCATEGORIZED host (empty fusion
// category) without resolving the group at all. These gates pin that the
// short-circuit is behaviour-preserving, because it sits in front of the
// Allow/Deny decision for every category-group rule: a wrong "false" silently
// stops a Deny rule enforcing, and a wrong "true" blocks traffic no rule
// covers.
//
// The oracle is the pre-guard body, reproduced verbatim below, so the
// equivalence is asserted against what the code actually used to do rather
// than against a restatement of it.
func legacyCategoryGroupMatches(rule *PolicyRule, sc *hostCatScratch) bool {
	hostCat, _, _ := sc.fusion()
	if id := rule.DestCategoryGroupID; id != "" {
		if matched, resolved := globalCategoryGroups.MatchesCategoryByID(id, hostCat); resolved {
			return matched
		}
	}
	return globalCategoryGroups.MatchesCategory(rule.DestCategoryGroup, hostCat)
}

func TestCategoryGroupUncategorized_GuardIsBehaviourPreserving(t *testing.T) {
	origGroups := globalCategoryGroups
	t.Cleanup(func() { globalCategoryGroups = origGroups })

	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.ReplaceAll([]CategoryGroup{
		{ID: "grp000000001", Name: "streaming-grp", Categories: []string{"Streaming", "Gambling"}},
		{ID: "grp000000002", Name: "social-grp", Categories: []string{"Social Media"}},
	})

	rules := []PolicyRule{
		{Name: "id+name, member", DestCategoryGroup: "social-grp", DestCategoryGroupID: "grp000000002"},
		{Name: "id+name, non-member", DestCategoryGroup: "streaming-grp", DestCategoryGroupID: "grp000000001"},
		{Name: "name only, member", DestCategoryGroup: "social-grp"},
		{Name: "name only, non-member", DestCategoryGroup: "streaming-grp"},
		{Name: "dangling id, name resolves", DestCategoryGroup: "social-grp", DestCategoryGroupID: "nosuchid0001"},
		{Name: "dangling id, dangling name", DestCategoryGroup: "nosuch-grp", DestCategoryGroupID: "nosuchid0001"},
		{Name: "empty group ref", DestCategoryGroup: ""},
	}

	// facebook.com is "Social Media" in the shipped taxonomy; the .invalid host
	// is classified by no tier, so its fusion category is empty — the shape the
	// guard answers.
	hosts := []string{"facebook.com", "uncategorized.example.invalid", ""}

	for _, host := range hosts {
		for i := range rules {
			rule := &rules[i]
			want := func() bool { sc := newHostCatScratch(host); return legacyCategoryGroupMatches(rule, &sc) }()
			got := func() bool { sc := newHostCatScratch(host); return categoryGroupMatchesHostScratch(rule, &sc) }()
			if got != want {
				t.Errorf("host=%q rule=%q: guard returned %v, pre-guard body returned %v",
					host, rule.Name, got, want)
			}
		}
	}
}

// CONTROL: the guard must not have turned the matcher into a constant false.
// A categorized host that IS a member still has to match, or every
// category-group Deny rule has silently stopped enforcing — which is the
// failure mode a "skip the work" optimization produces and which every
// equivalence test above would still pass if the oracle were broken the same
// way.
func TestCategoryGroupUncategorized_ControlMembershipStillMatches(t *testing.T) {
	origGroups := globalCategoryGroups
	t.Cleanup(func() { globalCategoryGroups = origGroups })

	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.ReplaceAll([]CategoryGroup{
		{ID: "grp000000002", Name: "social-grp", Categories: []string{"Social Media"}},
	})

	byID := &PolicyRule{DestCategoryGroup: "social-grp", DestCategoryGroupID: "grp000000002"}
	byName := &PolicyRule{DestCategoryGroup: "social-grp"}

	if !func() bool {
		sc := newHostCatScratch("facebook.com")
		return categoryGroupMatchesHostScratch(byID, &sc)
	}() {
		t.Error("ID-addressed rule stopped matching a member host: category-group enforcement is off")
	}
	if !func() bool {
		sc := newHostCatScratch("facebook.com")
		return categoryGroupMatchesHostScratch(byName, &sc)
	}() {
		t.Error("name-addressed rule stopped matching a member host")
	}
	if func() bool {
		sc := newHostCatScratch("uncategorized.example.invalid")
		return categoryGroupMatchesHostScratch(byID, &sc)
	}() {
		t.Error("uncategorized host must not match any group")
	}
}

// An empty category name is never a group member, which is what makes the
// guard equivalent.
//
// SCOPE: this covers the REACHABLE path only — admin CRUD and bulk installs go
// through normCats, which drops empty and whitespace-only names before a
// catSet is built, so what this pins is that normalization. It deliberately
// does NOT pin catgroup's own buildCatSet filter: an end-to-end test cannot,
// because normCats has already removed the empties by then (verified — an
// earlier version of this test passed with that filter removed, i.e. it was
// vacuous). The filter is pinned where it is reachable, by
// TestBuildCatSet_RefusesEmptyCategory in internal/catgroup.
func TestCategoryGroupUncategorized_EmptyCategoryIsNeverAMember(t *testing.T) {
	origGroups := globalCategoryGroups
	t.Cleanup(func() { globalCategoryGroups = origGroups })

	globalCategoryGroups = catgroup.New()
	// Empty and whitespace-only categories, alongside a real one.
	globalCategoryGroups.ReplaceAll([]CategoryGroup{
		{ID: "grp000000003", Name: "mixed-grp", Categories: []string{"", "   ", "Social Media"}},
	})

	for _, probe := range []string{"", " ", "\t"} {
		if m, _ := globalCategoryGroups.MatchesCategoryByID("grp000000003", probe); m {
			t.Errorf("empty-ish category %q reported as a group member", probe)
		}
		if globalCategoryGroups.MatchesCategory("mixed-grp", probe) {
			t.Errorf("empty-ish category %q reported as a group member by name", probe)
		}
	}
	if m, resolved := globalCategoryGroups.MatchesCategoryByID("grp000000003", "Social Media"); !resolved || !m {
		t.Errorf("real category lost: (%v,%v)", m, resolved)
	}
}

// The guard removes one group resolve per category-group rule, so on the
// uncategorized shape the scan must not get cheaper as a side effect of
// evaluating fewer rules. Pin that every rule is still visited by giving the
// last rule in priority order a match the scan has to reach.
func TestCategoryGroupUncategorized_ScanStillVisitsEveryRule(t *testing.T) {
	origGroups := globalCategoryGroups
	t.Cleanup(func() { globalCategoryGroups = origGroups })
	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.ReplaceAll([]CategoryGroup{
		{ID: "grp000000004", Name: "catchall", Categories: []string{"Social Media"}},
	})

	ps := &PolicyStore{}
	rules := make([]PolicyRule, 0, 6)
	for i := 0; i < 5; i++ {
		rules = append(rules, PolicyRule{
			Priority:            i + 1,
			Name:                fmt.Sprintf("group-rule-%d", i),
			DestCategoryGroup:   "catchall",
			DestCategoryGroupID: "grp000000004",
			Action:              ActionBlockPage,
		})
	}
	// Lowest priority, no category constraint: only reached if the five
	// category-group rules above were all evaluated and all declined.
	rules = append(rules, PolicyRule{
		Priority: 99, Name: "fallthrough", Action: ActionAllow,
	})
	ps.ReplaceAll(rules)

	m := ps.Evaluate("203.0.113.7", "", "unauth", "uncategorized.example.invalid", nil)
	if m == nil {
		t.Fatal("expected the fall-through rule to match")
	}
	if m.Rule.Name != "fallthrough" {
		t.Fatalf("expected fall-through, got %q: an uncategorized host matched a category group", m.Rule.Name)
	}
}
