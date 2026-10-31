//go:build benchgate

package main

// Deterministic allocation-regression gate for the CATEGORY-GROUP leg of the
// policy scan. Pairs with TestBenchGate_PolicyEvalAllocs in
// bench_regression_test.go, which holds the plain-FQDN leg to a constant
// allocation bound; this file holds the category-group leg to the same
// contract, which it did NOT previously meet.
//
//	go test -tags benchgate -run 'TestBenchGate_PolicyEvalCategoryGroup' -v .
//
// WHAT THIS CATCHES, AND WHY IT IS A SEPARATE GATE. The plain-FQDN gate scans
// rules carrying DestFQDN, so it never evaluates a category-group rule and
// could not see the regression this gate exists for: catgroup's membership
// probe took the DISPLAY-CASED category name and lowered it on every call,
// i.e. once per category-group rule per proxied request, and every category
// the product ships is display-cased ("Social Media", "Gambling", "HR &
// Recruiting", ...) so strings.ToLower's no-allocation fast path never
// applied. Measured at 20 ID-stamped rules against a categorized destination:
// 20 allocs/op, 320 B/op, 91% of every allocation the scan made, linear in the
// rule count.
//
// The bound below is therefore a CONSTANT, not a function of the rule count —
// exactly the shape of the plain-FQDN gate's bound, and for the same reason:
// its job is to catch the reintroduction of O(rules) allocation, not to pin an
// exact figure. A caller that goes back to passing the display-cased name
// (MatchesCategoryByID instead of MatchesCategoryKeyByID), or a scratch that
// stops memoizing the key, fails here at every rule count above the bound.

import (
	"fmt"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// gateCatGroupHosts: the categorized host is the one that exercises the probe
// at all — an UNCATEGORIZED destination is answered by the call-site guard in
// categoryGroupMatchesHostScratch without resolving any group, so it cannot
// witness a per-rule allocation. facebook.com is "Social Media" in the shipped
// taxonomy; the seeded groups deliberately do not hold it, so no rule matches
// and every rule runs a full membership probe.
const (
	gateHostCategorized   = "facebook.com"
	gateHostUncategorized = "uncategorized.example.invalid"
)

// gateSeedCategoryGroups installs groups and returns one stable ID per rule, in
// rule order. It is a testing.TB-free sibling of the benchmark helper in
// policy_catgroup_id_bench_test.go, because this gate is a Test and drives
// testing.Benchmark itself.
func gateSeedCategoryGroups(rules, groupsInStore int) []string {
	globalCategoryGroups = catgroup.New()
	groups := make([]CategoryGroup, 0, groupsInStore)
	for i := 0; i < groupsInStore; i++ {
		groups = append(groups, CategoryGroup{
			ID:   fmt.Sprintf("grpid%07d", i),
			Name: fmt.Sprintf("Group %d", i), // display-cased, as an operator types it
			// Display-cased categories, as the shipped taxonomy spells them.
			Categories: []string{"Streaming", "Gambling"},
		})
	}
	globalCategoryGroups.ReplaceAll(groups)

	ids := make([]string, 0, rules)
	for i := 0; i < rules; i++ {
		ids = append(ids, fmt.Sprintf("grpid%07d", groupsInStore-1-(i%groupsInStore)))
	}
	return ids
}

// gateCatGroupStore builds a rulebase of ID-stamped category-group rules — the
// shape production runs, since stampObjectRefIDs stamps the authoritative ID on
// every rule saved against an existing group.
func gateCatGroupStore(n int, ids []string) *PolicyStore {
	ps := &PolicyStore{}
	rules := make([]PolicyRule, n)
	for i := 0; i < n; i++ {
		rules[i] = PolicyRule{
			Priority:            i + 1,
			Name:                fmt.Sprintf("catgroup-gate-rule-%d", i),
			DestCategoryGroup:   fmt.Sprintf("Group %d", i),
			DestCategoryGroupID: ids[i],
			Action:              ActionBlockPage,
		}
	}
	ps.ReplaceAll(rules)
	return ps
}

// TestBenchGate_PolicyEvalCategoryGroupAllocs locks the category-group scan to a
// constant allocation count independent of the rule count.
func TestBenchGate_PolicyEvalCategoryGroupAllocs(t *testing.T) {
	origCat, origGroups := catStore, globalCategoryGroups
	t.Cleanup(func() { catStore, globalCategoryGroups = origCat, origGroups })
	catStore = urlcat.New(urlcat.DefaultEntries())

	// Measured: 1 alloc/op at every rule count — the ONE per-scan
	// strings.ToLower of the resolved destination category, which
	// hostCatScratch.fusionCatKey derives once and every rule then shares.
	//
	// The bound stays at 4 rather than tightening to the measured 1, for the
	// reason the plain-FQDN gate gives: the job is catching an O(rules)
	// regression, and headroom keeps the gate immune to escape-analysis
	// differences across Go releases and architectures. At 200 rules a
	// per-rule regression reports ~200 and blows past it by 50x; the exact
	// per-call contract is pinned where it belongs, in internal/catgroup's
	// TestMatchesCategoryKey_AllocationContract.
	const maxAllocs int64 = 4
	for _, rules := range []int{1, 10, 50, 200} {
		ids := gateSeedCategoryGroups(rules, 64)
		ps := gateCatGroupStore(rules, ids)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", gateHostCategorized, nil)
			}
		})
		allocs := res.AllocsPerOp()
		t.Logf("Evaluate category-group rules=%d: %d allocs/op (bound %d), %d B/op, %d ns/op",
			rules, allocs, maxAllocs, res.AllocedBytesPerOp(), res.NsPerOp())
		if allocs > maxAllocs {
			t.Errorf("REGRESSION: category-group Evaluate rules=%d allocates %d/op, exceeds constant "+
				"bound %d — the per-rule membership probe is deriving the catSet key again instead of "+
				"taking the one hostCatScratch.fusionCatKey already holds (a caller switched back to "+
				"MatchesCategoryByID / MatchesCategory, or the scratch memo was dropped).",
				rules, allocs, maxAllocs)
		}
	}
}

// TestBenchGate_PolicyEvalCategoryGroupUncategorizedStaysFree pins the common
// gateway shape — a destination no tier classifies — at zero allocations. The
// call-site guard answers it without resolving a group at all, so this arm is
// the one that must never regain an allocation for ANY rule count, and it is
// also the negative control for the gate above: if it started allocating, the
// guard itself had been bypassed.
func TestBenchGate_PolicyEvalCategoryGroupUncategorizedStaysFree(t *testing.T) {
	origCat, origGroups := catStore, globalCategoryGroups
	t.Cleanup(func() { catStore, globalCategoryGroups = origCat, origGroups })
	catStore = urlcat.New(urlcat.DefaultEntries())

	const maxAllocs int64 = 1 // headroom for the client-IP parse; measured 0
	for _, rules := range []int{10, 200} {
		ids := gateSeedCategoryGroups(rules, 64)
		ps := gateCatGroupStore(rules, ids)
		res := testing.Benchmark(func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = ps.Evaluate("203.0.113.7", "", "unauth", gateHostUncategorized, nil)
			}
		})
		if allocs := res.AllocsPerOp(); allocs > maxAllocs {
			t.Errorf("REGRESSION: uncategorized-destination category-group scan rules=%d allocates "+
				"%d/op, exceeds %d — the uncategorized short-circuit in "+
				"categoryGroupMatchesHostScratch is no longer answering before the group resolve.",
				rules, allocs, maxAllocs)
		} else {
			t.Logf("Evaluate uncategorized rules=%d: %d allocs/op, %d ns/op", rules, allocs, res.NsPerOp())
		}
	}
}
