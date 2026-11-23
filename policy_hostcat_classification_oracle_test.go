package main

// Why an UNCATEGORIZED destination does not license skipping category
// membership probes — the trap guarding the optimization the measurements in
// policy_category_realistic_bench_test.go invite.
//
// ── THE OPTIMIZATION THIS FORBIDS ───────────────────────────────────────────
//
// Single-category rules pay a full membership probe per rule per request
// (measured 107 ns/rule; 13.9 µs at 200 rules). hostCatScratch already
// memoizes the destination's CLASSIFICATION (fusion), so the obvious
// amortization is to short-circuit matchesCategory:
//
//	if sc.fusion() == "" { return false }   // WRONG — fail-OPEN
//
// Measured, that is a 61-85% reduction across every rule count, with no
// allocation added. It is also unsound, and the direction it fails in is the
// dangerous one: a Deny rule silently stops blocking.
//
// ── WHY IT IS UNSOUND ───────────────────────────────────────────────────────
//
// The premise is that classification succeeds whenever any membership probe
// would, because both walk the same exact-then-suffix keys. For the catStore
// tier that is FALSE BY CONSTRUCTION, and deliberately so: rebuildIndex
// (internal/urlcat/urlcat.go) builds the two directions with DIFFERENT key
// normalization, and says so —
//
//	set[strings.ToLower(strings.TrimSuffix(h, "."))] = true   // forward: TRIMMED
//	pk := strings.ToLower(h)                                  // reverse: NOT trimmed
//
// "NOTE the deliberately DIFFERENT key normalization ... The two matchers have
// disagreed on a 'example.com.'-shaped pattern since before this index
// existed; reproducing the difference keeps this a pure cost change.
// Reconciling them is a separate decision."
//
// So a category whose host pattern carries a TRAILING DOT is matched by the
// forward (membership) index and is invisible to the reverse (classification)
// index. The host is a MEMBER of the category while being classified by NO
// tier, and the short-circuit above converts that rule's match into a miss.
//
// The shape is reachable, not theoretical: Store.setMem stores the host list
// RAW (no normalization), and the admin category PUT hands it operator-supplied
// JSON (ui_policy.go) while the SaaS feed sync hands it feed-supplied hosts
// (saas_feed.go). Only the single-host AddHost path normalizes.
//
// ── THE TEST ────────────────────────────────────────────────────────────────
//
// What is asserted below is the FACTUAL property of the two indexes — that
// they disagree on this shape — and the consequence that follows for any
// classification-derived short-circuit. It is deliberately NOT an assertion
// that the disagreement is desirable. If the normalization is ever reconciled
// (the "separate decision" above), this test fails and names the optimization
// that reconciliation would unlock, rather than leaving it buried.
//
// KNOWN DEFECT, recorded here because this test is what proves it: the shipped
// category-GROUP matcher already takes this short-circuit —
// categoryGroupMatchesHostScratch returns false when fusion() is empty — so
// for a trailing-dot pattern a destCategoryGroup Deny rule does NOT block a
// host that the equivalent destCategory Deny rule DOES block. That is a
// pre-existing fail-open in the group path, not one introduced here, and
// fixing it is a policy-matching change outside a measurement change's scope.
// TestCategoryGroup_TrailingDotPatternFailsOpen below pins it as a WITNESS so
// the inconsistency cannot be mistaken for intended behaviour.

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/catgroup"
	"github.com/KidCarmi/Culvert/internal/urlcat"
)

// seedTrailingDotCategory installs a single admin category whose only host
// pattern carries a trailing dot — the shape the two indexes key differently.
func seedTrailingDotCategory(t *testing.T) {
	t.Helper()
	prev := catStore
	t.Cleanup(func() { catStore = prev })
	catStore = urlcat.New([]*urlcat.Entry{
		{Name: "Blocked Stuff", Hosts: []string{"example.com."}},
	})
}

func TestCategoryMembership_ClassificationIsNotAMembershipOracle(t *testing.T) {
	seedTrailingDotCategory(t)
	const host = "example.com"

	scMember := newHostCatScratch(host)
	member := scMember.matchesCategory("Blocked Stuff")

	scFusion := newHostCatScratch(host)
	gotCat, gotTier, _ := scFusion.fusion()

	if !member {
		t.Fatalf("membership: matchesCategory(%q, %q) = false, want true — the forward "+
			"index is built with TrimSuffix(h, \".\") so the trailing-dot pattern should "+
			"match this host. If this changed, the premise of this whole file moved.",
			"Blocked Stuff", host)
	}

	if gotCat != "" {
		t.Fatalf("classification: fusion(%q) = %q (tier %q), want \"\" — the reverse index "+
			"is built WITHOUT TrimSuffix, so no tier should classify this host. The two key "+
			"normalizations have evidently been reconciled (internal/urlcat/urlcat.go "+
			"rebuildIndex). That is the \"separate decision\" that file defers, and it is "+
			"what makes the fusion()==\"\" short-circuit in matchesCategory SOUND: this test "+
			"now exists to tell you the optimization in "+
			"policy_category_realistic_bench_test.go is available (measured 61-85%%, no "+
			"allocation). Re-verify the effective-view and community tiers the same way "+
			"before taking it.", host, gotCat, gotTier)
	}

	t.Logf("witness: %q is a MEMBER of %q while classified by no tier (fusion=%q) — "+
		"an uncategorized destination therefore does NOT imply no membership",
		host, "Blocked Stuff", gotCat)
}

// TestCategoryGroup_TrailingDotPatternFailsOpen is the WITNESS for the
// pre-existing group-path defect described in this file's header. It asserts
// the inconsistency EXISTS between the two rule shapes; it does not assert that
// the group answer is correct. When the defect is fixed, this test fails and
// points at the fix, which is the intended way for it to go away.
func TestCategoryGroup_TrailingDotPatternFailsOpen(t *testing.T) {
	seedTrailingDotCategory(t)
	const host = "example.com"

	origGroups := globalCategoryGroups
	t.Cleanup(func() { globalCategoryGroups = origGroups })
	globalCategoryGroups = catgroup.New()
	globalCategoryGroups.ReplaceAll([]CategoryGroup{
		{ID: "grp000000001", Name: "blockgrp", Categories: []string{"Blocked Stuff"}},
	})

	scSingle := newHostCatScratch(host)
	single := scSingle.matchesCategory("Blocked Stuff")

	groupRule := &PolicyRule{
		Name:                "deny-by-group",
		DestCategoryGroup:   "blockgrp",
		DestCategoryGroupID: "grp000000001",
	}
	scGroup := newHostCatScratch(host)
	group := categoryGroupMatchesHostScratch(groupRule, &scGroup)

	switch {
	case single && !group:
		t.Logf("witness (known defect): destCategory=%q matches %q but a destCategoryGroup "+
			"rule over the group {%q} does not. A Deny rule written against the GROUP does "+
			"not block traffic the equivalent single-category Deny rule blocks. Root cause: "+
			"the forward/reverse key divergence in rebuildIndex, consumed by the "+
			"fusion()==\"\" short-circuit in categoryGroupMatchesHostScratch.",
			"Blocked Stuff", host, "Blocked Stuff")
	case single && group:
		t.Fatalf("the group path now AGREES with the single-category path on the "+
			"trailing-dot shape (%q). The fail-open this witness records is fixed — delete "+
			"this test and the KNOWN DEFECT note in this file's header, and re-read "+
			"TestCategoryMembership_ClassificationIsNotAMembershipOracle, which may now "+
			"permit the matchesCategory short-circuit.", host)
	default:
		t.Fatalf("single-category membership for %q is now false; this witness no longer "+
			"measures the divergence it was written for (see the oracle test).", host)
	}
}
