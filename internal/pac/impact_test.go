package pac

// impact_test.go — DiffProfiles spec-identity coverage: an in-place change to
// a rule's action or pool override (same match tuple) must surface as a
// removal + addition, not be swallowed as "unchanged" (the match-only-key
// gap). Reorder/shadow stay on the match-only key by design.

import "testing"

func ruleUsePool(pattern, pool string) Rule {
	return Rule{Kind: RuleKindSuffix, Pattern: pattern, Action: ActionUsePool, PoolID: pool}
}

func TestDiffProfiles_PoolOverrideChangeIsDiffed(t *testing.T) {
	old := Profile{ID: "hq", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{ruleUsePool("cdn.example", "")}}
	// Same match tuple + same action, but the rule now overrides the pool.
	next := Profile{ID: "hq", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{ruleUsePool("cdn.example", "alt")}}

	d := DiffProfiles(old, true, next)
	if len(d.RulesAdded) != 1 || len(d.RulesRemoved) != 1 {
		t.Fatalf("pool-override change must diff: added=%v removed=%v", d.RulesAdded, d.RulesRemoved)
	}
	if d.RulesReordered {
		t.Error("an in-place spec change is not a reorder")
	}
}

func TestDiffProfiles_ActionChangeIsDiffed(t *testing.T) {
	old := Profile{ID: "hq", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{ruleUsePool("cdn.example", "")}}
	// Action flips use_pool → direct while the match tuple is identical.
	next := Profile{ID: "hq", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{{Kind: RuleKindSuffix, Pattern: "cdn.example", Action: ActionDirect}}}

	d := DiffProfiles(old, true, next)
	if len(d.RulesAdded) != 1 || len(d.RulesRemoved) != 1 {
		t.Fatalf("action change must diff: added=%v removed=%v", d.RulesAdded, d.RulesRemoved)
	}
	// It also newly introduces DIRECT, so the diff must be flagged sensitive.
	if !d.SecuritySensitive || len(d.NewDirectPaths) == 0 {
		t.Errorf("use_pool→direct must flag a new DIRECT path: %+v", d)
	}
}

func TestDiffProfiles_IdenticalRulesUnchanged(t *testing.T) {
	p := Profile{ID: "hq", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{ruleUsePool("cdn.example", "alt"), ruleUsePool("api.example", "")}}
	d := DiffProfiles(p, true, p)
	if len(d.RulesAdded) != 0 || len(d.RulesRemoved) != 0 || d.RulesReordered {
		t.Errorf("identical profiles must diff clean: %+v", d)
	}
}

func TestDiffProfiles_ReorderStaysMatchKeyed(t *testing.T) {
	// Swapping two rules' order (same specs) is a reorder, not add/remove.
	old := Profile{ID: "hq", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{ruleUsePool("a.example", ""), ruleUsePool("b.example", "")}}
	next := Profile{ID: "hq", PoolID: "main", AvailabilityMode: ModeBalanced, PrivateNetworks: PrivateProxy,
		Rules: []Rule{ruleUsePool("b.example", ""), ruleUsePool("a.example", "")}}
	d := DiffProfiles(old, true, next)
	if len(d.RulesAdded) != 0 || len(d.RulesRemoved) != 0 {
		t.Errorf("pure reorder must not add/remove: %+v", d)
	}
	if !d.RulesReordered {
		t.Error("pure reorder must be flagged reordered")
	}
}
