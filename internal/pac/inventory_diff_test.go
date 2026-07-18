package pac

// inventory_diff_test.go — behavioral proofs for the DIRECT-surface change-diff
// (P3-a). Built over real BuildDirectInventory outputs so the diff is exercised
// against the actual read-model, not hand-crafted structs.

import "testing"

func invOf(profiles ...Profile) DirectInventory {
	pools := []Pool{{ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}}
	return BuildDirectInventory(ProfilesConfig{Pools: pools, Profiles: profiles})
}

func prof(id string, mode, priv string, rules ...Rule) Profile {
	return Profile{ID: id, Name: id, Enabled: true, PoolID: "p", PrivateNetworks: priv, AvailabilityMode: mode, Revision: 1, Rules: rules}
}

// TestDiff_NoChangeIsEmpty proves an identical before/after yields no deltas and
// does not flag a risk increase.
func TestDiff_NoChangeIsEmpty(t *testing.T) {
	inv := invOf(prof("a", ModeBalanced, PrivateProxy))
	d := DiffDirectInventory(inv, inv)
	if len(d.Deltas) != 0 || d.RiskIncreased {
		t.Fatalf("identical inventories must diff empty: %+v", d)
	}
	if d.EvidenceClass != "config" {
		t.Errorf("evidence class = %q, want config", d.EvidenceClass)
	}
}

// TestDiff_ProfileGainedDirect proves adding a new profile registers a gained-
// DIRECT profile and its paths as additions, and flags risk increased.
func TestDiff_ProfileGainedDirect(t *testing.T) {
	before := invOf(prof("a", ModeBalanced, PrivateProxy))
	after := invOf(
		prof("a", ModeBalanced, PrivateProxy),
		prof("b", ModeBalanced, PrivateDirect), // new, DIRECT-capable (private + plain-host)
	)
	d := DiffDirectInventory(before, after)
	if d.ProfilesGainedDirect != 1 || !d.RiskIncreased {
		t.Fatalf("want 1 gained profile + risk increased: %+v", d)
	}
	var gained, broadAdd bool
	for _, x := range d.Deltas {
		if x.Change == ChangeProfileGainedDirect && x.ProfileID == "b" {
			gained = true
		}
		if x.Change == ChangePathAdded && x.ProfileID == "b" && x.Kind == BypassPrivate && x.Broad {
			broadAdd = true
		}
	}
	if !gained {
		t.Error("missing profile_gained_direct delta for b")
	}
	if !broadAdd || d.BroadPathsAdded < 1 {
		t.Errorf("new profile's broad private bypass must be an added broad path: %+v", d.Deltas)
	}
}

// TestDiff_ProfileLostDirect proves removing a profile is risk-reducing.
func TestDiff_ProfileLostDirect(t *testing.T) {
	before := invOf(
		prof("a", ModeBalanced, PrivateProxy),
		prof("b", ModeAvailability, PrivateProxy),
	)
	after := invOf(prof("a", ModeBalanced, PrivateProxy))
	d := DiffDirectInventory(before, after)
	if d.ProfilesLostDirect != 1 {
		t.Fatalf("want 1 lost profile: %+v", d)
	}
	if d.RiskIncreased {
		t.Error("a pure removal must not flag risk increased")
	}
	var lost bool
	for _, x := range d.Deltas {
		if x.Change == ChangeProfileLostDirect && x.ProfileID == "b" {
			lost = true
		}
		if x.RiskIncreasing {
			t.Errorf("removal deltas must not be risk-increasing: %+v", x)
		}
	}
	if !lost {
		t.Error("missing profile_lost_direct delta for b")
	}
}

// TestDiff_RuleBroadened proves a narrow→wildcard rule change reads as a removed
// narrow path + an added BROAD path (the risk signal rides the add).
func TestDiff_RuleBroadened(t *testing.T) {
	before := invOf(prof("a", ModeBalanced, PrivateProxy,
		Rule{Kind: RuleKindDomain, Pattern: "vendor.example", Action: ActionDirect}))
	after := invOf(prof("a", ModeBalanced, PrivateProxy,
		Rule{Kind: RuleKindWildcard, Pattern: "*.vendor.example", Action: ActionDirect}))
	d := DiffDirectInventory(before, after)
	if d.PathsAdded != 1 || d.PathsRemoved != 1 {
		t.Fatalf("broadening must be 1 add + 1 remove: %+v", d)
	}
	if d.BroadPathsAdded != 1 || !d.RiskIncreased {
		t.Errorf("the added wildcard path must be broad + risk-increasing: %+v", d)
	}
	var addedBroad, removedNarrow bool
	for _, x := range d.Deltas {
		if x.Change == ChangePathAdded && x.Kind == BypassRule && x.Broad {
			addedBroad = true
		}
		if x.Change == ChangePathRemoved && x.Kind == BypassRule && !x.Broad {
			removedNarrow = true
		}
	}
	if !addedBroad || !removedNarrow {
		t.Errorf("want added-broad + removed-narrow rule deltas: %+v", d.Deltas)
	}
}

// TestDiff_PathAddedAndRemovedOnExistingProfile proves per-profile set diffing
// of DIRECT sources (private bypass toggled on; a direct rule dropped).
func TestDiff_PathAddedAndRemovedOnExistingProfile(t *testing.T) {
	before := invOf(prof("a", ModeBalanced, PrivateProxy,
		Rule{Kind: RuleKindDomain, Pattern: "drop.example", Action: ActionDirect}))
	after := invOf(prof("a", ModeBalanced, PrivateDirect)) // rule removed, private added
	d := DiffDirectInventory(before, after)
	var addedPrivate, removedRule bool
	for _, x := range d.Deltas {
		if x.Change == ChangePathAdded && x.Kind == BypassPrivate {
			addedPrivate = true
		}
		if x.Change == ChangePathRemoved && x.Kind == BypassRule && x.Pattern == "drop.example" {
			removedRule = true
		}
	}
	if !addedPrivate || !removedRule {
		t.Errorf("want added private + removed rule deltas: %+v", d.Deltas)
	}
}

// TestDiff_RuleKindFlipIsDetected pins the Codex fix: a same-pattern rule-kind
// change (suffix→domain, which broadens subdomains-only to apex+subdomains) must
// read as remove+add, not identical.
func TestDiff_RuleKindFlipIsDetected(t *testing.T) {
	before := invOf(prof("a", ModeBalanced, PrivateProxy,
		Rule{Kind: RuleKindSuffix, Pattern: "example.com", Action: ActionDirect}))
	after := invOf(prof("a", ModeBalanced, PrivateProxy,
		Rule{Kind: RuleKindDomain, Pattern: "example.com", Action: ActionDirect}))
	d := DiffDirectInventory(before, after)
	if d.PathsAdded != 1 || d.PathsRemoved != 1 || !d.RiskIncreased {
		t.Fatalf("suffix→domain (same pattern) must be 1 add + 1 remove + risk: %+v", d)
	}
	var addedDomain, removedSuffix bool
	for _, x := range d.Deltas {
		if x.Change == ChangePathAdded && x.Kind == BypassRule {
			addedDomain = true
		}
		if x.Change == ChangePathRemoved && x.Kind == BypassRule {
			removedSuffix = true
		}
	}
	if !addedDomain || !removedSuffix {
		t.Errorf("want added + removed rule deltas for the kind flip: %+v", d.Deltas)
	}
}

// TestDiff_ServingFlipIsRiskIncreasing pins the Codex fix: enabling a disabled
// DIRECT-capable profile (404 → served) is a newly-reachable bypass surface even
// with unchanged DIRECT paths; disabling it is risk-reducing.
func TestDiff_ServingFlipIsRiskIncreasing(t *testing.T) {
	disabled := prof("a", ModeAvailability, PrivateProxy)
	disabled.Enabled = false
	enabled := prof("a", ModeAvailability, PrivateProxy) // same paths, Enabled=true

	// disabled → enabled: risk-increasing "served".
	d := DiffDirectInventory(invOf(disabled), invOf(enabled))
	if !d.RiskIncreased {
		t.Errorf("disabled→enabled DIRECT-capable profile must flag risk increased: %+v", d)
	}
	var served bool
	for _, x := range d.Deltas {
		if x.Change == ChangeProfileServed && x.RiskIncreasing {
			served = true
		}
	}
	if !served {
		t.Errorf("want a risk-increasing profile_served delta: %+v", d.Deltas)
	}

	// enabled → disabled: risk-reducing "unserved".
	d2 := DiffDirectInventory(invOf(enabled), invOf(disabled))
	if d2.RiskIncreased {
		t.Errorf("enabled→disabled must not flag risk increased: %+v", d2)
	}
	var unserved bool
	for _, x := range d2.Deltas {
		if x.Change == ChangeProfileUnserved && !x.RiskIncreasing {
			unserved = true
		}
	}
	if !unserved {
		t.Errorf("want a non-risk profile_unserved delta: %+v", d2.Deltas)
	}
}

// TestDiff_Deterministic proves the delta ordering is stable across runs.
func TestDiff_Deterministic(t *testing.T) {
	before := invOf(prof("a", ModeBalanced, PrivateProxy))
	after := invOf(
		prof("c", ModeAvailability, PrivateDirect),
		prof("a", ModeBalanced, PrivateProxy),
		prof("b", ModeBalanced, PrivateDirect),
	)
	first := DiffDirectInventory(before, after)
	for i := 0; i < 5; i++ {
		next := DiffDirectInventory(before, after)
		if len(next.Deltas) != len(first.Deltas) {
			t.Fatalf("delta count not stable: %d vs %d", len(next.Deltas), len(first.Deltas))
		}
		for j := range first.Deltas {
			if next.Deltas[j] != first.Deltas[j] {
				t.Fatalf("delta order not stable at %d: %+v vs %+v", j, next.Deltas[j], first.Deltas[j])
			}
		}
	}
}
