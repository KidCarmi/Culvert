package pac

import "testing"

func TestBuildDirectInventory(t *testing.T) {
	cfg := ProfilesConfig{
		Pools: []Pool{{ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}},
		Profiles: []Profile{
			// Fully proxied, enabled → no DIRECT.
			{ID: "safe", Name: "Safe", Enabled: true, PoolID: "p",
				PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced},
			// Enabled, DIRECT rule (broad wildcard) + private-direct → 2 paths, both broad.
			{ID: "hq", Name: "HQ", Enabled: true, PoolID: "p",
				PrivateNetworks: PrivateDirect, AvailabilityMode: ModeBalanced,
				Rules: []Rule{{Kind: RuleKindWildcard, Pattern: "*.cdn.example", Action: ActionDirect}}},
			// Disabled availability profile → DIRECT-capable but NOT serving.
			{ID: "dr", Name: "DR", Enabled: false, PoolID: "p",
				PrivateNetworks: PrivateProxy, AvailabilityMode: ModeAvailability},
			// Secure mode → DIRECT neutralized even with a DIRECT rule in spec.
			{ID: "locked", Name: "Locked", Enabled: true, PoolID: "p",
				PrivateNetworks: PrivateProxy, AvailabilityMode: ModeSecure,
				Rules: []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionDirect}}},
			// Narrow CIDR DIRECT rule → a path, but NOT broad (/24).
			{ID: "br", Name: "Branch", Enabled: true, PoolID: "p",
				PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
				Rules: []Rule{{Kind: RuleKindCIDR4, Pattern: "10.1.2.0/24", Action: ActionDirect}}},
		},
	}
	inv := BuildDirectInventory(cfg)

	if inv.EvidenceClass != "config" {
		t.Errorf("evidence class must be config (Observable), got %q", inv.EvidenceClass)
	}
	if inv.TotalProfiles != 5 {
		t.Errorf("TotalProfiles = %d, want 5", inv.TotalProfiles)
	}
	// hq, dr, br are direct-capable; safe + locked (secure) are not.
	if inv.DirectCapableProfiles != 3 {
		t.Errorf("DirectCapableProfiles = %d, want 3", inv.DirectCapableProfiles)
	}
	// dr is disabled, so serving-direct = hq + br = 2.
	if inv.ServingDirectProfiles != 2 {
		t.Errorf("ServingDirectProfiles = %d, want 2 (dr is disabled)", inv.ServingDirectProfiles)
	}
	// hq: wildcard rule + private = 2; dr: availability = 1; br: cidr rule = 1 → 4.
	if inv.TotalDirectPaths != 4 {
		t.Errorf("TotalDirectPaths = %d, want 4", inv.TotalDirectPaths)
	}
	// broad: hq wildcard + hq private + dr availability = 3 (br /24 is narrow).
	if inv.BroadDirectPaths != 3 {
		t.Errorf("BroadDirectPaths = %d, want 3", inv.BroadDirectPaths)
	}

	byID := map[string]ProfileDirectInventory{}
	for _, p := range inv.Profiles {
		byID[p.ProfileID] = p
	}
	if byID["safe"].DirectCapable {
		t.Error("proxy-only profile must not be DIRECT-capable")
	}
	if byID["locked"].DirectCapable {
		t.Error("secure-mode profile must not be DIRECT-capable (DIRECT neutralized)")
	}
	if !byID["dr"].DirectCapable || byID["dr"].Serving {
		t.Errorf("dr must be DIRECT-capable but not serving: %+v", byID["dr"])
	}
	if got := len(byID["hq"].DirectPaths); got != 2 {
		t.Errorf("hq DirectPaths = %d, want 2", got)
	}
	// br's single CIDR path must not be flagged broad (/24).
	brPaths := byID["br"].DirectPaths
	if len(brPaths) != 1 || brPaths[0].Broad {
		t.Errorf("br /24 rule should be one non-broad path: %+v", brPaths)
	}
}

func TestRuleIsBroad(t *testing.T) {
	cases := []struct {
		r    Rule
		want bool
	}{
		{Rule{Kind: RuleKindWildcard, Pattern: "*.example"}, true},
		{Rule{Kind: RuleKindCIDR4, Pattern: "10.0.0.0/8"}, true},
		{Rule{Kind: RuleKindCIDR4, Pattern: "172.16.0.0/16"}, true},
		{Rule{Kind: RuleKindCIDR4, Pattern: "192.168.1.0/24"}, false},
		{Rule{Kind: RuleKindCIDR4, Pattern: "10.0.0.0/17"}, false},
		{Rule{Kind: RuleKindDomain, Pattern: "example.com"}, false},
		{Rule{Kind: RuleKindSuffix, Pattern: "example.com"}, false},
		{Rule{Kind: RuleKindCIDR4, Pattern: "bogus"}, false},
	}
	for _, c := range cases {
		if got := ruleIsBroad(&c.r); got != c.want {
			t.Errorf("ruleIsBroad(%s %s) = %v, want %v", c.r.Kind, c.r.Pattern, got, c.want)
		}
	}
}
