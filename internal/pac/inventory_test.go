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
	// EVERY profile carries the unconditional plain-host DIRECT bypass, so all
	// 5 are direct-capable (secure included — it neutralizes only rules/private/
	// availability, not the plain-host guard).
	if inv.DirectCapableProfiles != 5 {
		t.Errorf("DirectCapableProfiles = %d, want 5 (plain-host is universal)", inv.DirectCapableProfiles)
	}
	// dr is disabled, so serving-direct = safe + hq + locked + br = 4.
	if inv.ServingDirectProfiles != 4 {
		t.Errorf("ServingDirectProfiles = %d, want 4 (dr is disabled)", inv.ServingDirectProfiles)
	}
	// Each profile +1 plain-host; hq +wildcard +private; dr +availability;
	// br +cidr; locked (secure) plain-host only → 1+3+2+1+2 = 9.
	if inv.TotalDirectPaths != 9 {
		t.Errorf("TotalDirectPaths = %d, want 9", inv.TotalDirectPaths)
	}
	// broad: hq wildcard + hq private + dr availability = 3 (plain-host and the
	// /24 CIDR are not broad).
	if inv.BroadDirectPaths != 3 {
		t.Errorf("BroadDirectPaths = %d, want 3", inv.BroadDirectPaths)
	}

	byID := map[string]ProfileDirectInventory{}
	for _, p := range inv.Profiles {
		byID[p.ProfileID] = p
	}
	// A proxy-only profile still bypasses for dotless hosts → exactly the
	// plain-host path, not broad.
	if !byID["safe"].DirectCapable || len(byID["safe"].DirectPaths) != 1 ||
		byID["safe"].DirectPaths[0].Kind != BypassPlainHost || byID["safe"].DirectPaths[0].Broad {
		t.Errorf("proxy-only profile must expose exactly the plain-host bypass: %+v", byID["safe"])
	}
	// Secure mode neutralizes rules/private/availability but keeps plain-host.
	if !byID["locked"].DirectCapable || len(byID["locked"].DirectPaths) != 1 ||
		byID["locked"].DirectPaths[0].Kind != BypassPlainHost {
		t.Errorf("secure profile must expose only the plain-host bypass: %+v", byID["locked"])
	}
	if !byID["dr"].DirectCapable || byID["dr"].Serving {
		t.Errorf("dr must be DIRECT-capable but not serving: %+v", byID["dr"])
	}
	if got := len(byID["hq"].DirectPaths); got != 3 {
		t.Errorf("hq DirectPaths = %d, want 3 (plain-host + wildcard + private)", got)
	}
	// br: plain-host + one /24 CIDR path; the CIDR path is not broad.
	brPaths := byID["br"].DirectPaths
	var cidr *DirectEntry
	for i := range brPaths {
		if brPaths[i].Kind == BypassRule {
			cidr = &brPaths[i]
		}
	}
	if len(brPaths) != 2 || cidr == nil || cidr.Broad {
		t.Errorf("br should be plain-host + one non-broad /24 rule: %+v", brPaths)
	}
}

// TestBuildDirectInventory_DropsInvalidRules pins F3: a DIRECT rule the
// compiler would drop for an invalid pattern must NOT be inventoried (the
// inventory must match what the compiled PAC actually emits).
func TestBuildDirectInventory_DropsInvalidRules(t *testing.T) {
	cfg := ProfilesConfig{
		Pools: []Pool{{ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}},
		Profiles: []Profile{
			{ID: "bad", Name: "Bad", Enabled: true, PoolID: "p",
				PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
				Rules: []Rule{
					{Kind: RuleKindCIDR4, Pattern: "not-a-cidr", Action: ActionDirect},
					{Kind: RuleKindWildcard, Pattern: "bad\"quote", Action: ActionDirect},
					{Kind: "bogus-kind", Pattern: "x.example", Action: ActionDirect},
					{Kind: RuleKindDomain, Pattern: "", Action: ActionDirect},
					// One VALID rule survives.
					{Kind: RuleKindDomain, Pattern: "ok.example", Action: ActionDirect},
				}},
		},
	}
	inv := BuildDirectInventory(cfg)
	p := inv.Profiles[0]
	// plain-host + exactly one valid direct_rule = 2 paths (the four invalid
	// rules are dropped, matching the compiler).
	if len(p.DirectPaths) != 2 {
		t.Fatalf("DirectPaths = %d, want 2 (plain-host + one valid rule); got %+v", len(p.DirectPaths), p.DirectPaths)
	}
	var ruleCount int
	for i := range p.DirectPaths {
		if p.DirectPaths[i].Kind == BypassRule {
			ruleCount++
			if p.DirectPaths[i].Pattern != "ok.example" {
				t.Errorf("surviving rule pattern = %q, want ok.example", p.DirectPaths[i].Pattern)
			}
		}
	}
	if ruleCount != 1 {
		t.Errorf("direct_rule entries = %d, want 1", ruleCount)
	}
	if inv.BroadDirectPaths != 0 {
		t.Errorf("BroadDirectPaths = %d, want 0 (the dropped wildcard must not be counted broad)", inv.BroadDirectPaths)
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
