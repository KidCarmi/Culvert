package pac

// inventory_parity_test.go — behavioral proof that the DIRECT bypass inventory
// (BuildDirectInventory) tells the truth about what the compiled PAC actually
// does. The security-critical invariant is ONE-DIRECTIONAL:
//
//	if the evaluator (Simulate — the parity-proven twin of the compiler) can
//	return DIRECT for some (profile, input), the inventory MUST flag that
//	profile DIRECT-capable.
//
// Under-reporting is a false sense of security (a real full-security-path
// bypass an operator cannot see); over-reporting is only noise. These tests
// drive Simulate over a config × input matrix and cross-check the inventory,
// then prove the specific DIRECT mechanisms (plain-host, private-networks,
// direct rule, availability fail-open) each resolve to a real DIRECT.

import (
	"fmt"
	"testing"
)

// simInputs is the battery of destinations exercised against every profile.
// ResolvedIP is supplied where a rule needs it so cidr4/private evaluate
// definitely (not OutcomeUndeterminedDNS).
var simInputs = []struct {
	name string
	in   SimInput
}{
	{"plain dotless host", SimInput{Host: "intranet"}},
	{"public host", SimInput{Host: "www.example.com", ResolvedIP: "8.8.8.8"}},
	{"domain-rule host", SimInput{Host: "direct.example", ResolvedIP: "8.8.8.8"}},
	{"wildcard-rule host", SimInput{Host: "foo.cdn.example", ResolvedIP: "8.8.8.8"}},
	{"private-ip host", SimInput{Host: "db.corp.example", ResolvedIP: "10.0.0.5"}},
	{"cidr-rule host", SimInput{Host: "svc.corp.example", ResolvedIP: "10.9.9.9"}},
}

// buildProfileMatrix returns a representative cross-product of profiles: every
// availability mode × private-network setting × a few rule shapes.
func buildProfileMatrix() (profiles []Profile, pools map[string]Pool) {
	pools = map[string]Pool{"p": {ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}}
	modes := []string{ModeSecure, ModeBalanced, ModeAvailability}
	privs := []string{PrivateProxy, PrivateDirect}
	ruleSets := map[string][]Rule{
		"norules": nil,
		"domain-direct": {
			{Kind: RuleKindDomain, Pattern: "direct.example", Action: ActionDirect},
		},
		"wildcard-direct": {
			{Kind: RuleKindWildcard, Pattern: "*.cdn.example", Action: ActionDirect},
		},
		"cidr-direct": {
			{Kind: RuleKindCIDR4, Pattern: "10.0.0.0/16", Action: ActionDirect},
		},
		"usepool-only": {
			{Kind: RuleKindDomain, Pattern: "route.example", Action: ActionUsePool, PoolID: "p"},
		},
	}
	for _, mode := range modes {
		for _, priv := range privs {
			for rs, rules := range ruleSets {
				id := fmt.Sprintf("%s-%s-%s", mode, priv, rs)
				profiles = append(profiles, Profile{
					ID: id, Name: id, Enabled: true, PoolID: "p",
					PrivateNetworks: priv, AvailabilityMode: mode, Revision: 1, Rules: rules,
				})
			}
		}
	}
	return profiles, pools
}

// TestInventory_NeverUnderReportsDirect is the headline invariant: for every
// profile in the matrix, if ANY input drives Simulate to a definite DIRECT (or
// a DirectPossible terminal such as availability fail-open), the inventory must
// mark that profile DIRECT-capable. A violation is a hidden full-security-path
// bypass.
func TestInventory_NeverUnderReportsDirect(t *testing.T) {
	profs, pools := buildProfileMatrix()
	cfg := ProfilesConfig{Pools: []Pool{pools["p"]}, Profiles: profs}
	inv := BuildDirectInventory(cfg)
	byID := map[string]ProfileDirectInventory{}
	for i := range inv.Profiles {
		byID[inv.Profiles[i].ProfileID] = inv.Profiles[i]
	}

	for i := range profs {
		p := profs[i]
		var directWhy []string
		for _, tc := range simInputs {
			r := Simulate(p, pools, tc.in)
			if r.Outcome == OutcomeMatched && r.Directive == "DIRECT" {
				directWhy = append(directWhy, tc.name+"→DIRECT")
			} else if r.DirectPossible {
				// e.g. availability terminal "PROXY …; DIRECT" (fail-open).
				directWhy = append(directWhy, tc.name+"→DirectPossible("+r.Directive+")")
			}
		}
		pinv, ok := byID[p.ID]
		if !ok {
			t.Errorf("profile %q missing from inventory", p.ID)
			continue
		}
		if len(directWhy) > 0 && !pinv.DirectCapable {
			t.Errorf("UNDER-REPORT: profile %q yields DIRECT via %v but inventory says not DIRECT-capable (%+v)",
				p.ID, directWhy, pinv.DirectPaths)
		}
	}
}

// TestInventory_ReportsEachMechanism proves each DIRECT source the inventory
// names corresponds to a real DIRECT from the evaluator, and that the source
// kind is present in the inventory for the profile that has it.
func TestInventory_ReportsEachMechanism(t *testing.T) {
	pools := map[string]Pool{"p": {ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}}

	type tc struct {
		name       string
		profile    Profile
		input      SimInput
		wantKind   DirectBypassKind
		wantDirect bool // Simulate must return a definite "DIRECT"
	}
	cases := []tc{
		{
			name:       "plain-host in secure mode still DIRECT",
			profile:    Profile{ID: "a", Enabled: true, PoolID: "p", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeSecure},
			input:      SimInput{Host: "intranet"},
			wantKind:   BypassPlainHost,
			wantDirect: true,
		},
		{
			name:       "private-networks=direct sends RFC-1918 DIRECT",
			profile:    Profile{ID: "b", Enabled: true, PoolID: "p", PrivateNetworks: PrivateDirect, AvailabilityMode: ModeBalanced},
			input:      SimInput{Host: "db.corp.example", ResolvedIP: "10.0.0.5"},
			wantKind:   BypassPrivate,
			wantDirect: true,
		},
		{
			name:       "explicit direct rule",
			profile:    Profile{ID: "c", Enabled: true, PoolID: "p", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced, Rules: []Rule{{Kind: RuleKindDomain, Pattern: "vendor.example", Action: ActionDirect}}},
			input:      SimInput{Host: "vendor.example", ResolvedIP: "8.8.8.8"},
			wantKind:   BypassRule,
			wantDirect: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Simulate(c.profile, pools, c.input)
			if c.wantDirect && (r.Outcome != OutcomeMatched || r.Directive != "DIRECT") {
				t.Fatalf("evaluator did not return DIRECT: %+v", r)
			}
			inv := BuildDirectInventory(ProfilesConfig{Pools: []Pool{pools["p"]}, Profiles: []Profile{c.profile}})
			paths := inv.Profiles[0].DirectPaths
			found := false
			for _, d := range paths {
				if d.Kind == c.wantKind {
					found = true
				}
			}
			if !found {
				t.Errorf("inventory missing %q source; got %+v", c.wantKind, paths)
			}
		})
	}
}

// TestInventory_AvailabilityFailOpenIsReportedAndReal proves the availability
// terminal appends DIRECT (fail-open) and the inventory flags it broad.
func TestInventory_AvailabilityFailOpenIsReportedAndReal(t *testing.T) {
	pools := map[string]Pool{"p": {ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}}
	p := Profile{ID: "dr", Enabled: true, PoolID: "p", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeAvailability}

	// A public host that matches no rule hits the terminal.
	r := Simulate(p, pools, SimInput{Host: "www.example.com", ResolvedIP: "8.8.8.8"})
	if !r.DirectPossible {
		t.Fatalf("availability terminal must be DirectPossible (fail-open): %+v", r)
	}
	inv := BuildDirectInventory(ProfilesConfig{Pools: []Pool{pools["p"]}, Profiles: []Profile{p}})
	var av *DirectEntry
	for i := range inv.Profiles[0].DirectPaths {
		if inv.Profiles[0].DirectPaths[i].Kind == BypassAvailability {
			av = &inv.Profiles[0].DirectPaths[i]
		}
	}
	if av == nil {
		t.Fatalf("availability_mode source missing: %+v", inv.Profiles[0].DirectPaths)
	}
	if !av.Broad {
		t.Errorf("availability fail-open must be flagged broad (all-destination bypass)")
	}
}

// TestInventory_CountsAreConsistent proves the aggregate counters equal the
// per-profile facts they summarize (no double-count / off-by-one).
func TestInventory_CountsAreConsistent(t *testing.T) {
	profs, pools := buildProfileMatrix()
	// Disable one profile to exercise serving vs capable divergence.
	profs = append(profs, Profile{ID: "disabled-cap", Name: "disabled", Enabled: false, PoolID: "p",
		PrivateNetworks: PrivateDirect, AvailabilityMode: ModeAvailability, Revision: 1})
	inv := BuildDirectInventory(ProfilesConfig{Pools: []Pool{pools["p"]}, Profiles: profs})

	var totalPaths, broadPaths, capable, serving int
	for i := range inv.Profiles {
		p := inv.Profiles[i]
		totalPaths += len(p.DirectPaths)
		for _, d := range p.DirectPaths {
			if d.Broad {
				broadPaths++
			}
		}
		if p.DirectCapable {
			capable++
			if p.Serving {
				serving++
			}
		}
	}
	if inv.TotalProfiles != len(profs) {
		t.Errorf("TotalProfiles = %d, want %d", inv.TotalProfiles, len(profs))
	}
	if inv.TotalDirectPaths != totalPaths {
		t.Errorf("TotalDirectPaths = %d, want %d (sum of per-profile paths)", inv.TotalDirectPaths, totalPaths)
	}
	if inv.BroadDirectPaths != broadPaths {
		t.Errorf("BroadDirectPaths = %d, want %d", inv.BroadDirectPaths, broadPaths)
	}
	if inv.DirectCapableProfiles != capable {
		t.Errorf("DirectCapableProfiles = %d, want %d", inv.DirectCapableProfiles, capable)
	}
	if inv.ServingDirectProfiles != serving {
		t.Errorf("ServingDirectProfiles = %d, want %d", inv.ServingDirectProfiles, serving)
	}
	// The disabled profile is capable (availability + private) but not serving.
	byID := map[string]ProfileDirectInventory{}
	for i := range inv.Profiles {
		byID[inv.Profiles[i].ProfileID] = inv.Profiles[i]
	}
	if d := byID["disabled-cap"]; !d.DirectCapable || d.Serving {
		t.Errorf("disabled-cap must be capable-but-not-serving: %+v", d)
	}
}

// TestInventory_InvalidDirectRuleParity proves the over-report fix matches the
// evaluator: a DIRECT rule with an invalid pattern is dropped by the compiler
// (Simulate does not return DIRECT via it) AND is not inventoried.
func TestInventory_InvalidDirectRuleParity(t *testing.T) {
	pools := map[string]Pool{"p": {ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}}
	p := Profile{ID: "bad", Enabled: true, PoolID: "p", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
		Rules: []Rule{{Kind: RuleKindCIDR4, Pattern: "not-a-cidr", Action: ActionDirect}}}

	// The evaluator must NOT produce a DIRECT for a would-be target of the
	// broken rule (it only bypasses via plain-host, which this host is not).
	r := Simulate(p, pools, SimInput{Host: "target.example", ResolvedIP: "8.8.8.8"})
	if r.Directive == "DIRECT" {
		t.Errorf("invalid CIDR direct rule must not yield DIRECT: %+v", r)
	}
	// The inventory must not list the dropped rule → only plain_host remains.
	inv := BuildDirectInventory(ProfilesConfig{Pools: []Pool{pools["p"]}, Profiles: []Profile{p}})
	for _, d := range inv.Profiles[0].DirectPaths {
		if d.Kind == BypassRule {
			t.Errorf("dropped invalid rule must not be inventoried: %+v", d)
		}
	}
}

// TestInventory_SecureModeNeutralizesButKeepsPlainHost proves secure mode is
// reduced to plain-host only — a DIRECT rule in the spec does NOT produce a
// DIRECT (compiler neutralizes it), and the inventory agrees.
func TestInventory_SecureModeNeutralizesButKeepsPlainHost(t *testing.T) {
	pools := map[string]Pool{"p": {ID: "p", Name: "P", Endpoints: []PoolEndpoint{{Host: "proxy.example", Port: 8080}}}}
	p := Profile{ID: "locked", Enabled: true, PoolID: "p", PrivateNetworks: PrivateDirect, AvailabilityMode: ModeSecure,
		Rules: []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionDirect}}}

	// The DIRECT rule host must NOT be DIRECT in secure mode.
	r := Simulate(p, pools, SimInput{Host: "x.example", ResolvedIP: "8.8.8.8"})
	if r.Directive == "DIRECT" {
		t.Errorf("secure mode must neutralize the DIRECT rule; got %+v", r)
	}
	// A private IP must NOT be DIRECT in secure mode either.
	rp := Simulate(p, pools, SimInput{Host: "db.corp.example", ResolvedIP: "10.0.0.5"})
	if rp.Directive == "DIRECT" {
		t.Errorf("secure mode must neutralize the private-network bypass; got %+v", rp)
	}
	// But a plain host still bypasses.
	rh := Simulate(p, pools, SimInput{Host: "intranet"})
	if rh.Directive != "DIRECT" {
		t.Errorf("plain host must still be DIRECT even in secure mode; got %+v", rh)
	}
	// Inventory: exactly the plain-host source.
	inv := BuildDirectInventory(ProfilesConfig{Pools: []Pool{pools["p"]}, Profiles: []Profile{p}})
	paths := inv.Profiles[0].DirectPaths
	if len(paths) != 1 || paths[0].Kind != BypassPlainHost {
		t.Errorf("secure profile must expose only plain_host; got %+v", paths)
	}
}
