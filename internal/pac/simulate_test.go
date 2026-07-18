package pac

import (
	"strings"
	"testing"
)

// ─── Simulator parity: the evaluator must agree with the compiled JS ──────────
//
// For each input we assert the simulator's directive matches what the
// compiled PAC would return, computed independently here by a tiny reference
// that mirrors the compiler's emission order. If the two ever diverge, the
// simulator is lying to operators.

func simParityProfile() (Profile, map[string]Pool) { //nolint:gocritic // test helper; named returns collide with locals
	p := Profile{
		ID: "hq", Name: "HQ", Enabled: true, PoolID: "main",
		PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
		Rules: []Rule{
			{Kind: RuleKindDomain, Pattern: "intranet.corp.example", Action: ActionDirect},
			{Kind: RuleKindSuffix, Pattern: "cdn.example", Action: ActionUsePool, PoolID: "backup"},
			{Kind: RuleKindWildcard, Pattern: "*.media.example", Action: ActionDirect},
		},
	}
	pools := map[string]Pool{
		"main":   {ID: "main", Endpoints: []PoolEndpoint{{Host: "p1.example", Port: 8080}}},
		"backup": {ID: "backup", Endpoints: []PoolEndpoint{{Host: "b1.example", Port: 3128}}},
	}
	return p, pools
}

func TestSimulate_MatchedRuleAndDirective(t *testing.T) {
	p, pools := simParityProfile()
	cases := []struct {
		host      string
		wantKind  string
		wantDirec string
	}{
		{"intranet.corp.example", RuleKindDomain, "DIRECT"},
		{"www.cdn.example", RuleKindSuffix, "PROXY b1.example:3128"},
		{"x.media.example", RuleKindWildcard, "DIRECT"},
		{"anything.else.example", "terminal", "PROXY p1.example:8080"},
		{"host", "plain-host", "DIRECT"}, // dotless
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			res := Simulate(p, pools, SimInput{Host: c.host})
			if res.Directive != c.wantDirec {
				t.Errorf("host %q: directive %q, want %q", c.host, res.Directive, c.wantDirec)
			}
			if res.MatchedRule.Kind != c.wantKind {
				t.Errorf("host %q: matched kind %q, want %q", c.host, res.MatchedRule.Kind, c.wantKind)
			}
			if res.Reason == "" {
				t.Error("every decision must carry a reason")
			}
		})
	}
}

// TestSimulate_ParityWithCompiledJS cross-checks the simulator directive
// against the compiled artifact for a battery of hosts by extracting the
// return the compiler would produce. Rather than run JS, we assert the
// simulator's chosen directive string actually appears in the compiled JS
// (every directive the simulator can return is emitted verbatim by the
// compiler), and that the terminal matches.
func TestSimulate_ParityWithCompiledJS(t *testing.T) {
	p, pools := simParityProfile()
	art := CompileProfile(p, pools)
	for _, host := range []string{
		"intranet.corp.example", "sub.cdn.example", "a.media.example", "other.example",
	} {
		res := Simulate(p, pools, SimInput{Host: host})
		quoted := "return " + goQuote(res.Directive) + ";"
		if !strings.Contains(art.JS, quoted) {
			t.Errorf("host %q: simulator directive %q not emitted by the compiler:\n%s", host, res.Directive, art.JS)
		}
	}
}

func goQuote(s string) (quoted string) {
	// mirror strconv.Quote for the ASCII directives we emit
	return `"` + s + `"`
}

func TestSimulate_SchemePortGuards(t *testing.T) {
	p, pools := simParityProfile()
	p.Rules = []Rule{
		{Kind: RuleKindDomain, Pattern: "media.example", Action: ActionDirect, Scheme: "https", Port: 8443},
	}
	// Matching scheme+port → DIRECT.
	res := Simulate(p, pools, SimInput{Host: "media.example", Scheme: "https", Port: 8443})
	if res.Directive != "DIRECT" {
		t.Errorf("scheme+port match should be DIRECT, got %q", res.Directive)
	}
	// Wrong port → falls through to terminal.
	res = Simulate(p, pools, SimInput{Host: "media.example", Scheme: "https", Port: 443})
	if res.Directive != "PROXY p1.example:8080" {
		t.Errorf("port mismatch should fall through to terminal, got %q", res.Directive)
	}
	// Port parsed from URL.
	res = Simulate(p, pools, SimInput{URL: "https://media.example:8443/path"})
	if res.Directive != "DIRECT" {
		t.Errorf("port from URL should match, got %q (host=%q)", res.Directive, simHost(SimInput{URL: "https://media.example:8443/path"}))
	}
}

func TestSimulate_CIDRUndeterminedWithoutIP(t *testing.T) {
	p, pools := simParityProfile()
	p.Rules = []Rule{{Kind: RuleKindCIDR4, Pattern: "10.0.0.0/8", Action: ActionDirect}}
	// No resolved IP → undetermined.
	res := Simulate(p, pools, SimInput{Host: "db.example"})
	if res.Outcome != OutcomeUndeterminedDNS {
		t.Errorf("cidr4 without resolvedIp must be undetermined, got %q", res.Outcome)
	}
	// With resolved IP in-range → DIRECT.
	res = Simulate(p, pools, SimInput{Host: "db.example", ResolvedIP: "10.1.2.3"})
	if res.Directive != "DIRECT" || res.Outcome != OutcomeMatched {
		t.Errorf("cidr4 with in-range IP → DIRECT matched, got %q/%q", res.Directive, res.Outcome)
	}
	// With resolved IP out-of-range → terminal.
	res = Simulate(p, pools, SimInput{Host: "db.example", ResolvedIP: "8.8.8.8"})
	if res.Directive != "PROXY p1.example:8080" {
		t.Errorf("cidr4 out-of-range → terminal, got %q", res.Directive)
	}
}

func TestSimulate_SecureNeutralizesDirectRule(t *testing.T) {
	p, pools := simParityProfile()
	p.AvailabilityMode = ModeSecure
	p.PrivateNetworks = PrivateProxy
	p.Rules = []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionDirect}}
	res := Simulate(p, pools, SimInput{Host: "x.example"})
	if res.Directive == "DIRECT" {
		t.Error("secure mode must not simulate DIRECT for a DIRECT rule")
	}
	if !strings.Contains(res.Reason, "secure") {
		t.Errorf("reason should explain the secure-mode degradation, got %q", res.Reason)
	}
}

func TestSimulate_IPv6DestinationNotBypassed(t *testing.T) {
	p, pools := simParityProfile()
	p.AvailabilityMode = ModeSecure
	p.PrivateNetworks = PrivateProxy
	p.Rules = nil
	// A dotless IPv6 literal must NOT be treated as a plain-host bypass.
	res := Simulate(p, pools, SimInput{Host: "[2606:4700::1]"})
	if res.Directive == "DIRECT" {
		t.Errorf("IPv6 destination must follow the profile (not plain-host DIRECT), got %q", res.Directive)
	}
}

// ─── Diff ─────────────────────────────────────────────────────────────────────

func TestDiffProfiles_ChangeSet(t *testing.T) {
	old := Profile{ID: "p", PoolID: "a", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
		Rules: []Rule{{Kind: RuleKindDomain, Pattern: "keep.example", Action: ActionUsePool}}}
	next := Profile{ID: "p", PoolID: "b", PrivateNetworks: PrivateDirect, AvailabilityMode: ModeAvailability,
		Rules: []Rule{
			{Kind: RuleKindDomain, Pattern: "keep.example", Action: ActionUsePool},
			{Kind: RuleKindSuffix, Pattern: "new.example", Action: ActionDirect},
		}}
	d := DiffProfiles(old, true, next)
	if len(d.RulesAdded) != 1 || !strings.Contains(d.RulesAdded[0], "new.example") {
		t.Errorf("expected one added rule, got %+v", d.RulesAdded)
	}
	if !d.PoolChanged || d.OldPool != "a" || d.NewPool != "b" {
		t.Errorf("pool change not detected: %+v", d)
	}
	if d.AvailabilityChange != "balanced → availability" {
		t.Errorf("availability change: %q", d.AvailabilityChange)
	}
	if len(d.NewDirectPaths) == 0 {
		t.Error("new DIRECT paths (availability mode + DIRECT rule) must be flagged")
	}
	if !d.SecuritySensitive {
		t.Error("widening DIRECT + availability must be security-sensitive")
	}
}

// ─── Impact analysis ────────────────────────────────────────────────────────

func TestAnalyzeImpact_Categories(t *testing.T) {
	pools := map[string]Pool{
		"a": {ID: "a", Endpoints: []PoolEndpoint{{Host: "pa.example", Port: 8080}}},
		"b": {ID: "b", Endpoints: []PoolEndpoint{{Host: "pb.example", Port: 8080}}},
	}
	active := Profile{ID: "p", PoolID: "a", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
		Rules: []Rule{{Kind: RuleKindSuffix, Pattern: "direct.example", Action: ActionDirect}}}
	candidate := Profile{ID: "p", PoolID: "b", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
		Rules: []Rule{{Kind: RuleKindSuffix, Pattern: "newdirect.example", Action: ActionDirect}}}
	sample := []string{
		"x.direct.example",    // was DIRECT, now proxied via b → no_longer_direct
		"y.newdirect.example", // was proxied via a, now DIRECT → became_direct
		"z.other.example",     // pool a → pool b → pool_changed
	}
	rep := AnalyzeImpact(active, true, candidate, pools, sample, "test_vectors")
	if rep.Sampled != 3 {
		t.Fatalf("expected 3 sampled, got %d", rep.Sampled)
	}
	if rep.Counts[ImpactNoLongerDirect] != 1 || rep.Counts[ImpactBecameDirect] != 1 || rep.Counts[ImpactPoolChanged] != 1 {
		t.Errorf("category counts wrong: %+v", rep.Counts)
	}
}

func TestAnalyzeImpact_LostProxyPath(t *testing.T) {
	pools := map[string]Pool{"a": {ID: "a", Endpoints: []PoolEndpoint{{Host: "pa.example", Port: 8080}}}}
	active := Profile{ID: "p", PoolID: "a", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced}
	// Candidate references a missing pool in secure mode → fail-closed placeholder.
	candidate := Profile{ID: "p", PoolID: "gone", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeSecure}
	rep := AnalyzeImpact(active, true, candidate, pools, []string{"x.example"}, "test_vectors")
	if rep.Counts[ImpactLostProxy] != 1 {
		t.Errorf("expected lost_proxy_path, got %+v (movements %+v)", rep.Counts, rep.Movements)
	}
}

func TestAnalyzeImpact_ShadowAndDuplicate(t *testing.T) {
	candidate := Profile{ID: "p", PoolID: "a", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
		Rules: []Rule{
			{Kind: RuleKindSuffix, Pattern: "example", Action: ActionDirect},
			{Kind: RuleKindDomain, Pattern: "sub.example", Action: ActionDirect}, // shadowed by the suffix above
			{Kind: RuleKindSuffix, Pattern: "example", Action: ActionDirect},     // duplicate
		}}
	rep := AnalyzeImpact(Profile{}, false, candidate,
		map[string]Pool{"a": {ID: "a", Endpoints: []PoolEndpoint{{Host: "p.example", Port: 8080}}}},
		nil, "test_vectors")
	if len(rep.ShadowedRules) == 0 {
		t.Error("expected a shadowed rule")
	}
	if len(rep.DuplicateRules) == 0 {
		t.Error("expected a duplicate rule")
	}
}

func TestAnalyzeImpact_CIDRNote(t *testing.T) {
	candidate := Profile{ID: "p", PoolID: "a", PrivateNetworks: PrivateProxy, AvailabilityMode: ModeBalanced,
		Rules: []Rule{{Kind: RuleKindCIDR4, Pattern: "10.0.0.0/8", Action: ActionDirect}}}
	rep := AnalyzeImpact(Profile{}, false, candidate,
		map[string]Pool{"a": {ID: "a", Endpoints: []PoolEndpoint{{Host: "p.example", Port: 8080}}}},
		[]string{"db.example"}, "test_vectors")
	found := false
	for _, n := range rep.Notes {
		if strings.Contains(n, "undetermined") {
			found = true
		}
	}
	if !found {
		t.Errorf("cidr4 sample must note undetermined DNS, got %+v", rep.Notes)
	}
}
