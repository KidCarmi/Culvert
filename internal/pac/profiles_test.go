package pac

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testPools() []Pool {
	return []Pool{
		{ID: "il-prod", Name: "Israel Production", Endpoints: []PoolEndpoint{
			{Host: "culvert-il-vip", Port: 8080}, {Host: "culvert-eu-vip", Port: 8080}}},
		{ID: "backup", Name: "Backup", Endpoints: []PoolEndpoint{{Host: "backup.example", Port: 3128}}},
	}
}

func testProfile() Profile {
	return Profile{
		ID: "hq-israel", Name: "HQ Israel", Enabled: true, PoolID: "il-prod",
		PrivateNetworks: PrivateDirect, AvailabilityMode: ModeBalanced, Revision: 3,
		Rules: []Rule{
			{Kind: RuleKindDomain, Pattern: "intranet.corp.example", Action: ActionDirect},
			{Kind: RuleKindSuffix, Pattern: "cdn.example", Action: ActionUsePool, PoolID: "backup"},
			{Kind: RuleKindWildcard, Pattern: "*.media.example", Action: ActionUsePool},
			{Kind: RuleKindCIDR4, Pattern: "203.0.113.0/24", Action: ActionDirect},
		},
	}
}

// ─── ProfileStore ─────────────────────────────────────────────────────────────

func TestProfileStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pac_profiles.json")
	s := &ProfileStore{}
	if err := s.Load(path); err != nil {
		t.Fatalf("Load missing: %v", err)
	}
	cfg := ProfilesConfig{Profiles: []Profile{testProfile()}, Pools: testPools()}
	if err := s.Set(cfg); err != nil {
		t.Fatalf("Set: %v", err)
	}

	s2 := &ProfileStore{}
	if err := s2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := s2.Get()
	if len(got.Profiles) != 1 || got.Profiles[0].ID != "hq-israel" || len(got.Pools) != 2 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Profiles[0].Rules[1].PoolID != "backup" {
		t.Errorf("nested rule lost: %+v", got.Profiles[0].Rules)
	}

	// Mutating the returned copy must not affect the store.
	got.Profiles[0].Rules[0].Pattern = "mutated"
	got.Pools[0].Endpoints[0].Host = "mutated"
	fresh := s2.Get()
	if fresh.Profiles[0].Rules[0].Pattern == "mutated" || fresh.Pools[0].Endpoints[0].Host == "mutated" {
		t.Error("Get must deep-copy nested slices")
	}
}

func TestProfileStore_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &ProfileStore{}
	if err := s.Load(path); err == nil {
		t.Error("expected parse error")
	}
}

// ─── Validation ───────────────────────────────────────────────────────────────

func TestValidateProfilesConfig_Valid(t *testing.T) {
	p := testProfile()
	// Balanced mode with DIRECT rules + private direct is legal.
	if issues := ValidateProfilesConfig(ProfilesConfig{Profiles: []Profile{p}, Pools: testPools()}); len(issues) != 0 {
		t.Fatalf("expected valid, got %+v", issues)
	}
	if issues := ValidateProfilesConfig(ProfilesConfig{}); len(issues) != 0 {
		t.Fatalf("empty config must be valid, got %+v", issues)
	}
}

func TestValidateProfilesConfig_Table(t *testing.T) {
	mk := func(mut func(*Profile, *ProfilesConfig)) ProfilesConfig {
		p := testProfile()
		cfg := ProfilesConfig{Pools: testPools()}
		mut(&p, &cfg)
		cfg.Profiles = append(cfg.Profiles, p)
		return cfg
	}
	cases := []struct {
		name string
		cfg  ProfilesConfig
		code string
	}{
		{"reserved default id", mk(func(p *Profile, _ *ProfilesConfig) { p.ID = "default" }), IssueReservedID},
		{"bad id", mk(func(p *Profile, _ *ProfilesConfig) { p.ID = "Bad_ID!" }), IssueInvalidID},
		{"unknown pool", mk(func(p *Profile, _ *ProfilesConfig) { p.PoolID = "nope" }), IssueUnknownPool},
		{"bad mode", mk(func(p *Profile, _ *ProfilesConfig) { p.AvailabilityMode = "yolo" }), IssueInvalidMode},
		{"bad private", mk(func(p *Profile, _ *ProfilesConfig) { p.PrivateNetworks = "maybe" }), IssueInvalidMode},
		{"secure with direct rule", mk(func(p *Profile, _ *ProfilesConfig) {
			p.AvailabilityMode = ModeSecure
			p.PrivateNetworks = PrivateProxy
		}), IssueSecureModeConflict}, // testProfile has DIRECT rules
		{"secure with private direct", mk(func(p *Profile, _ *ProfilesConfig) {
			p.AvailabilityMode = ModeSecure
			p.Rules = nil
		}), IssueSecureModeConflict},
		{"bad rule action", mk(func(p *Profile, _ *ProfilesConfig) {
			p.Rules = []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: "block"}}
		}), IssueInvalidRule},
		{"direct rule with pool", mk(func(p *Profile, _ *ProfilesConfig) {
			p.Rules = []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionDirect, PoolID: "backup"}}
		}), IssueInvalidRule},
		{"rule unknown pool", mk(func(p *Profile, _ *ProfilesConfig) {
			p.Rules = []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionUsePool, PoolID: "nope"}}
		}), IssueInvalidRule},
		{"bad cidr rule", mk(func(p *Profile, _ *ProfilesConfig) {
			p.Rules = []Rule{{Kind: RuleKindCIDR4, Pattern: "300.0.0.0/8", Action: ActionDirect}}
		}), IssueInvalidRule},
		{"bad kind", mk(func(p *Profile, _ *ProfilesConfig) {
			p.Rules = []Rule{{Kind: "regex", Pattern: ".*", Action: ActionDirect}}
		}), IssueInvalidRule},
		{"bad scheme", mk(func(p *Profile, _ *ProfilesConfig) {
			p.Rules = []Rule{{Kind: RuleKindDomain, Pattern: "x.example", Action: ActionDirect, Scheme: "ftp"}}
		}), IssueInvalidRule},
		{"pool no endpoints", mk(func(_ *Profile, cfg *ProfilesConfig) {
			cfg.Pools = append(cfg.Pools, Pool{ID: "empty", Name: "Empty"})
		}), IssueNoEndpoints},
		{"pool too many endpoints", mk(func(_ *Profile, cfg *ProfilesConfig) {
			cfg.Pools = append(cfg.Pools, Pool{ID: "big", Name: "Big", Endpoints: []PoolEndpoint{
				{Host: "a", Port: 1}, {Host: "b", Port: 2}, {Host: "c", Port: 3}, {Host: "d", Port: 4}}})
		}), IssueTooManyEndpoints},
		{"pool bad endpoint host", mk(func(_ *Profile, cfg *ProfilesConfig) {
			cfg.Pools = append(cfg.Pools, Pool{ID: "bad", Name: "Bad",
				Endpoints: []PoolEndpoint{{Host: "bad#host", Port: 8080}}})
		}), IssueInvalidEndpoint},
		{"pool bad endpoint port", mk(func(_ *Profile, cfg *ProfilesConfig) {
			cfg.Pools = append(cfg.Pools, Pool{ID: "badp", Name: "BadP",
				Endpoints: []PoolEndpoint{{Host: "ok.example", Port: 0}}})
		}), IssueInvalidEndpoint},
		{"duplicate pool id", mk(func(_ *Profile, cfg *ProfilesConfig) {
			cfg.Pools = append(cfg.Pools, cfg.Pools[0])
		}), IssueDuplicateID},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			issues := ValidateProfilesConfig(c.cfg)
			for _, is := range issues {
				if is.Code == c.code {
					if is.Message == "" {
						t.Error("issue message must be actionable")
					}
					return
				}
			}
			t.Errorf("expected issue %s, got %+v", c.code, issues)
		})
	}
}

func TestValidateProfilesConfig_DuplicateProfileID(t *testing.T) {
	p := testProfile()
	cfg := ProfilesConfig{Profiles: []Profile{p, p}, Pools: testPools()}
	found := false
	for _, is := range ValidateProfilesConfig(cfg) {
		if is.Code == IssueDuplicateID {
			found = true
		}
	}
	if !found {
		t.Error("expected duplicate_id for duplicated profile")
	}
}

// ─── CompileProfile ───────────────────────────────────────────────────────────

func poolMap() map[string]Pool {
	m := map[string]Pool{}
	for _, p := range testPools() {
		m[p.ID] = p
	}
	return m
}

func TestCompileProfile_FailoverChainAndModes(t *testing.T) {
	p := testProfile()
	p.PrivateNetworks = PrivateProxy

	// Balanced: chain terminal, no DIRECT appended.
	art := CompileProfile(p, poolMap())
	if !strings.Contains(art.JS, `return "PROXY culvert-il-vip:8080; PROXY culvert-eu-vip:8080";`) {
		t.Errorf("balanced terminal must be the bare pool chain:\n%s", art.JS)
	}
	if strings.Contains(art.JS, `PROXY culvert-eu-vip:8080; DIRECT`) {
		t.Error("balanced mode must not append DIRECT to the chain")
	}

	// Availability: chain + DIRECT.
	p.AvailabilityMode = ModeAvailability
	art = CompileProfile(p, poolMap())
	if !strings.Contains(art.JS, `return "PROXY culvert-il-vip:8080; PROXY culvert-eu-vip:8080; DIRECT";`) {
		t.Errorf("availability terminal must append DIRECT:\n%s", art.JS)
	}

	// Secure: no DIRECT anywhere (strip the DIRECT rules first).
	p.AvailabilityMode = ModeSecure
	p.Rules = []Rule{{Kind: RuleKindSuffix, Pattern: "cdn.example", Action: ActionUsePool, PoolID: "backup"}}
	art = CompileProfile(p, poolMap())
	if strings.Contains(art.JS, `"DIRECT"`) || strings.Contains(art.JS, "; DIRECT") {
		// isPlainHostName DIRECT is the one permitted bypass.
		stripped := strings.Replace(art.JS, `if (isPlainHostName(host)) return "DIRECT";`, "", 1)
		if strings.Contains(stripped, "DIRECT") {
			t.Errorf("secure mode must emit no DIRECT beyond plain-hostname:\n%s", art.JS)
		}
	}
	if art.ProxyChain[len(art.ProxyChain)-1] == "DIRECT" {
		t.Error("secure chain must not end in DIRECT")
	}
}

func TestCompileProfile_RuleEmission(t *testing.T) {
	p := testProfile()
	art := CompileProfile(p, poolMap())
	js := art.JS

	for _, want := range []string{
		`if ((host === "intranet.corp.example" || dnsDomainIs(host, ".intranet.corp.example"))) return "DIRECT";`,
		`if (dnsDomainIs(host, ".cdn.example")) return "PROXY backup.example:3128";`,
		`if (shExpMatch(host, "*.media.example")) return "PROXY culvert-il-vip:8080; PROXY culvert-eu-vip:8080";`,
		`if ((resolveOnce() && isInNet(resolveOnce(), "203.0.113.0", "255.255.255.0"))) return "DIRECT";`,
	} {
		if !strings.Contains(js, want) {
			t.Errorf("missing rule emission %q in:\n%s", want, js)
		}
	}
	// Order must match authoring order.
	if strings.Index(js, "intranet.corp") > strings.Index(js, "cdn.example") {
		t.Error("rules must be emitted in admin order")
	}
	// Private direct block present and before rules.
	if !strings.Contains(js, `isInNet(pip, "10.0.0.0", "255.0.0.0")`) {
		t.Error("privateNetworks=direct must emit the RFC1918 bypass")
	}
}

func TestCompileProfile_PrivateProxyOmitsBypass(t *testing.T) {
	p := testProfile()
	p.PrivateNetworks = PrivateProxy
	art := CompileProfile(p, poolMap())
	if strings.Contains(art.JS, "192.168.0.0") || strings.Contains(art.JS, "10.0.0.0") {
		t.Errorf("privateNetworks=proxy must omit the built-in RFC1918 bypass:\n%s", art.JS)
	}
}

func TestCompileProfile_SchemePortGuards(t *testing.T) {
	p := testProfile()
	p.Rules = []Rule{{Kind: RuleKindDomain, Pattern: "media.example", Action: ActionDirect,
		Scheme: "https", Port: 8443}}
	art := CompileProfile(p, poolMap())
	// Port guards compare the AUTHORITY tail, never a substring of the whole
	// URL — a ":80" rule must not fire on ":8080" or on path text.
	if !strings.Contains(art.JS, `url.substring(0, 6) === "https:" && auth.substring(auth.length - 5) === ":8443" && `) {
		t.Errorf("scheme/port guards missing or not authority-anchored:\n%s", art.JS)
	}
	if !strings.Contains(art.JS, `var auth = url;`) || !strings.Contains(art.JS, `auth.lastIndexOf("@")`) {
		t.Errorf("authority-extraction preamble missing:\n%s", art.JS)
	}
	if strings.Contains(art.JS, `url.indexOf(":`) {
		t.Errorf("port guard must never substring-match the full URL:\n%s", art.JS)
	}

	// No port rules -> no authority preamble emitted.
	p.Rules = []Rule{{Kind: RuleKindDomain, Pattern: "media.example", Action: ActionDirect}}
	art = CompileProfile(p, poolMap())
	if strings.Contains(art.JS, "var auth") {
		t.Errorf("authority preamble must be omitted without port rules:\n%s", art.JS)
	}
}

func TestCompileProfile_Deterministic(t *testing.T) {
	p := testProfile()
	first := CompileProfile(p, poolMap())
	for i := 0; i < 5; i++ {
		next := CompileProfile(p, poolMap())
		if next.JS != first.JS || next.Digest != first.Digest || next.Fingerprint != first.Fingerprint {
			t.Fatalf("iteration %d: non-deterministic profile compile", i)
		}
	}
}

func TestCompileProfile_DegenerateNoPoolFailsClosed(t *testing.T) {
	p := testProfile()
	p.Rules = nil
	p.PrivateNetworks = PrivateProxy
	p.AvailabilityMode = ModeSecure
	p.PoolID = "missing-pool"
	art := CompileProfile(p, poolMap())
	if strings.Contains(art.JS, `return "DIRECT";`) &&
		!strings.Contains(art.JS, "isPlainHostName") {
		t.Error("secure degenerate must not fail open")
	}
	if !strings.Contains(art.JS, "unresolvable.invalid") {
		t.Errorf("secure degenerate must fail closed via unresolvable placeholder:\n%s", art.JS)
	}
	found := false
	for _, w := range art.Warnings {
		if w.Code == IssueSecureModeConflict || w.Code == IssueUnknownPool {
			found = true
		}
	}
	if !found {
		t.Errorf("degenerate compile must warn, got %+v", art.Warnings)
	}
}

func TestCompileProfile_ES3Portability(t *testing.T) {
	art := CompileProfile(testProfile(), poolMap())
	for i := 0; i < len(art.JS); i++ {
		if art.JS[i] > 0x7e || (art.JS[i] < 0x20 && art.JS[i] != '\n') {
			t.Fatalf("non-ASCII byte 0x%02x at %d", art.JS[i], i)
		}
	}
	// Note vs the legacy compiler's list: String.prototype.indexOf IS ES3
	// (only the Array variants are ES5+), and the profile compiler uses it
	// deliberately in the authority preamble — so ".indexOf(" is absent here.
	for _, forbidden := range []string{"let ", "const ", "=>", "`", "..."} {
		if strings.Contains(art.JS, forbidden) {
			t.Errorf("post-ES3 construct %q in profile PAC", forbidden)
		}
	}
}
