package main

// auth_ldap_edge_cases_test.go — boundary / edge-case regression wall for the
// ADR-0027 LDAP-as-first-class-IdP feature. The behavioural suites in
// auth_ldap_provider_test.go, auth_ldap_gate_test.go, auth_idp_ldap_persistence_test.go
// and the OpenLDAP interop suite cover the happy paths and the CHAOS-47
// blast-radius classification; this file pins the VALIDATOR boundaries (the
// LDAP-injection guard, hostname/URL shape, DN/attribute length caps, cache-TTL
// clamp edges) and the identity-engine twins of legacy paths that only had
// boolean-mode coverage. Every case here is a value a hostile or fat-fingered
// admin could actually submit through POST /api/idp.

import (
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// ── CHAOS-47 blast-radius: the client-error range must track the library ─────
//
// ldapUserBindIsUnreachable classifies a step-2 user-bind failure as
// "directory unreachable" (arms the provider-wide cooldown, and clears it on
// reachable evidence) vs "the directory answered about this account" (must
// NEVER gate — it is attacker-provokable per account). The reachable/unreachable
// split for go-ldap's own client-side faults keys on the contiguous constant
// block [ldapClientErrorFloor, ldapClientErrorCeil] == [ErrorNetwork,
// ErrorEmptyPassword] == [200, 206]. TestLDAPUserBindIsUnreachable_ClientSpaceBoundaries
// pins the CURRENT edges, but nothing catches go-ldap EXTENDING that block: a
// new Error* constant at 207 would fall OUTSIDE the range and be misclassified
// as "server answered" — so a genuine transport/client fault would (a) fail to
// arm the cooldown and (b) be read as positive reachability that clears an
// already-armed one. This guard fires on exactly that library change.
func TestLDAPClientErrorCeil_TracksLibrary(t *testing.T) {
	// Our ceiling must be the library's current top client-error constant.
	if ldapClientErrorCeil != ldap.ErrorEmptyPassword {
		t.Fatalf("ldapClientErrorCeil = %d, want ldap.ErrorEmptyPassword = %d — sync the constant",
			ldapClientErrorCeil, ldap.ErrorEmptyPassword)
	}
	if ldapClientErrorFloor != ldap.ErrorNetwork {
		t.Fatalf("ldapClientErrorFloor = %d, want ldap.ErrorNetwork = %d", ldapClientErrorFloor, ldap.ErrorNetwork)
	}
	// The go-ldap client-error block (Error* constants) is contiguous and 206
	// is its top; every code in [floor, ceil] is a defined client fault…
	for code := uint16(ldapClientErrorFloor); code <= ldapClientErrorCeil; code++ {
		if _, ok := ldap.LDAPResultCodeMap[code]; !ok {
			t.Errorf("client-error code %d is not defined in the library — the range no longer matches", code)
		}
	}
	// …and the next code up is undefined. If a future go-ldap adds an Error*
	// constant at ceil+1, it appears here, and ldapUserBindIsUnreachable must be
	// re-examined before the range silently misclassifies it as reachable.
	if desc, ok := ldap.LDAPResultCodeMap[ldapClientErrorCeil+1]; ok {
		t.Fatalf("go-ldap now defines code %d (%q): the client-error block was extended past "+
			"ldapClientErrorCeil — review ldapUserBindIsUnreachable and raise the ceiling",
			ldapClientErrorCeil+1, desc)
	}
}

// ── validateLDAPUserFilter: the LDAP-injection guard boundaries ──────────────
//
// The exactly-one-%s rule is the single guarantee that
// fmt.Sprintf(filter, ldap.EscapeFilter(username)) cannot be steered into a
// second substitution or a literal-% corruption, so its boundaries are a
// security contract, not cosmetics.

func TestValidateLDAPUserFilter_EdgeCases(t *testing.T) {
	accepted := []struct {
		name, filter string
	}{
		{"minimal parenthesized placeholder", "(%s)"},
		{"literal double-percent before placeholder", "(cn=100%%done-%s)"},
		{"literal double-percent after placeholder", "(&(sAMAccountName=%s)(note=50%%))"},
		{"empty template applies compile-time default", ""},
		{"filter exactly at length cap", "(" + strings.Repeat("a", 508) + "%s)"}, // len == 512
	}
	for _, tc := range accepted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := validateLDAPUserFilter(tc.filter); err != nil {
				t.Errorf("filter %q rejected, want accepted: %v", tc.filter, err)
			}
		})
	}
	if got := len(accepted[4].filter); got != maxLDAPFilterLen {
		t.Fatalf("length-cap fixture is %d bytes, meant to be exactly %d", got, maxLDAPFilterLen)
	}

	rejected := []struct {
		name, filter, substr string
	}{
		{"double-percent only, no placeholder", "(x=100%%)", "exactly one"},
		{"filter over length cap", "(" + strings.Repeat("a", 509) + "%s)", "exceeds"}, // len == 513
		{"tab control char", "(uid=%s\t)", "control"},
		{"del control char", "(uid=%s\x7f)", "control"},
		{"percent then space", "(uid=% s)", "%s placeholder"},
		{"percent then digit", "(uid=%1s)", "%s placeholder"},
		{"three placeholders", "(|(a=%s)(b=%s)(c=%s))", "exactly one"},
		{"placeholder outside parens", "%s", "parenthesized"},
	}
	for _, tc := range rejected {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			err := validateLDAPUserFilter(tc.filter)
			if err == nil || !strings.Contains(err.Error(), tc.substr) {
				t.Errorf("filter %q: want error containing %q, got %v", tc.filter, tc.substr, err)
			}
		})
	}
}

// ── isValidHostname: RFC-1123 label rules ────────────────────────────────────

func TestIsValidHostname_EdgeCases(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"dc01.corp.example", true},
		{"dc01.corp.example.", true}, // trailing dot (FQDN) is tolerated
		{"a", true},
		{strings.Repeat("a", 63), true},           // label at the 63-char cap
		{strings.Repeat("a", 64), false},          // label over the cap
		{"", false},                               // empty host
		{"bad_host", false},                       // underscore is not a legal label char
		{"-leading.example", false},               // label may not start with a hyphen
		{"trailing-.example", false},              // …nor end with one
		{"dc..corp", false},                       // empty inner label (double dot)
		{strings.Repeat("a.", 127) + "aa", false}, // total length over 253
	}
	for _, c := range cases {
		if got := isValidHostname(c.host); got != c.want {
			t.Errorf("isValidHostname(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

// ── validateLDAPURL: authority-shape boundaries via the profile validator ────

func TestValidateLDAPURL_EdgeCases(t *testing.T) {
	base := func(url string) *LDAPProfileConfig {
		return &LDAPProfileConfig{URL: url, BaseDN: "DC=corp,DC=example"}
	}

	accepted := []struct{ name, url string }{
		{"port lower bound", "ldaps://dc01:1"},
		{"port upper bound", "ldaps://dc01:65535"},
		{"no explicit port", "ldaps://dc01"},
		{"uppercase scheme normalizes", "LDAPS://dc01:636"},
		{"trailing-dot fqdn", "ldaps://dc01.corp.example.:636"},
		{"ipv4 literal", "ldaps://192.168.1.10:636"},
	}
	for _, tc := range accepted {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			if err := validateLDAPProfileConfig(base(tc.url)); err != nil {
				t.Errorf("url %q rejected, want accepted: %v", tc.url, err)
			}
		})
	}

	rejected := []struct{ name, url, substr string }{
		{"opaque form", "ldap:dc01", "host[:port] only"},
		{"fragment", "ldaps://dc01:636#frag", "host[:port] only"},
		{"query", "ldaps://dc01:636?a=b", "host[:port] only"},
		{"port zero", "ldaps://dc01:0", "port"},
		{"port over max", "ldaps://dc01:65536", "port"},
		{"non-numeric port", "ldaps://dc01:ssl", "valid URL"}, // url.Parse rejects a non-numeric port before our port check
		{"missing host", "ldaps://:636", "host is required"},
		{"underscore host", "ldaps://bad_host:636", "hostname"},
	}
	for _, tc := range rejected {
		t.Run("reject/"+tc.name, func(t *testing.T) {
			err := validateLDAPProfileConfig(base(tc.url))
			if err == nil || !strings.Contains(err.Error(), tc.substr) {
				t.Errorf("url %q: want error containing %q, got %v", tc.url, tc.substr, err)
			}
		})
	}
}

// ── DN / attribute length caps and control-char rejection on every field ─────
//
// The validator loops over baseDn+bindDn+requiredGroup and over the three
// attribute names; the existing suite only exercises baseDn / groupAttribute,
// so these pin that the OTHER fields share the same cap and control-char guard
// (a copy-paste regression in the loop would otherwise pass unnoticed).

func TestValidateLDAPProfileConfig_FieldBoundaries(t *testing.T) {
	valid := func() *LDAPProfileConfig {
		return &LDAPProfileConfig{URL: "ldaps://dc01:636", BaseDN: "DC=corp,DC=example"}
	}

	cases := []struct {
		name   string
		mutate func(*LDAPProfileConfig)
		substr string
	}{
		{"bindDn over length cap", func(c *LDAPProfileConfig) { c.BindDN = "CN=" + strings.Repeat("a", maxLDAPDNLen) }, "bindDn: exceeds"},
		{"requiredGroup over length cap", func(c *LDAPProfileConfig) { c.RequiredGroup = "CN=" + strings.Repeat("a", maxLDAPDNLen) }, "requiredGroup: exceeds"},
		{"bindDn control char", func(c *LDAPProfileConfig) { c.BindDN = "CN=svc\x00" }, "bindDn: contains control"},
		{"requiredGroup control char", func(c *LDAPProfileConfig) { c.RequiredGroup = "CN=grp\x1b" }, "requiredGroup: contains control"},
		{"attr over length cap", func(c *LDAPProfileConfig) { c.EmailAttribute = strings.Repeat("a", maxLDAPAttrLen+1) }, "emailAttribute: exceeds"},
		{"nameAttribute bad char", func(c *LDAPProfileConfig) { c.NameAttribute = "display_name" }, "nameAttribute: may contain only"},
		{"bindPassword at cap accepted-boundary+1", func(c *LDAPProfileConfig) { c.BindPassword = strings.Repeat("x", maxLDAPBindInputLen+1) }, "bind credential"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			err := validateLDAPProfileConfig(c)
			if err == nil || !strings.Contains(err.Error(), tc.substr) {
				t.Errorf("want error containing %q, got %v", tc.substr, err)
			}
		})
	}

	// Boundary values that MUST be accepted (one byte under each cap).
	okBoundary := []struct {
		name   string
		mutate func(*LDAPProfileConfig)
	}{
		{"bindDn at length cap", func(c *LDAPProfileConfig) { c.BindDN = strings.Repeat("a", maxLDAPDNLen) }},
		{"attr at length cap", func(c *LDAPProfileConfig) { c.GroupAttribute = strings.Repeat("a", maxLDAPAttrLen) }},
		{"bindPassword at cap", func(c *LDAPProfileConfig) { c.BindPassword = strings.Repeat("x", maxLDAPBindInputLen) }},
	}
	for _, tc := range okBoundary {
		t.Run("accept/"+tc.name, func(t *testing.T) {
			c := valid()
			tc.mutate(c)
			if err := validateLDAPProfileConfig(c); err != nil {
				t.Errorf("boundary value rejected, want accepted: %v", err)
			}
		})
	}
}

// ── Cache-TTL clamp: the exact accepted window [10, 86400] ───────────────────

func TestValidateLDAPProfileConfig_CacheTTLBoundaries(t *testing.T) {
	mk := func(ttl int) *LDAPProfileConfig {
		return &LDAPProfileConfig{URL: "ldaps://dc01:636", BaseDN: "DC=x", CacheTTLSeconds: ttl}
	}
	accept := []int{0, minLDAPCacheTTLSecs, defLDAPCacheTTLSecs, maxLDAPCacheTTLSecs}
	for _, ttl := range accept {
		if err := validateLDAPProfileConfig(mk(ttl)); err != nil {
			t.Errorf("cacheTtlSeconds=%d rejected, want accepted: %v", ttl, err)
		}
	}
	reject := []int{minLDAPCacheTTLSecs - 1, maxLDAPCacheTTLSecs + 1, -1}
	for _, ttl := range reject {
		if err := validateLDAPProfileConfig(mk(ttl)); err == nil {
			t.Errorf("cacheTtlSeconds=%d accepted, want rejected", ttl)
		}
	}
}

// ── ldapProfileDefault: whitespace-only collapses to the default ─────────────

func TestLDAPProfileDefault(t *testing.T) {
	cases := []struct{ in, def, want string }{
		{"", "d", "d"},
		{"   ", "d", "d"},
		{"\t\n", "d", "d"},
		{"mail", "d", "mail"},
		{"  mail  ", "d", "  mail  "}, // non-blank is returned verbatim, untrimmed
	}
	for _, c := range cases {
		if got := ldapProfileDefault(c.in, c.def); got != c.want {
			t.Errorf("ldapProfileDefault(%q,%q) = %q, want %q", c.in, c.def, got, c.want)
		}
	}
}

// ── Identity-engine edge cases (no live directory) ───────────────────────────

// buildIdentity when NameAttribute is explicitly "cn": the value comes from cn
// and searchAttributes must not double-request it.
func TestLDAPEngine_BuildIdentity_NameAttributeIsCN(t *testing.T) {
	p := ldapTestProfile("corp-ad", "AD")
	p.LDAP.NameAttribute = "cn"
	prov, err := NewLDAPIdPProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(prov.engine.searchAttributes(), ","); strings.Count(got, "cn") != 1 {
		t.Errorf("searchAttributes() = %q must request cn exactly once", got)
	}
	id := prov.engine.buildIdentity("dave", ldapEntryForTest("CN=Dave,DC=x",
		map[string][]string{"cn": {"Dave Display"}}))
	if id == nil || id.Name != "Dave Display" {
		t.Errorf("Name from cn = %+v, want Dave Display", id)
	}
}

// A directory entry with no group attribute yields an empty (never a garbage)
// group set, and a multi-valued mail attribute maps to its first value.
func TestLDAPEngine_BuildIdentity_EmptyGroupsAndMultiValueMail(t *testing.T) {
	prov, err := NewLDAPIdPProvider(ldapTestProfile("corp-ad", "AD"))
	if err != nil {
		t.Fatal(err)
	}
	id := prov.engine.buildIdentity("erin", ldapEntryForTest("CN=Erin,DC=x",
		map[string][]string{"mail": {"erin@corp.example", "erin.alt@corp.example"}}))
	if id == nil {
		t.Fatal("nil identity")
	}
	if len(id.Groups) != 0 {
		t.Errorf("Groups = %v, want empty when the group attribute is absent", id.Groups)
	}
	if id.Email != "erin@corp.example" {
		t.Errorf("Email = %q, want the first mail value", id.Email)
	}
	if id.Sub != "CN=Erin,DC=x" {
		t.Errorf("Sub = %q, want the full DN", id.Sub)
	}
}

// resolveIdentity is the identity-engine twin of Verify: an empty password must
// short-circuit to (nil, false) with no dial and no cache write.
func TestLDAPEngine_ResolveIdentity_EmptyPasswordShortCircuits(t *testing.T) {
	prov, err := NewLDAPIdPProvider(ldapTestProfile("corp-ad", "AD"))
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := prov.ResolveIdentity("alice", ""); ok || id != nil {
		t.Errorf("ResolveIdentity(_, \"\") = (%+v,%v), want (nil,false)", id, ok)
	}
	prov.engine.mu.Lock()
	n := len(prov.engine.cache)
	prov.engine.mu.Unlock()
	if n != 0 {
		t.Errorf("empty-password attempt wrote %d cache entries, want 0", n)
	}
}

// A cached AUTHORITATIVE negative (the directory answered "no") is honored by
// resolveIdentity without a dial — the identity twin of TestLDAPAuth_Cache_HitFalse.
func TestLDAPEngine_ResolveIdentity_HonorsCachedNegative(t *testing.T) {
	prov, err := NewLDAPIdPProvider(ldapTestProfile("corp-ad", "AD"))
	if err != nil {
		t.Fatal(err)
	}
	// Point the engine at a black-hole URL so any dial would fail loudly; the
	// cached negative must be returned before we ever get there.
	prov.engine.cache[cacheKey("mallory", "nope")] = &ldapCacheEntry{ok: false, id: nil, expiry: time.Now().Add(time.Hour)}
	if id, ok := prov.ResolveIdentity("mallory", "nope"); ok || id != nil {
		t.Errorf("ResolveIdentity on cached negative = (%+v,%v), want (nil,false)", id, ok)
	}
}
