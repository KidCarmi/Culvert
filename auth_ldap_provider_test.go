package main

// auth_ldap_provider_test.go — Slice 1 regression wall for ADR-0025:
//  1. The capability model (IdPType.Interactive / CredentialCapable) and the
//     capability-explicit registry accessors.
//  2. LDAP can NEVER leak into interactive SSO behavior — selector, captive
//     URL, ssoCapable probe, SSORequired providerRefs.
//  3. LDAP participates in the credential chain and produces a full Identity.
//  4. The LDAP profile validator's exactly-safe placeholder / transport rules.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// ldapEntryForTest builds a directory entry without a live server.
func ldapEntryForTest(dn string, attrs map[string][]string) *ldap.Entry {
	return ldap.NewEntry(dn, attrs)
}

// ── Capability model ─────────────────────────────────────────────────────────

func TestIdPTypeCapabilities(t *testing.T) {
	cases := []struct {
		typ         IdPType
		interactive bool
		credential  bool
	}{
		{IdPTypeOIDC, true, true},
		{IdPTypeSAML, true, false},
		{IdPTypeLDAP, false, true},
		{IdPType(""), false, false},      // never-valid zero type carries no capability
		{IdPType("bogus"), false, false}, // unknown types carry no capability (fail closed)
	}
	for _, c := range cases {
		if got := c.typ.Interactive(); got != c.interactive {
			t.Errorf("IdPType(%q).Interactive() = %v, want %v", c.typ, got, c.interactive)
		}
		if got := c.typ.CredentialCapable(); got != c.credential {
			t.Errorf("IdPType(%q).CredentialCapable() = %v, want %v", c.typ, got, c.credential)
		}
	}
}

// ldapTestProfile returns a valid enabled LDAP profile for registry tests.
func ldapTestProfile(id, name string) *IdPProfile {
	return &IdPProfile{
		ID:      id,
		Name:    name,
		Type:    IdPTypeLDAP,
		Enabled: true,
		LDAP: &LDAPProfileConfig{
			URL:          "ldaps://dc01.corp.example:636",
			BindDN:       "CN=svc-proxy,OU=Service,DC=corp,DC=example",
			BindPassword: "svc-secret",
			BaseDN:       "DC=corp,DC=example",
		},
	}
}

// swapIdPRegistry installs a fresh registry for the test and restores the
// original on cleanup (the established global-isolation pattern).
func swapIdPRegistry(t *testing.T, profiles ...*IdPProfile) *IdPRegistry {
	t.Helper()
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	reg := &IdPRegistry{live: map[string]IdentityProvider{}}
	if err := reg.ReplaceAll(profiles); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	idpRegistry = reg
	return reg
}

// ── Registry integration: LDAP compiles, is credential-capable, never SSO ────

func TestLDAPProfile_CompilesInRegistry(t *testing.T) {
	reg := swapIdPRegistry(t, ldapTestProfile("corp-ad", "Corporate AD"))

	prov, ok := reg.LiveProvider("corp-ad")
	if !ok {
		t.Fatal("enabled LDAP profile must compile to a live provider")
	}
	if got := prov.Name(); got != "ldap:corp-ad" {
		t.Errorf("Name() = %q, want ldap:corp-ad", got)
	}
	if got := prov.DisplayName(); got != "Corporate AD" {
		t.Errorf("DisplayName() = %q, want Corporate AD", got)
	}
}

func TestLDAPProfile_NeverInteractive(t *testing.T) {
	reg := swapIdPRegistry(t, ldapTestProfile("corp-ad", "Corporate AD"))

	// 1. ssoCapable probe must stay false with only LDAP enabled.
	if reg.HasEnabledInteractiveProvider() {
		t.Error("HasEnabledInteractiveProvider() = true with only an LDAP profile — LDAP leaked into ssoCapable")
	}
	// 2. …while the credential probes go true.
	if !reg.HasEnabledCredentialProvider() {
		t.Error("HasEnabledCredentialProvider() = false with an enabled LDAP profile")
	}
	if len(reg.EnabledCredentialProviders()) != 1 {
		t.Error("EnabledCredentialProviders() must include the LDAP provider")
	}
	// 3. Interactive iteration surfaces must exclude it.
	if got := reg.EnabledInteractiveProviders(); len(got) != 0 {
		t.Errorf("EnabledInteractiveProviders() returned %d providers, want 0", len(got))
	}
	// 4. Captive login URL is structurally empty.
	prov, _ := reg.LiveProvider("corp-ad")
	if url := prov.CaptiveLoginURL("corp.example", nil); url != "" {
		t.Errorf("CaptiveLoginURL() = %q, want empty — LDAP must never mint a browser flow", url)
	}
	// 5. Email-domain routing must not pick LDAP.
	p := ldapTestProfile("corp-ad2", "AD2")
	p.EmailDomains = []string{"corp.example"}
	reg = swapIdPRegistry(t, p)
	if got := reg.RouteByDomain("corp.example"); got != nil {
		t.Error("RouteByDomain matched an LDAP profile — captive redirects would be swallowed")
	}
	// 6. SSORequired eligibility (proxy_portal): zero eligible providers.
	if elig := eligibleSSOProviders([]string{"corp-ad2"}); len(elig) != 0 {
		t.Errorf("eligibleSSOProviders() returned %d for an LDAP ref, want 0", len(elig))
	}
	// 7. SSORequired providerRefs write-door validation rejects LDAP refs.
	err := validateSSOProviderRefsLive(&AuthRuleSpec{
		Outcome:      OutcomeSSORequired,
		ProviderRefs: []string{"corp-ad2"},
	})
	if err == nil || !strings.Contains(err.Error(), "not an interactive") {
		t.Errorf("validateSSOProviderRefsLive must reject an LDAP ref, got %v", err)
	}
}

func TestLDAPProfile_NeverOnAuthSelectPage(t *testing.T) {
	swapIdPRegistry(t, ldapTestProfile("corp-ad", "Corporate AD"))

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/select", http.NoBody)
	rec := httptest.NewRecorder()
	authSelectProvider(rec, req)
	body := rec.Body.String()
	if strings.Contains(body, "Corporate AD") || strings.Contains(body, "ldap:") {
		t.Errorf("/auth/select leaked an LDAP provider: %s", body)
	}
	if !strings.Contains(body, "No identity providers are configured.") {
		t.Errorf("/auth/select with only LDAP must render as no interactive providers, got: %s", body)
	}
}

func TestCaptivePortalURL_IgnoresLDAPOnlyRegistry(t *testing.T) {
	swapIdPRegistry(t, ldapTestProfile("corp-ad", "Corporate AD"))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/", http.NoBody)
	if got := resolveCaptivePortalURL(req); got != cfg.OIDCLoginURL() {
		t.Errorf("resolveCaptivePortalURL with LDAP-only registry = %q, want legacy fallback %q", got, cfg.OIDCLoginURL())
	}
}

// ── Mixed registries: interactive behavior is unchanged by an added LDAP ─────

func TestMixedRegistry_InteractiveSubsetExcludesLDAP(t *testing.T) {
	saml := &IdPProfile{
		ID: "corp-saml", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: true,
		SAML: &SAMLProfileConfig{MetadataXML: clusterAuthSAMLMetadataXML(t)},
	}
	reg := swapIdPRegistry(t, saml, ldapTestProfile("corp-ad", "Corporate AD"))

	if !reg.HasEnabledInteractiveProvider() {
		t.Error("SAML profile must keep ssoCapable true")
	}
	inter := reg.EnabledInteractiveProviders()
	if len(inter) != 1 || inter[0].Name() != "saml:corp-saml" {
		t.Errorf("EnabledInteractiveProviders() = %v, want only saml:corp-saml", providerNames(inter))
	}
	creds := reg.EnabledCredentialProviders()
	if len(creds) != 1 || creds[0].Name() != "ldap:corp-ad" {
		t.Errorf("EnabledCredentialProviders() = %v, want only ldap:corp-ad", providerNames(creds))
	}
	// SSORequired with mixed refs: only the interactive subset is eligible.
	elig := eligibleSSOProviders([]string{"corp-saml", "corp-ad"})
	if len(elig) != 1 || elig[0].id != "corp-saml" {
		t.Errorf("eligibleSSOProviders(mixed) must keep only the SAML ref, got %+v", elig)
	}
}

func providerNames(ps []IdentityProvider) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name())
	}
	return out
}

// ── authSource plumbing ──────────────────────────────────────────────────────

func TestSplitIdPSource_LDAPScheme(t *testing.T) {
	scheme, name := splitIdPSource("ldap:corp-ad")
	if scheme != "ldap" || name != "corp-ad" {
		t.Errorf("splitIdPSource(ldap:corp-ad) = (%q,%q)", scheme, name)
	}
	if got := stripIdPPrefix("ldap:corp-ad"); got != "corp-ad" {
		t.Errorf("stripIdPPrefix(ldap:corp-ad) = %q", got)
	}
	// Bare/prefixed alias matches, cross-scheme does not.
	if !matchAuthSource("corp-ad", "ldap:corp-ad") {
		t.Error("bare rule ref must match ldap:-prefixed source")
	}
	if !matchAuthSource("ldap:corp-ad", "ldap:corp-ad") {
		t.Error("exact ldap: match failed")
	}
	if matchAuthSource("oidc:corp-ad", "ldap:corp-ad") {
		t.Error("cross-scheme oidc: rule must NOT match an ldap: source")
	}
}

// ── Identity mapping (engine-level, no directory needed) ─────────────────────

func TestLDAPEngine_BuildIdentity(t *testing.T) {
	prof := ldapTestProfile("corp-ad", "Corporate AD")
	prov, err := NewLDAPIdPProvider(prof)
	if err != nil {
		t.Fatalf("NewLDAPIdPProvider: %v", err)
	}
	entry := ldapEntryForTest("CN=Alice,OU=Users,DC=corp,DC=example", map[string][]string{
		"mail":        {"alice@corp.example"},
		"displayName": {"Alice Example"},
		"cn":          {"Alice"},
		"memberOf":    {"CN=Engineering,OU=Groups,DC=corp,DC=example", "CN=VPN,OU=Groups,DC=corp,DC=example"},
	})
	id := prov.engine.buildIdentity("alice", entry)
	if id == nil {
		t.Fatal("identity-resolving engine returned nil identity")
	}
	if id.Sub != "CN=Alice,OU=Users,DC=corp,DC=example" {
		t.Errorf("Sub = %q, want the full user DN", id.Sub)
	}
	if id.Email != "alice@corp.example" || id.Name != "Alice Example" {
		t.Errorf("Email/Name = %q/%q", id.Email, id.Name)
	}
	if len(id.Groups) != 2 || !strings.HasPrefix(id.Groups[0], "CN=Engineering,") {
		t.Errorf("Groups = %v, want the verbatim group DNs", id.Groups)
	}
	if id.Provider != "corp-ad" {
		t.Errorf("Provider = %q, want the profile ID", id.Provider)
	}
}

func TestLDAPEngine_BuildIdentity_NameFallbacks(t *testing.T) {
	prov, err := NewLDAPIdPProvider(ldapTestProfile("corp-ad", "AD"))
	if err != nil {
		t.Fatal(err)
	}
	// displayName absent → cn.
	id := prov.engine.buildIdentity("bob", ldapEntryForTest("CN=Bob,DC=corp,DC=example",
		map[string][]string{"cn": {"Bob"}}))
	if id.Name != "Bob" {
		t.Errorf("Name = %q, want cn fallback Bob", id.Name)
	}
	// Both absent → login username.
	id = prov.engine.buildIdentity("carol", ldapEntryForTest("CN=Carol,DC=corp,DC=example", nil))
	if id.Name != "carol" {
		t.Errorf("Name = %q, want username fallback carol", id.Name)
	}
	if id.Email != "" {
		t.Errorf("Email = %q, want empty when the attribute is absent", id.Email)
	}
}

func TestLegacyLDAPEngine_NoIdentity(t *testing.T) {
	// The legacy YAML provider must stay boolean-only: its engine builds no
	// identity (Stage-2 keeps username + "local" semantics), and its wire
	// request keeps the historical dn+memberOf attribute list.
	a, err := NewLDAPAuth(LDAPConfig{URL: "ldaps://dc:636", BaseDN: "dc=x"})
	if err != nil {
		t.Fatal(err)
	}
	if a.attrs.enabled() {
		t.Fatal("legacy engine must not enable identity attributes")
	}
	if id := a.buildIdentity("alice", ldapEntryForTest("CN=Alice,DC=x", map[string][]string{"memberOf": {"g"}})); id != nil {
		t.Errorf("legacy engine built an identity: %+v", id)
	}
	if got := a.searchAttributes(); len(got) != 2 || got[0] != "dn" || got[1] != "memberOf" {
		t.Errorf("legacy searchAttributes() = %v, want [dn memberOf]", got)
	}
	if got := a.groupAttribute(); got != "memberOf" {
		t.Errorf("legacy groupAttribute() = %q", got)
	}
}

func TestRegistryLDAPEngine_SearchAttributes(t *testing.T) {
	p := ldapTestProfile("corp-ad", "AD")
	p.LDAP.EmailAttribute = "userPrincipalName"
	p.LDAP.NameAttribute = "cn"
	p.LDAP.GroupAttribute = "isMemberOf"
	prov, err := NewLDAPIdPProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(prov.engine.searchAttributes(), ",")
	if got != "dn,isMemberOf,cn,userPrincipalName" {
		t.Errorf("searchAttributes() = %q", got)
	}
	if prov.engine.groupAttribute() != "isMemberOf" {
		t.Errorf("groupAttribute() = %q", prov.engine.groupAttribute())
	}
}

// ── Cache identity round-trip ────────────────────────────────────────────────

func TestLDAPEngine_CacheStoresAndClonesIdentity(t *testing.T) {
	prov, err := NewLDAPIdPProvider(ldapTestProfile("corp-ad", "AD"))
	if err != nil {
		t.Fatal(err)
	}
	engine := prov.engine
	id := &Identity{Sub: "CN=Alice,DC=x", Groups: []string{"CN=G1"}, Provider: "corp-ad"}
	k := cacheKey("alice", "pw")
	engine.cacheSet(k, true, id)

	got, ok := engine.resolveIdentityFromCacheForTest(k)
	if !ok || got == nil || got.Sub != "CN=Alice,DC=x" {
		t.Fatalf("cached identity round-trip failed: %+v %v", got, ok)
	}
	// Mutating the returned identity must not corrupt the cache.
	got.Groups[0] = "TAMPERED"
	again, _ := engine.resolveIdentityFromCacheForTest(k)
	if again.Groups[0] != "CN=G1" {
		t.Error("cached identity groups were mutated through a caller's copy — missing clone")
	}
}

// resolveIdentityFromCacheForTest reads a cached entry through the same clone
// path resolveIdentity uses, without needing a live directory.
func (a *LDAPAuth) resolveIdentityFromCacheForTest(key string) (*Identity, bool) {
	e, hit := a.cacheGet(key)
	if !hit || !e.ok {
		return nil, false
	}
	return cloneIdentity(e.id), true
}

// ── Validator ────────────────────────────────────────────────────────────────

func TestValidateLDAPProfileConfig(t *testing.T) {
	valid := func() *LDAPProfileConfig {
		return &LDAPProfileConfig{URL: "ldaps://dc01.corp.example:636", BaseDN: "DC=corp,DC=example"}
	}
	if err := validateLDAPProfileConfig(valid()); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*LDAPProfileConfig)
		substr string
	}{
		{"nil config", nil, "required"},
		{"empty url", func(c *LDAPProfileConfig) { c.URL = "" }, "required"},
		{"http scheme", func(c *LDAPProfileConfig) { c.URL = "https://dc01:636" }, "scheme"},
		{"gopher scheme", func(c *LDAPProfileConfig) { c.URL = "gopher://dc01" }, "scheme"},
		{"url with path", func(c *LDAPProfileConfig) { c.URL = "ldaps://dc01:636/base" }, "host[:port] only"},
		{"url with creds", func(c *LDAPProfileConfig) { c.URL = "ldaps://u:p@dc01:636" }, "host[:port] only"},
		{"bad port", func(c *LDAPProfileConfig) { c.URL = "ldaps://dc01:99999" }, "port"},
		{"bad hostname", func(c *LDAPProfileConfig) { c.URL = "ldaps://bad_host!" }, "hostname"},
		{"empty base dn", func(c *LDAPProfileConfig) { c.BaseDN = "  " }, "baseDn is required"},
		{"control char dn", func(c *LDAPProfileConfig) { c.BaseDN = "DC=x\n" }, "control"},
		{"contradictory starttls", func(c *LDAPProfileConfig) { c.StartTLS = true }, "contradictory"},
		{"filter no placeholder", func(c *LDAPProfileConfig) { c.UserFilter = "(uid=alice)" }, "exactly one"},
		{"filter two placeholders", func(c *LDAPProfileConfig) { c.UserFilter = "(|(uid=%s)(cn=%s))" }, "exactly one"},
		{"filter other verb", func(c *LDAPProfileConfig) { c.UserFilter = "(uid=%d)" }, "%s placeholder"},
		{"filter trailing percent", func(c *LDAPProfileConfig) { c.UserFilter = "(uid=%s)%" }, "bare %"},
		{"filter unparenthesized", func(c *LDAPProfileConfig) { c.UserFilter = "uid=%s" }, "parenthesized"},
		{"filter newline", func(c *LDAPProfileConfig) { c.UserFilter = "(uid=%s)\n" }, "control"},
		{"bad attr", func(c *LDAPProfileConfig) { c.GroupAttribute = "member;Of" }, "letters, digits"},
		{"attr starts with digit", func(c *LDAPProfileConfig) { c.EmailAttribute = "1mail" }, "start with a letter"},
		{"ttl too small", func(c *LDAPProfileConfig) { c.CacheTTLSeconds = 5 }, "cacheTtlSeconds"},
		{"ttl negative", func(c *LDAPProfileConfig) { c.CacheTTLSeconds = -1 }, "cacheTtlSeconds"},
		{"ttl too large", func(c *LDAPProfileConfig) { c.CacheTTLSeconds = 100000 }, "cacheTtlSeconds"},
		{"huge password", func(c *LDAPProfileConfig) { c.BindPassword = strings.Repeat("x", 2000) }, "bind credential"},
		{"huge url", func(c *LDAPProfileConfig) { c.URL = "ldaps://" + strings.Repeat("a", 300) + ":636" }, "exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg *LDAPProfileConfig
			if tc.mutate != nil {
				cfg = valid()
				tc.mutate(cfg)
			}
			err := validateLDAPProfileConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.substr) {
				t.Errorf("want error containing %q, got %v", tc.substr, err)
			}
		})
	}

	// Accepted shapes.
	ok := []func(c *LDAPProfileConfig){
		func(c *LDAPProfileConfig) { c.URL = "ldap://10.1.2.3:389"; c.StartTLS = true }, // StartTLS over plain LDAP
		func(c *LDAPProfileConfig) { c.URL = "ldap://[2001:db8::1]:389" },               // IPv6
		func(c *LDAPProfileConfig) { c.UserFilter = "(uid=%s)" },
		func(c *LDAPProfileConfig) { c.UserFilter = "(&(objectClass=user)(sAMAccountName=%s))" },
		func(c *LDAPProfileConfig) { c.CacheTTLSeconds = 60 },
		func(c *LDAPProfileConfig) {
			c.GroupAttribute = "isMemberOf"
			c.EmailAttribute = "mail"
			c.NameAttribute = "displayName"
		},
	}
	for i, mutate := range ok {
		cfg := valid()
		mutate(cfg)
		if err := validateLDAPProfileConfig(cfg); err != nil {
			t.Errorf("accepted shape %d rejected: %v", i, err)
		}
	}
}

func TestValidateIdPProfile_LDAPType(t *testing.T) {
	p := ldapTestProfile("corp-ad", "Corporate AD")
	if err := validateIdPProfile(p); err != nil {
		t.Fatalf("valid LDAP profile rejected: %v", err)
	}
	p.LDAP = nil
	if err := validateIdPProfile(p); err == nil {
		t.Error("LDAP profile without config must be rejected")
	}
	if err := validateUpsertProfile(ldapTestProfile("corp-ad", "Corporate AD")); err != nil {
		t.Errorf("Upsert-path validation rejected a valid LDAP profile: %v", err)
	}
	bad := ldapTestProfile("corp-ad", "Corporate AD")
	bad.LDAP.URL = "https://not-ldap"
	if err := validateUpsertProfile(bad); err == nil {
		t.Error("Upsert-path validation must reject a bad LDAP URL")
	}
}

func TestNewLDAPIdPProvider_Defaults(t *testing.T) {
	prov, err := NewLDAPIdPProvider(ldapTestProfile("corp-ad", "AD"))
	if err != nil {
		t.Fatal(err)
	}
	e := prov.engine
	if e.cfg.UserFilter != "(sAMAccountName=%s)" {
		t.Errorf("UserFilter default = %q", e.cfg.UserFilter)
	}
	if e.attrs.email != "mail" || e.attrs.name != "displayName" || e.attrs.group != "memberOf" {
		t.Errorf("attribute defaults = %+v", e.attrs)
	}
	if e.ttl != defLDAPCacheTTLSecs*time.Second {
		t.Errorf("ttl default = %v", e.ttl)
	}
	if e.backendName != "ldap:corp-ad" || e.providerID != "corp-ad" {
		t.Errorf("backendName/providerID = %q/%q", e.backendName, e.providerID)
	}
}
