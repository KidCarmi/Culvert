package main

// auth_ldap_openldap_integration_test.go — REAL-directory interop suite for
// the LDAP IdP (ADR-0025, Slice 6). Runs against a pinned OpenLDAP container
// seeded from .github/idp/openldap/bootstrap.ldif (see the "OpenLDAP" job in
// .github/workflows/auth-idp-interop.yml). Env-gated: skips without
// CULVERT_OPENLDAP_URL, exactly like the Keycloak/SimpleSAMLphp suites.
//
// Coverage (mission §25): service bind, user search, valid user bind,
// invalid password, unknown user, empty password, direct group membership,
// non-member, Identity.{Sub,Email,Name,Groups}, Provider/authSource, LDAP
// profile compile + registry integration, the RequiredGroup legacy gate, the
// staged directory-test pipeline, and LDAPS.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openLDAPInteropProfile(t *testing.T) *IdPProfile {
	t.Helper()
	url := os.Getenv("CULVERT_OPENLDAP_URL")
	if url == "" {
		t.Skip("set CULVERT_OPENLDAP_URL to run OpenLDAP interop tests")
	}
	return &IdPProfile{
		ID:      "openldap-interop",
		Name:    "OpenLDAP Interop",
		Type:    IdPTypeLDAP,
		Enabled: true,
		LDAP: &LDAPProfileConfig{
			URL:          url,
			BindDN:       envOrDefault("CULVERT_OPENLDAP_BIND_DN", "cn=admin,dc=corp,dc=example"),
			BindPassword: requiredEnv(t, "CULVERT_OPENLDAP_BIND_PASSWORD"),
			BaseDN:       envOrDefault("CULVERT_OPENLDAP_BASE_DN", "dc=corp,dc=example"),
			UserFilter:   "(uid=%s)",
		},
	}
}

func TestOpenLDAPInterop_ResolveIdentity(t *testing.T) {
	prov, err := NewLDAPIdPProvider(openLDAPInteropProfile(t))
	if err != nil {
		t.Fatalf("compile LDAP profile: %v", err)
	}
	if got := prov.Name(); got != "ldap:openldap-interop" {
		t.Fatalf("Name() = %q", got)
	}

	id, ok := prov.ResolveIdentity("alice", "alice-password")
	if !ok || id == nil {
		t.Fatalf("ResolveIdentity(alice) failed against a live directory")
	}
	if id.Sub != "uid=alice,ou=people,dc=corp,dc=example" {
		t.Errorf("Sub = %q, want the full user DN", id.Sub)
	}
	if id.Email != "alice@corp.example" {
		t.Errorf("Email = %q", id.Email)
	}
	if id.Name != "Alice Example" {
		t.Errorf("Name = %q, want displayName value", id.Name)
	}
	if id.Provider != "openldap-interop" {
		t.Errorf("Provider = %q, want the profile ID (authSource ldap:openldap-interop)", id.Provider)
	}
	found := false
	for _, g := range id.Groups {
		if strings.EqualFold(g, "cn=engineering,ou=groups,dc=corp,dc=example") {
			found = true
		}
	}
	if !found {
		t.Errorf("Groups = %v, want the full engineering group DN (memberOf)", id.Groups)
	}

	// Verify() delegates to the same resolution.
	if !prov.Verify("alice", "alice-password") {
		t.Error("Verify(alice) = false")
	}
	// LDAP is never interactive, even against a live directory.
	if url := prov.CaptiveLoginURL("corp.example", nil); url != "" {
		t.Errorf("CaptiveLoginURL = %q, want empty", url)
	}
}

func TestOpenLDAPInterop_Denials(t *testing.T) {
	prov, err := NewLDAPIdPProvider(openLDAPInteropProfile(t))
	if err != nil {
		t.Fatalf("compile LDAP profile: %v", err)
	}
	if id, ok := prov.ResolveIdentity("alice", "wrong-password"); ok || id != nil {
		t.Error("wrong password must be denied")
	}
	if id, ok := prov.ResolveIdentity("mallory", "whatever"); ok || id != nil {
		t.Error("unknown user must be denied")
	}
	if id, ok := prov.ResolveIdentity("alice", ""); ok || id != nil {
		t.Error("empty password must be denied without a directory round trip")
	}
}

func TestOpenLDAPInterop_NonMemberHasNoGroups(t *testing.T) {
	prov, err := NewLDAPIdPProvider(openLDAPInteropProfile(t))
	if err != nil {
		t.Fatal(err)
	}
	id, ok := prov.ResolveIdentity("bob", "bob-password")
	if !ok || id == nil {
		t.Fatalf("ResolveIdentity(bob) failed")
	}
	if len(id.Groups) != 0 {
		t.Errorf("bob's Groups = %v, want none", id.Groups)
	}
}

func TestOpenLDAPInterop_RequiredGroupGate(t *testing.T) {
	p := openLDAPInteropProfile(t)
	p.LDAP.RequiredGroup = "cn=engineering,ou=groups,dc=corp,dc=example"
	prov, err := NewLDAPIdPProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := prov.ResolveIdentity("alice", "alice-password"); !ok {
		t.Error("alice is a direct member of the required group and must pass")
	}
	if _, ok := prov.ResolveIdentity("bob", "bob-password"); ok {
		t.Error("bob is NOT in the required group and must be denied (fail closed)")
	}
}

func TestOpenLDAPInterop_RegistryIntegration(t *testing.T) {
	p := openLDAPInteropProfile(t)
	reg := swapIdPRegistry(t, p)
	creds := reg.EnabledCredentialProviders()
	if len(creds) != 1 || creds[0].Name() != "ldap:openldap-interop" {
		t.Fatalf("EnabledCredentialProviders = %v", providerNames(creds))
	}
	if reg.HasEnabledInteractiveProvider() {
		t.Error("a live LDAP profile must not make the registry SSO-capable")
	}
	id, ok := creds[0].ResolveIdentity("alice", "alice-password")
	if !ok || id == nil || id.Sub == "" {
		t.Fatalf("registry-compiled provider failed to authenticate: %v %v", id, ok)
	}
}

func TestOpenLDAPInterop_StagedDirectoryTest(t *testing.T) {
	p := openLDAPInteropProfile(t)
	rep := runLDAPDirectoryTest(p.LDAP, "alice", "alice-password")
	if !rep.OK {
		t.Fatalf("staged test failed against a live directory: %+v", rep)
	}
	steps := map[string]bool{}
	for _, s := range rep.Steps {
		steps[s.Name] = s.OK
	}
	for _, want := range []string{"reachable", "service_bind", "base_dn", "user_lookup", "user_auth"} {
		if !steps[want] {
			t.Errorf("step %q did not pass: %+v", want, rep.Steps)
		}
	}
	if rep.Identity == nil || rep.Identity.Sub != "uid=alice,ou=people,dc=corp,dc=example" {
		t.Errorf("identity summary = %+v", rep.Identity)
	}
	if rep.Identity != nil && rep.Identity.GroupCount != 1 {
		t.Errorf("GroupCount = %d, want 1", rep.Identity.GroupCount)
	}

	// Failure taxonomy: wrong service credential fails the service_bind stage
	// with an actionable hint, and later stages are not attempted.
	bad := *p.LDAP
	bad.BindPassword = "wrong-service-password"
	rep = runLDAPDirectoryTest(&bad, "", "")
	if rep.OK {
		t.Fatal("staged test must fail on a rejected service bind")
	}
	var sawBindFailure bool
	for _, s := range rep.Steps {
		if s.Name == "service_bind" && !s.OK && s.Action != "" {
			sawBindFailure = true
		}
		if s.Name == "base_dn" {
			t.Error("base_dn stage ran after a failed service bind")
		}
	}
	if !sawBindFailure {
		t.Errorf("service_bind failure not reported: %+v", rep.Steps)
	}
}

// TestOpenLDAPInterop_PreflightSucceedsThenPersistFails is the P1-3 proof
// with a REAL preflight: the ?preflight=connection stage passes against the
// live directory, and the SUBSEQUENT persistence failure must still leave
// the old provider live and the API reporting failure — the transaction
// point is persistence, not the preflight.
func TestOpenLDAPInterop_PreflightSucceedsThenPersistFails(t *testing.T) {
	p := openLDAPInteropProfile(t)

	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	reg := &IdPRegistry{live: make(map[string]IdentityProvider)}
	idpRegistry = reg
	if err := reg.Load(filepath.Join(t.TempDir(), "idp_profiles.json")); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if err := reg.Upsert(p); err != nil {
		t.Fatalf("seed Upsert: %v", err)
	}
	liveBefore, ok := reg.LiveProvider(p.ID)
	if !ok {
		t.Fatal("seed profile did not compile")
	}

	// Break persistence AFTER the working provider is live.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	reg.mu.Lock()
	reg.path = filepath.Join(blocker, "idp_profiles.json")
	reg.mu.Unlock()

	// Enabled edit WITH the connection preflight: the preflight succeeds
	// against the live directory; the persist step then fails.
	body := map[string]any{
		"name": "Renamed Interop AD", "type": "ldap", "enabled": true,
		"ldap": map[string]any{
			"url":    p.LDAP.URL,
			"bindDn": p.LDAP.BindDN,
			"baseDn": p.LDAP.BaseDN,
		},
	}
	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPut, "/api/idp/"+p.ID+"?preflight=connection", body)
	apiIdPItem(w, r, p.ID)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("preflight-then-persist-failure: status = %d, want 500 (body=%s)", w.Code, w.Body.String())
	}
	got := reg.Get(p.ID)
	if got == nil || got.Name != "OpenLDAP Interop" {
		t.Fatalf("stored profile changed after failed persistence: %+v", got)
	}
	liveAfter, ok := reg.LiveProvider(p.ID)
	if !ok || liveAfter != liveBefore {
		t.Fatal("old live provider was replaced despite the failed persistence")
	}
	// And it still authenticates.
	if id, ok := liveAfter.ResolveIdentity("alice", "alice-password"); !ok || id == nil {
		t.Fatal("old provider no longer authenticates after the failed mutation")
	}
}

// TestOpenLDAPInterop_LDAPS exercises the TLS transport against the
// container's ldaps listener. The fixture certificate is self-signed and
// rotates per container start, so this deliberately uses TLSSkipVerify (the
// warned dev-only path) — certificate *verification* semantics are covered
// by unit tests; this proves the TLS handshake + bind path end to end.
func TestOpenLDAPInterop_LDAPS(t *testing.T) {
	ldapsURL := os.Getenv("CULVERT_OPENLDAP_LDAPS_URL")
	if ldapsURL == "" {
		t.Skip("set CULVERT_OPENLDAP_LDAPS_URL to run the LDAPS interop test")
	}
	p := openLDAPInteropProfile(t)
	p.LDAP.URL = ldapsURL
	p.LDAP.TLSSkipVerify = true
	prov, err := NewLDAPIdPProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := prov.ResolveIdentity("alice", "alice-password")
	if !ok || id == nil || id.Sub == "" {
		t.Fatalf("LDAPS ResolveIdentity failed: %v %v", id, ok)
	}
}

// TestOpenLDAPInterop_StartTLS proves the StartTLS upgrade path on the plain
// listener (osixia enables StartTLS with the same generated certificate).
func TestOpenLDAPInterop_StartTLS(t *testing.T) {
	p := openLDAPInteropProfile(t)
	if !strings.HasPrefix(strings.ToLower(p.LDAP.URL), "ldap://") {
		t.Skip("StartTLS test requires a plain ldap:// CULVERT_OPENLDAP_URL")
	}
	p.LDAP.StartTLS = true
	p.LDAP.TLSSkipVerify = true // self-signed fixture certificate
	prov, err := NewLDAPIdPProvider(p)
	if err != nil {
		t.Fatal(err)
	}
	id, ok := prov.ResolveIdentity("alice", "alice-password")
	if !ok || id == nil {
		t.Fatalf("StartTLS ResolveIdentity failed")
	}
}
