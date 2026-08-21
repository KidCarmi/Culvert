package main

// authpolicy_ldap_test.go — Slice 5 wall (ADR-0025): CredentialRequired
// providerRefs activation + LDAP policy integration.
//
//   - Write door: CR refs accept enabled credential-capable (OIDC/LDAP)
//     profiles and reject SAML/disabled/missing refs; SSO refs keep rejecting
//     LDAP; Exempt still rejects refs entirely.
//   - Runtime: CR + eligible LDAP ref challenges (407) and a presented Basic
//     credential resolved by the LDAP provider yields a full Identity whose
//     groups/authSource reach Stage-2; CR refs resolving to zero eligible
//     providers fail CLOSED (403, no dangling 407).
//   - Diagnostics: auth_cr_no_eligible_provider / auth_cr_providerref_
//     unavailable rows; LDAP transport-hygiene rows.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Write-door validation ────────────────────────────────────────────────────

func TestCRProviderRefs_ShapeAcceptedOnCR(t *testing.T) {
	spec := &AuthRuleSpec{Outcome: OutcomeCredentialRequired, ProviderRefs: []string{"corp-ad"}}
	if err := validateAuthOutcomeAndProviders(spec); err != nil {
		t.Fatalf("CR providerRefs must pass shape validation now: %v", err)
	}
	// Shape rules still apply.
	bad := &AuthRuleSpec{Outcome: OutcomeCredentialRequired, ProviderRefs: []string{" corp-ad "}}
	if err := validateAuthOutcomeAndProviders(bad); err == nil {
		t.Fatal("whitespace-padded refs must still be rejected")
	}
	// Exempt still rejects refs.
	ex := &AuthRuleSpec{Outcome: OutcomeExempt, ProviderRefs: []string{"corp-ad"}}
	if err := validateAuthOutcomeAndProviders(ex); err == nil {
		t.Fatal("Exempt must keep rejecting providerRefs")
	}
}

func TestCRProviderRefs_LiveValidation(t *testing.T) {
	saml := &IdPProfile{
		ID: "corp-saml", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: true,
		SAML: &SAMLProfileConfig{MetadataXML: clusterAuthSAMLMetadataXML(t)},
	}
	disabledLDAP := ldapTestProfile("ldap-off", "Disabled AD")
	disabledLDAP.Enabled = false
	swapIdPRegistry(t, ldapTestProfile("corp-ad", "Corporate AD"), saml, disabledLDAP)

	cr := func(refs ...string) *AuthRuleSpec {
		return &AuthRuleSpec{Outcome: OutcomeCredentialRequired, ProviderRefs: refs}
	}
	if err := validateAuthProviderRefsLive(cr("corp-ad")); err != nil {
		t.Fatalf("enabled LDAP ref must be eligible for CR: %v", err)
	}
	if err := validateAuthProviderRefsLive(cr("corp-saml")); err == nil || !strings.Contains(err.Error(), "credential-capable") {
		t.Errorf("SAML ref on CR must be rejected, got %v", err)
	}
	if err := validateAuthProviderRefsLive(cr("ldap-off")); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Errorf("disabled LDAP ref must be rejected at the write door, got %v", err)
	}
	if err := validateAuthProviderRefsLive(cr("ghost")); err == nil {
		t.Error("missing ref must be rejected at the write door")
	}
	// SSO refs keep their interactive-only contract with the same combined door.
	sso := &AuthRuleSpec{Outcome: OutcomeSSORequired, ProviderRefs: []string{"corp-ad"}}
	if err := validateAuthProviderRefsLive(sso); err == nil || !strings.Contains(err.Error(), "not an interactive") {
		t.Errorf("LDAP ref on SSORequired must stay rejected, got %v", err)
	}
}

// ── Runtime ──────────────────────────────────────────────────────────────────

// ldapStubProvider stands in for a compiled LDAP provider so runtime tests
// need no live directory: it accepts one username/password and returns a full
// directory-shaped identity.
type ldapStubProvider struct {
	profileID  string
	user, pass string
	identity   *Identity
}

func (p *ldapStubProvider) Verify(u, pw string) bool {
	_, ok := p.ResolveIdentity(u, pw)
	return ok
}

func (p *ldapStubProvider) ResolveIdentity(u, pw string) (*Identity, bool) {
	if u != p.user || pw != p.pass {
		return nil, false
	}
	return cloneIdentity(p.identity), true
}
func (p *ldapStubProvider) Name() string                                 { return "ldap:" + p.profileID }
func (p *ldapStubProvider) DisplayName() string                          { return "Stub AD" }
func (p *ldapStubProvider) CaptiveLoginURL(string, *http.Request) string { return "" }

// installLDAPRegistry installs a registry holding one enabled LDAP profile
// backed by the stub provider.
func installLDAPRegistry(t *testing.T, profileID string, stub *ldapStubProvider) {
	t.Helper()
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	profile := ldapTestProfile(profileID, "Corporate AD")
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{profile},
		live:     map[string]IdentityProvider{profileID: stub},
	}
}

func crRuleWithRefs(name, host string, refs ...string) PolicyRule {
	r := validCRRule()
	r.Name, r.DestFQDN = name, host
	r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}}
	r.Auth.ProviderRefs = refs
	return r
}

func TestCR_LDAPRef_ChallengeThenLDAPAuthYieldsIdentity(t *testing.T) {
	setupAuthGateTest(t)
	const host = "cr-ldap.example.test"
	stub := &ldapStubProvider{
		profileID: "corp-ad", user: "alice", pass: "ldap-pass",
		identity: &Identity{
			Sub:      "CN=Alice,OU=Users,DC=corp,DC=example",
			Email:    "alice@corp.example",
			Name:     "Alice Example",
			Groups:   []string{"CN=Engineering,OU=Groups,DC=corp,DC=example"},
			Provider: "corp-ad",
		},
	}
	installLDAPRegistry(t, "corp-ad", stub)
	policyStore.Add(crRuleWithRefs("cr-ldap", host, "corp-ad"))

	// 1. No credentials → deterministic 407 Basic challenge (refs eligible).
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("no-creds CR with an eligible LDAP ref must 407, got %d", w.Code)
	}

	// 2. Basic credentials validated by the LDAP provider → full identity.
	r := makeRequest("http://"+host+"/", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:ldap-pass")))
	w = httptest.NewRecorder()
	outcome, proceed := resolveRequestAuth(w, r, "127.0.0.1", "cr-ldap-test")
	if !proceed {
		t.Fatalf("LDAP-validated credentials rejected: status=%d body=%q", w.Code, w.Body.String())
	}
	if outcome.identity != "CN=Alice,OU=Users,DC=corp,DC=example" {
		t.Errorf("identity = %q, want the user DN", outcome.identity)
	}
	if len(outcome.groups) != 1 || outcome.groups[0] != "CN=Engineering,OU=Groups,DC=corp,DC=example" {
		t.Errorf("groups = %v, want the directory group DNs (Stage-2 SourceGroup input)", outcome.groups)
	}
	if outcome.source != "corp-ad" {
		t.Errorf("authSource = %q, want the LDAP profile ID (Stage-2 AuthSource input)", outcome.source)
	}

	// 3. Wrong password → 407, never an identity.
	r = makeRequest("http://"+host+"/", nil)
	r.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:wrong")))
	w = httptest.NewRecorder()
	if _, proceed := resolveRequestAuth(w, r, "127.0.0.1", "cr-ldap-test-bad"); proceed {
		t.Fatal("wrong password must fail closed")
	}
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("failed credentials must 407, got %d", w.Code)
	}
}

func TestCR_RefsResolveToZeroEligible_FailsClosed(t *testing.T) {
	setupAuthGateTest(t)
	const host = "cr-ghost.example.test"
	// Registry has NO matching profile — the ref is deleted/disabled drift.
	installLDAPRegistry(t, "some-other", &ldapStubProvider{profileID: "some-other"})
	policyStore.Add(crRuleWithRefs("cr-ghost", host, "deleted-ldap"))

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("CR with zero eligible providerRefs must fail CLOSED 403, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "no eligible credential provider") {
		t.Errorf("403 body should explain the fail-closed reason: %q", w.Body.String())
	}
	e := findLogByHost(t, host)
	if e.Status != "CRED_DENIED" {
		t.Errorf("log status = %q, want CRED_DENIED", e.Status)
	}
}

func TestCR_EmptyRefs_GlobalChainUnchanged(t *testing.T) {
	setupAuthGateTest(t)
	const host = "cr-plain.example.test"
	policyStore.Add(crRuleWithRefs("cr-plain", host)) // no refs

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CR without refs must keep the 407 challenge, got %d", w.Code)
	}
}

func TestCountEligibleCredentialProviderRefs(t *testing.T) {
	saml := &IdPProfile{
		ID: "corp-saml", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: true,
		SAML: &SAMLProfileConfig{MetadataXML: clusterAuthSAMLMetadataXML(t)},
	}
	swapIdPRegistry(t, ldapTestProfile("corp-ad", "AD"), saml)
	if got := countEligibleCredentialProviderRefs([]string{"corp-ad"}); got != 1 {
		t.Errorf("eligible = %d, want 1 for an enabled LDAP ref", got)
	}
	if got := countEligibleCredentialProviderRefs([]string{"corp-saml"}); got != 0 {
		t.Errorf("eligible = %d, want 0 for a SAML ref (browser-only)", got)
	}
	if got := countEligibleCredentialProviderRefs([]string{"ghost", "corp-ad"}); got != 1 {
		t.Errorf("eligible = %d, want 1 with one stale + one live ref", got)
	}
}

// ── Diagnostics ──────────────────────────────────────────────────────────────

func TestAuthCRProviderRefDiagnostics(t *testing.T) {
	swapIdPRegistry(t, ldapTestProfile("corp-ad", "AD"))

	ok := crRuleWithRefs("cr-ok", "a.example", "corp-ad")
	stale := crRuleWithRefs("cr-stale", "b.example", "corp-ad", "gone")
	dead := crRuleWithRefs("cr-dead", "c.example", "gone")

	checks := authCRProviderRefDiagnostics([]PolicyRule{ok, stale, dead})
	var gotFail, gotWarn bool
	for _, c := range checks {
		switch c.Code {
		case "auth_cr_no_eligible_provider":
			gotFail = true
			if !strings.Contains(c.Message, "cr-dead") {
				t.Errorf("FAIL row should name the dead rule: %s", c.Message)
			}
		case "auth_cr_providerref_unavailable":
			gotWarn = true
			if !strings.Contains(c.Message, "cr-stale") {
				t.Errorf("WARN row should name the stale rule: %s", c.Message)
			}
		}
	}
	if !gotFail || !gotWarn {
		t.Fatalf("expected FAIL+WARN rows, got %+v", checks)
	}
	// Fully-eligible rules contribute nothing.
	if got := authCRProviderRefDiagnostics([]PolicyRule{ok}); len(got) != 0 {
		t.Errorf("fully-eligible CR rule produced findings: %+v", got)
	}
}

func TestAuthLDAPProfileDiagnostics(t *testing.T) {
	plain := ldapTestProfile("ldap-plain", "Plain AD")
	plain.LDAP.URL = "ldap://dc:389"
	unverified := ldapTestProfile("ldap-skipverify", "SkipVerify AD")
	unverified.LDAP.TLSSkipVerify = true
	swapIdPRegistry(t, plain, unverified)

	codes := map[string]bool{}
	for _, c := range authLDAPProfileDiagnostics() {
		codes[c.Code] = true
	}
	if !codes["ldap_plaintext_transport"] || !codes["ldap_tls_unverified"] {
		t.Fatalf("missing transport-hygiene rows: %v", codes)
	}

	// StartTLS over plain LDAP is not flagged as plaintext.
	startTLS := ldapTestProfile("ldap-starttls", "StartTLS AD")
	startTLS.LDAP.URL = "ldap://dc:389"
	startTLS.LDAP.StartTLS = true
	swapIdPRegistry(t, startTLS)
	for _, c := range authLDAPProfileDiagnostics() {
		if c.Code == "ldap_plaintext_transport" {
			t.Errorf("StartTLS profile flagged as plaintext: %+v", c)
		}
	}
}
