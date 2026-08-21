package main

// authpolicy_ldap_test.go — LDAP × Authentication Policy wall (ADR-0027,
// hardening round P1-1).
//
// CredentialRequired providerRefs is NOT activated: an earlier draft
// activation was reverted because presented Proxy-Authorization credentials
// resolve through the GLOBAL validator chain before the no-credentials
// Stage-1 branch, so per-rule provider pinning was only half-enforced. This
// wall pins the reverted contract:
//
//   - CR with providerRefs is rejected at validation (write door included).
//   - CR with empty refs behaves exactly as before (407 challenge; the
//     global chain validates presented credentials).
//   - LDAP satisfies ORDINARY CredentialRequired and yields a full Identity.
//   - Provider-specific authorization is expressed in Stage 2:
//     AuthSource/SourceGroup narrow LDAP-authenticated traffic.

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Write-door validation: CR providerRefs stays reserved ────────────────────

func TestCRProviderRefs_RejectedAsReserved(t *testing.T) {
	spec := &AuthRuleSpec{Outcome: OutcomeCredentialRequired, ProviderRefs: []string{"corp-ad"}}
	err := validateAuthOutcomeAndProviders(spec)
	if err == nil || !strings.Contains(err.Error(), "reserved for a future program") {
		t.Fatalf("CR providerRefs must be rejected as reserved, got %v", err)
	}
	// Full rule validation rejects it too (the path the API write door uses).
	rule := validCRRule()
	rule.Auth.ProviderRefs = []string{"corp-ad"}
	if _, err := validateAuthRule(rule); err == nil {
		t.Fatal("validateAuthRule must reject CR providerRefs")
	}
	// Exempt still rejects refs; SSORequired still accepts shape-valid refs.
	ex := &AuthRuleSpec{Outcome: OutcomeExempt, ProviderRefs: []string{"corp-ad"}}
	if err := validateAuthOutcomeAndProviders(ex); err == nil {
		t.Fatal("Exempt must keep rejecting providerRefs")
	}
	sso := &AuthRuleSpec{Outcome: OutcomeSSORequired, ProviderRefs: []string{"corp-oidc"}}
	if err := validateAuthOutcomeAndProviders(sso); err != nil {
		t.Fatalf("SSORequired shape-valid refs must stay accepted: %v", err)
	}
}

func TestCRProviderRefs_APIRejectsAndStoresNothing(t *testing.T) {
	withConfigVersionsDir(t)
	withFreshPolicyStore(t)
	swapIdPRegistry(t, ldapTestProfile("corp-ad", "Corporate AD"))

	body := crRuleMap("cr-with-refs")
	body["auth"].(map[string]any)["providerRefs"] = []string{"corp-ad"}
	w := httptest.NewRecorder()
	apiAuthPolicy(w, roleReq(RoleAdmin, "POST", "/api/authpolicy", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("CR + providerRefs POST = %d, want 400 (body=%s)", w.Code, w.Body.String())
	}
	if len(listAuthRules()) != 0 {
		t.Fatal("rejected CR rule must not be stored")
	}
}

// ── Runtime: LDAP satisfies ORDINARY CredentialRequired ──────────────────────

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

func plainCRRule(name, host string) PolicyRule {
	r := validCRRule()
	r.Name, r.DestFQDN = name, host
	r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}}
	return r
}

func aliceStub() *ldapStubProvider {
	return &ldapStubProvider{
		profileID: "corp-ad", user: "alice", pass: "ldap-pass",
		identity: &Identity{
			Sub:      "CN=Alice,OU=Users,DC=corp,DC=example",
			Email:    "alice@corp.example",
			Name:     "Alice Example",
			Groups:   []string{"CN=Engineering,OU=Groups,DC=corp,DC=example"},
			Provider: "corp-ad",
		},
	}
}

func TestCR_OrdinaryRule_LDAPChallengeThenAuthYieldsIdentity(t *testing.T) {
	setupAuthGateTest(t)
	const host = "cr-ldap.example.test"
	installLDAPRegistry(t, "corp-ad", aliceStub())
	policyStore.Add(plainCRRule("cr-ldap", host))

	// 1. No credentials → deterministic 407 Basic challenge (unchanged CR).
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("no-creds CR must 407, got %d", w.Code)
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

// ── Stage 2: AuthSource/SourceGroup narrow LDAP-authorized traffic ───────────
//
// This is THE supported way to scope traffic to a specific LDAP provider (in
// place of the reverted CR providerRefs): authenticate with ordinary CR, then
// authorize in Stage 2 on the resolved identity.
func TestStage2_AuthSourceAndSourceGroupNarrowLDAPTraffic(t *testing.T) {
	withFreshPolicyStore(t)
	const host = "stage2.example.test"
	enabled := true
	policyStore.Add(PolicyRule{
		Priority:    10,
		Name:        "allow-corp-ad-engineering",
		Enabled:     &enabled,
		Action:      ActionAllow,
		AuthSource:  "ldap:corp-ad",
		SourceGroup: "CN=Engineering,OU=Groups,DC=corp,DC=example",
		DestFQDN:    host,
	})

	// alice: authenticated by corp-ad, in Engineering → matches.
	m := policyStore.Evaluate("10.0.0.5", "CN=Alice,OU=Users,DC=corp,DC=example",
		"corp-ad", host, []string{"CN=Engineering,OU=Groups,DC=corp,DC=example"})
	if m == nil || m.Rule == nil || m.Rule.Name != "allow-corp-ad-engineering" {
		t.Fatalf("LDAP-authenticated engineering member must match the scoped allow rule, got %+v", m)
	}

	// bob: same provider, NOT in the group → no match (default deny backstop).
	if m := policyStore.Evaluate("10.0.0.5", "CN=Bob,OU=Users,DC=corp,DC=example",
		"corp-ad", host, nil); m != nil {
		t.Fatalf("non-member must not match the group-scoped rule, got %+v", m)
	}

	// Same group claim from a DIFFERENT provider (cross-scheme) → no match:
	// the ldap:-scoped AuthSource must not be satisfiable by an OIDC source.
	if m := policyStore.Evaluate("10.0.0.5", "alice@corp.example",
		"oidc:corp-ad", host, []string{"CN=Engineering,OU=Groups,DC=corp,DC=example"}); m != nil {
		t.Fatalf("oidc: source must not satisfy an ldap:-scoped AuthSource rule, got %+v", m)
	}
}

// ── Diagnostics (transport hygiene rows survive the P1-1 revert) ─────────────

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
