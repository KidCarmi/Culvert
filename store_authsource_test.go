package main

// F5 — Entry.AuthSource attribution contract.
//
// The auth_source SIEM field was declared on logstore.Entry from the start but
// never populated. F5 populates it from AUTHORITATIVE SERVER-SIDE auth state
// only (resolveRequestAuth's resolved source / ProxyIdentity.AuthSource) via
// the AuthLogFields carrier. These tests pin one deterministic attribution per
// supported state, and the spoof-resistance invariant: no client-controlled
// header or request field may influence AuthSource.
//
// Deliberately-unattributed rows (empty AuthSource, documented on the
// AuthLogFields.AuthSource contract): pre-auth blocks (IP_BLOCKED /
// RATE_LIMITED), AUTH_FAIL (no backend authenticated the credentials), SOCKS5
// (boolean auth), and the inner scanner block rows (pending the M2 typed
// identity plumbing). Empty means "unattributed", never "unauthenticated".

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// authSourceForHost scans the request-log ring newest-first for the first
// entry about destHost and returns its auth_source, or ok=false.
func authSourceForHost(t *testing.T, destHost, status string) (string, bool) {
	t.Helper()
	for _, e := range logGet() { // newest-first
		if e.Host == destHost && (status == "" || e.Status == status) {
			return e.AuthSource, true
		}
	}
	return "", false
}

func destHostOf(t *testing.T, rawURL string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	return u.Host
}

// TestAuthSource_IdPRegistryBasic: Basic credentials resolved by an IdP-registry
// provider attribute to the provider's ID (Identity.Provider via
// identityAuthSource) — the OIDC-registry state.
func TestAuthSource_IdPRegistryBasic(t *testing.T) {
	backend, _ := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), engRule())

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "alice", "eng-token", nil); got != http.StatusOK {
		t.Fatalf("authenticated GET: status %d, want 200", got)
	}
	src, ok := authSourceForHost(t, destHostOf(t, backend.URL), "OK")
	if !ok {
		t.Fatal("no OK log entry for the backend host")
	}
	if src != "test-idp" {
		t.Errorf("auth_source = %q, want %q (IdP-registry provider ID)", src, "test-idp")
	}
}

// TestAuthSource_SessionCookieProvider: a signed session cookie attributes to
// the session's Provider — covering the browser-SSO path. A SAML-shaped
// provider ID proves the scheme-prefixed form round-trips verbatim.
func TestAuthSource_SessionCookieProvider(t *testing.T) {
	backend, _ := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(),
		[]PolicyRule{{Priority: 1, Name: "eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow}})
	if !sessionSecretSet() {
		initSessionSecret()
	}
	val, err := encodeSession(&Session{Sub: "alice", Email: "alice@example.com", Groups: []string{"engineering"}, Provider: "saml:corp", Exp: time.Now().Add(time.Hour).Unix(), Jti: newSessionJti()})
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}
	cookie := &http.Cookie{Name: sessionCookieName, Value: val, Path: "/"} // #nosec G124 -- request-side fixture

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", cookie); got != http.StatusOK {
		t.Fatalf("session GET: status %d, want 200", got)
	}
	src, ok := authSourceForHost(t, destHostOf(t, backend.URL), "OK")
	if !ok {
		t.Fatal("no OK log entry for the backend host")
	}
	if src != "saml:corp" {
		t.Errorf("auth_source = %q, want %q (session Provider)", src, "saml:corp")
	}
}

// TestAuthSource_LocalBasic: legacy local bcrypt credentials attribute "local".
func TestAuthSource_LocalBasic(t *testing.T) {
	backend, _ := startCountingBackend(t)
	setupProxyTest(t)
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{}
	t.Cleanup(func() { idpRegistry = origReg })
	if err := cfg.SetAuth("admin", "admin-pass"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() { cfg.SetAuth("", "") }) //nolint:errcheck // test cleanup
	policyStore.Add(PolicyRule{Priority: 1, Name: "any-allow", DestFQDN: "*", Action: ActionAllow})

	srv := httptest.NewServer(http.HandlerFunc(handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, _ := url.Parse(srv.URL)

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "admin", "admin-pass", nil); got != http.StatusOK {
		t.Fatalf("local-auth GET: status %d, want 200", got)
	}
	src, ok := authSourceForHost(t, destHostOf(t, backend.URL), "OK")
	if !ok {
		t.Fatal("no OK log entry for the backend host")
	}
	if src != "local" {
		t.Errorf("auth_source = %q, want %q", src, "local")
	}
}

// TestAuthSource_DefaultExemptUnauth: default-Exempt (open) posture — unmatched
// unauthenticated traffic attributes "unauth", and a spoofed X-User-Identity
// header must not change that (server-side state only).
func TestAuthSource_DefaultExemptUnauth(t *testing.T) {
	backend, _ := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(),
		[]PolicyRule{{Priority: 1, Name: "any-allow", DestFQDN: "*", Action: ActionAllow}})
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })

	// Include a spoofed identity header alongside no credentials: attribution
	// must remain the server-resolved "unauth".
	if got := spoofedGet(t, proxyURL, backend.URL+"/", "alice"); got != http.StatusOK {
		t.Fatalf("exempt GET: status %d, want 200", got)
	}
	src, ok := authSourceForHost(t, destHostOf(t, backend.URL), "OK")
	if !ok {
		t.Fatal("no OK log entry for the backend host")
	}
	if src != "unauth" {
		t.Errorf("auth_source = %q, want %q (default-Exempt, spoof ignored)", src, "unauth")
	}
}

// TestAuthSource_NoBackendUnauth: the no-backend inert posture attributes
// "unauth" (no credentials, no validator).
func TestAuthSource_NoBackendUnauth(t *testing.T) {
	backend, _ := startCountingBackend(t)
	setupProxyTest(t)
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{}
	t.Cleanup(func() { idpRegistry = origReg })
	policyStore.Add(PolicyRule{Priority: 1, Name: "any-allow", DestFQDN: "*", Action: ActionAllow})

	srv := httptest.NewServer(http.HandlerFunc(handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, _ := url.Parse(srv.URL)

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", nil); got != http.StatusOK {
		t.Fatalf("no-backend GET: status %d, want 200", got)
	}
	src, ok := authSourceForHost(t, destHostOf(t, backend.URL), "OK")
	if !ok {
		t.Fatal("no OK log entry for the backend host")
	}
	if src != "unauth" {
		t.Errorf("auth_source = %q, want %q", src, "unauth")
	}
}

// TestAuthSource_ScopedExempt: a matching scoped Exempt auth rule attributes
// "exempt" — deliberately distinct from the default-open "unauth".
func TestAuthSource_ScopedExempt(t *testing.T) {
	backend, _ := startCountingBackend(t)
	setupProxyTest(t)
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{}
	t.Cleanup(func() { idpRegistry = origReg })
	if err := cfg.SetAuth("admin", "admin-pass"); err != nil { // auth-required posture
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() { cfg.SetAuth("", "") }) //nolint:errcheck // test cleanup

	enabled := true
	policyStore.Add(PolicyRule{
		Priority: 1, Name: "exempt-lab", RuleType: ruleTypeAuth, Enabled: &enabled,
		SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}},
		DestFQDN:     "*",
		Auth:         &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "f5 test"},
	})
	policyStore.Add(PolicyRule{Priority: 2, Name: "any-allow", DestFQDN: "*", Action: ActionAllow})

	srv := httptest.NewServer(http.HandlerFunc(handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, _ := url.Parse(srv.URL)

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", nil); got != http.StatusOK {
		t.Fatalf("scoped-exempt GET: status %d, want 200", got)
	}
	src, ok := authSourceForHost(t, destHostOf(t, backend.URL), "OK")
	if !ok {
		t.Fatal("no OK log entry for the backend host")
	}
	if src != "exempt" {
		t.Errorf("auth_source = %q, want %q (scoped Exempt rule)", src, "exempt")
	}
}

// TestAuthSource_TunnelCloseAttribution: the TUNNEL_CLOSED accounting entry
// carries the resolved auth source from ProxyIdentity.
func TestAuthSource_TunnelCloseAttribution(t *testing.T) {
	id := ProxyIdentity{ClientIP: "198.51.100.7", Identity: "alice", AuthSource: "oidc:okta"}
	recordTunnelCloseGated(nil, id, "CONNECT", "tunnel-f5.example", 10, 20, time.Now(), "bypass")
	src, ok := authSourceForHost(t, "tunnel-f5.example", "TUNNEL_CLOSED")
	if !ok {
		t.Fatal("no TUNNEL_CLOSED entry")
	}
	if src != "oidc:okta" {
		t.Errorf("tunnel-close auth_source = %q, want %q", src, "oidc:okta")
	}
}

// TestAuthSource_ZeroValueWireIdentical: an empty AuthSource stays off the wire
// (omitempty) — pre-F5 rows and unattributed rows are byte-identical.
func TestAuthSource_ZeroValueWireIdentical(t *testing.T) {
	var e LogEntry
	AuthLogFields{}.applyTo(&e)
	raw, err := json.Marshal(e)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := m["auth_source"]; present {
		t.Errorf("empty AuthSource serialized: %s", raw)
	}

	e2 := LogEntry{}
	AuthLogFields{AuthSource: "local"}.applyTo(&e2)
	if e2.AuthSource != "local" {
		t.Errorf("applyTo did not copy AuthSource: %q", e2.AuthSource)
	}
}

// TestAuthSource_CredentialRequiredRow: the Stage-1 CredentialRequired denial
// row attributes "unauth" (the request had no credentials; the outcome and rule
// are carried separately).
func TestAuthSource_CredentialRequiredRow(t *testing.T) {
	backend, _ := startCountingBackend(t)
	setupProxyTest(t)
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{}
	t.Cleanup(func() { idpRegistry = origReg })
	if err := cfg.SetAuth("admin", "admin-pass"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() { cfg.SetAuth("", "") }) //nolint:errcheck // test cleanup

	enabled := true
	policyStore.Add(PolicyRule{
		Priority: 1, Name: "cred-req", RuleType: ruleTypeAuth, Enabled: &enabled,
		SubjectMatch: &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}},
		DestFQDN:     "*",
		Auth:         &AuthRuleSpec{Outcome: OutcomeCredentialRequired, Owner: "ops", Reason: "f5 test"},
	})

	srv := httptest.NewServer(http.HandlerFunc(handleRequest))
	t.Cleanup(srv.Close)
	proxyURL, _ := url.Parse(srv.URL)

	if got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", nil); got != http.StatusProxyAuthRequired {
		t.Fatalf("cred-required GET: status %d, want 407", got)
	}
	src, ok := authSourceForHost(t, destHostOf(t, backend.URL), "CRED_REQUIRED")
	if !ok {
		t.Fatal("no CRED_REQUIRED entry")
	}
	if src != "unauth" {
		t.Errorf("CRED_REQUIRED auth_source = %q, want %q", src, "unauth")
	}
}
