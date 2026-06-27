package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Slice 3 (S2) — runtime wiring of the global defaultAuthOutcome. Auth rules
// evaluate first; the global default applies only on no-match. Default mode is
// byte-identical to today; only Exempt mode changes (scoped rules now enforce,
// unmatched no-credential traffic opens with authSource="unauth"). See
// AUTH-POLICY-DEFAULTAUTHOUTCOME-SPEC.md.

// nonBrowserReq builds a non-browser, non-CONNECT no-cred request.
func nonBrowserReq(host string) *http.Request {
	return makeRequest("http://"+host+"/", map[string]string{"User-Agent": "curl/8.0"})
}

// basicAuthReq builds a request presenting Basic proxy credentials.
func basicAuthReq(host, user, pass string) *http.Request {
	return makeRequest("http://"+host+"/", map[string]string{
		"Proxy-Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)),
	})
}

// allowFor adds a Stage-2 allow rule scoped to host for the given authSource.
func allowFor(name, host, authSource string) {
	policyStore.Add(PolicyRule{Priority: 50, Name: name, Action: ActionAllow, AuthSource: authSource, DestFQDN: host})
}

// ── Default-mode parity (byte-identical to pre-Slice-3) ──────────────────────

func TestS3_DefaultMode_Parity(t *testing.T) {
	// Backend present, default Default, no rule, no creds → today's 407.
	setupAuthGateTest(t) // sets local user "alice" (credential backend)
	const host = "s3-parity-backend.example.test"
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("Default+backend+no-creds must 407 (parity), got %d", w.Code)
	}

	// No backend, default Default → Stage-1 inert: no 407, request reaches
	// Stage-2 (default-deny here).
	setupProxyTest(t) // fresh cfg: no user/provider, default Default
	const host2 = "s3-parity-nobackend.example.test"
	w = httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host2))
	if w.Code == http.StatusProxyAuthRequired {
		t.Fatalf("Default+no-backend must stay inert (no 407), got %d", w.Code)
	}
	if e := findLogByHost(t, host2); e.Status != "POLICY_DEFAULT_DENY" {
		t.Errorf("Default+no-backend must reach Stage-2 default-deny, got %+v", e)
	}
}

// ── no-match Exempt opens unmatched no-credential traffic (authSource=unauth) ─

func TestS3_DefaultExempt_OpensUnmatched_AuthSourceUnauth(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t) // restore the global store on cleanup (no rule leak)
	cfg.SetUnauthMode(true) // open mode (defaultAuthOutcome Exempt)
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	const host = "s3-defexempt-unauth.example.test"
	allowFor("allow-unauth", host, "unauth") // matches only if authSource=="unauth"

	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	e := findLogByHost(t, host)
	if e.RuleMatched != "allow-unauth" {
		t.Errorf("default-Exempt traffic must reach Stage-2 as authSource=unauth and match the unauth allow rule, got %+v", e)
	}
	if e.AuthOutcome != "" {
		t.Errorf("default-Exempt (no scoped rule) must carry NO auth outcome, got %q", e.AuthOutcome)
	}
}

// ── Stage-2 default-deny still blocks after default Exempt (open != allow) ────

func TestS3_DefaultExempt_DefaultDenyStillBlocks(t *testing.T) {
	setupAuthGateTest(t)
	cfg.SetUnauthMode(true)
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	const host = "s3-defexempt-deny.example.test"
	// No allow rule → default-deny must still block.
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	if e := findLogByHost(t, host); e.Status != "POLICY_DEFAULT_DENY" {
		t.Errorf("open default-Exempt must still hit Stage-2 default-deny, got %+v", e)
	}
}

// ── Scoped rules win over default Exempt ─────────────────────────────────────

func TestS3_ScopedCR_OverDefaultExempt_407(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	cfg.SetUnauthMode(true) // default Exempt
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	const host = "s3-cr-over-exempt.example.test"
	policyStore.Add(p2s3CR("cr-1", host))

	start := crCount()
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("scoped CR must enforce over default Exempt (407), got %d", w.Code)
	}
	if crCount() != start+1 {
		t.Error("scoped CR must fire (metric) over default Exempt")
	}
}

func TestS3_ScopedSSO_OverDefaultExempt_BrowserAnd403(t *testing.T) {
	// Browser → 302.
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	cfg.SetUnauthMode(true) // default Exempt
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	const host = "s3-sso-over-exempt.example.test"
	policyStore.Add(localSSO(host))

	w := httptest.NewRecorder()
	handleRequest(w, browserReq(host))
	if w.Code != http.StatusFound {
		t.Fatalf("scoped SSO must 302 a browser over default Exempt, got %d", w.Code)
	}
	// Non-browser → 403 fail-closed.
	w = httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	if w.Code != http.StatusForbidden {
		t.Fatalf("scoped SSO must 403 a non-browser over default Exempt, got %d", w.Code)
	}
}

// Explicit scoped Exempt rule → authSource="exempt" (distinct from default-Exempt
// "unauth"): it matches a Stage-2 rule scoped to authSource=exempt.
func TestS3_ScopedExempt_OverDefaultExempt_AuthSourceExempt(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	cfg.SetUnauthMode(true) // default Exempt
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	const host = "s3-scopedexempt.example.test"
	policyStore.Add(slice7ExemptRule(host)) // scoped Exempt
	allowFor("allow-exempt", host, "exempt")

	start := exemptCount()
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	if exemptCount() != start+1 {
		t.Error("scoped Exempt must fire over default Exempt")
	}
	e := findLogByHost(t, host)
	if e.RuleMatched != "allow-exempt" {
		t.Errorf("scoped Exempt must set authSource=exempt and match the exempt allow rule, got %+v", e)
	}
	if e.AuthOutcome != "Exempt" {
		t.Errorf("scoped Exempt must carry AuthOutcome=Exempt, got %q", e.AuthOutcome)
	}
}

// ── Kill switch forces effectiveDefault → Default ────────────────────────────

func TestS3_KillSwitch_ForcesDefault(t *testing.T) {
	setupAuthGateTest(t)
	cfg.SetUnauthMode(true) // default Exempt …
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	setAuthExemptDisabled(true) // … but kill switch forces Default (cleanup in setupAuthGateTest)

	// No scoped rule, no creds → forced Default → 407 (open is suppressed).
	const host = "s3-killswitch.example.test"
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("kill switch must force Default (407) over default Exempt, got %d", w.Code)
	}

	// A scoped Exempt rule is suppressed under the kill switch (falls through to
	// the forced Default).
	withFreshPolicyStore(t)
	const host2 = "s3-killswitch-exempt.example.test"
	policyStore.Add(slice7ExemptRule(host2))
	w = httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host2))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("kill switch must suppress a scoped Exempt rule (407), got %d", w.Code)
	}

	// A scoped CR rule is NOT disabled by the kill switch — still 407.
	withFreshPolicyStore(t)
	const host3 = "s3-killswitch-cr.example.test"
	policyStore.Add(p2s3CR("cr-ks", host3))
	start := crCount()
	w = httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host3))
	if w.Code != http.StatusProxyAuthRequired || crCount() != start+1 {
		t.Fatalf("kill switch must NOT disable scoped CR (407 + metric), got code=%d", w.Code)
	}
}

// ── Presented credentials are never default-exempted ─────────────────────────

func TestS3_PresentedCreds_NotDefaultExempted(t *testing.T) {
	setupAuthGateTest(t)    // backend user alice/secret
	cfg.SetUnauthMode(true) // default Exempt
	t.Cleanup(func() { cfg.SetUnauthMode(false) })

	// Bad creds in open mode → 407, NOT opened.
	const host = "s3-badcreds.example.test"
	w := httptest.NewRecorder()
	handleRequest(w, basicAuthReq(host, "bob", "wrong"))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("bad creds under default Exempt must 407 (never default-exempted), got %d", w.Code)
	}

	// Valid creds in open mode → authenticated identity (creds win), reaching
	// Stage-2 with identity (default-deny here, but as identity "alice").
	const host2 = "s3-goodcreds.example.test"
	w = httptest.NewRecorder()
	handleRequest(w, basicAuthReq(host2, "alice", "secret"))
	if e := findLogByHost(t, host2); e.Identity != "alice" {
		t.Errorf("valid creds under default Exempt must authenticate (identity=alice), got %+v", e)
	}
}

// ── No-backend behavior matches the frozen spec ──────────────────────────────

func TestS3_NoBackend_DefaultInert_ExemptScopedFires(t *testing.T) {
	// No backend + Default → inert (covered by parity test); here assert that
	// under Exempt, a scoped CR rule still fires even with NO credential backend.
	setupProxyTest(t)       // no user/provider
	withFreshPolicyStore(t) // CRITICAL: restore the store on cleanup — otherwise a
	// leftover CR rule with NO credential provider leaks an auth_cr_no_credential_provider
	// FAIL into a later diagnostics test (the QA·Determinism order-dependent flake).
	cfg.SetUnauthMode(true) // default Exempt
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	const host = "s3-nobackend-exempt-cr.example.test"
	policyStore.Add(p2s3CR("cr-nb", host))

	start := crCount()
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	if w.Code != http.StatusProxyAuthRequired || crCount() != start+1 {
		t.Fatalf("under default Exempt a scoped CR must fire even with no backend (407 + metric), got code=%d", w.Code)
	}

	// Same setup but unmatched host → default-Exempt opens to Stage-2 (default-deny).
	const host2 = "s3-nobackend-exempt-open.example.test"
	w = httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host2))
	if w.Code == http.StatusProxyAuthRequired {
		t.Fatalf("default-Exempt unmatched (no backend) must open, not 407, got %d", w.Code)
	}
}

// ── P1 (Codex): SAML-only deployment must not let Basic creds spoof identity ──

// A SAML-only deployment (no local user, no OIDC) is NOT credential-capable.
// credCapable excludes SAML, so a Basic Proxy-Authorization must NOT enter the
// credential branch (where VerifyAuth with no local user would accept any creds
// and mint the supplied username as the identity). It fails closed instead.
func TestS3_SAMLOnly_BasicCredsCannotSpoofIdentity(t *testing.T) {
	setupProxyTest(t)                                  // no local user, no legacy provider
	withSSORegistry(t, idp("corp", IdPTypeSAML, true)) // browser-only IdP
	const host = "s3-saml-spoof.example.test"

	w := httptest.NewRecorder()
	r := basicAuthReq(host, "evil", "whatever")
	handleRequest(w, r)

	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("SAML-only + Basic creds must fail closed (407), got %d", w.Code)
	}
	if got := r.Header.Get("X-User-Identity"); got != "" {
		t.Errorf("SAML-only must not mint an identity from Basic creds, got %q", got)
	}
	if e := findLogByHost(t, host); e.Identity == "evil" {
		t.Errorf("Basic creds must not spoof identity, got %q", e.Identity)
	}
}

// ── Kill switch + no credential backend: CR rules must still fire ─────────────
//
// Bug: when the kill switch is engaged AND there is no credential backend, the
// auth gate (authRequired) evaluates to false (credCapable=false, ssoCapable=false,
// effectiveDefault=Default after kill switch). The gate is never entered, so CR
// rules silently stop challenging and requests fall through to Stage-2.
//
// Fix: authRequired must use the ORIGINAL effectiveDefault (pre-kill-switch) so
// the gate is entered whenever the deployment was originally configured as Exempt.
// Inside the gate, effectiveDefault (kill-switched) governs the resolver — that is
// where scoped Exempt outcomes are suppressed. CR/SSO rules are never suppressed
// by the kill switch in either path.
func TestS3_KillSwitch_NoBackend_CRStillFires(t *testing.T) {
	setupProxyTest(t)       // no user/provider → credCapable=false, ssoCapable=false
	withFreshPolicyStore(t) // clean store; restore on cleanup (prevents rule leaks into diagnostics tests)
	cfg.SetUnauthMode(true) // default Exempt
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	setAuthExemptDisabled(true) // kill switch: forces effectiveDefault → Default
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	const host = "s3-ks-nobackend-cr.example.test"
	policyStore.Add(p2s3CR("cr-ks-nb", host))

	start := crCount()
	w := httptest.NewRecorder()
	handleRequest(w, nonBrowserReq(host))
	// The kill switch must NOT disable CR even with no credential backend.
	// The CR rule must challenge with 407 and increment the metric.
	if w.Code != http.StatusProxyAuthRequired || crCount() != start+1 {
		t.Fatalf("kill switch must NOT disable CR with no credential backend (want 407 + metric +1), got code=%d crDelta=%d",
			w.Code, crCount()-start)
	}
}

// ── Migration diagnostic fires only for the intended case ────────────────────

func TestS3_MigrationDiagnostic_Scoping(t *testing.T) {
	cr := validCRRule()
	sso := validSSORule()
	// Exempt + CR/SSO rules → WARN naming them.
	c, ok := hasCheck(authDefaultExemptMigrationDiagnostics([]PolicyRule{cr, sso}, true), "auth_default_exempt_rules_now_enforce")
	if !ok || c.Status != diagWarn {
		t.Fatal("expected WARN under default Exempt with CR/SSO rules")
	}
	// Not Exempt → no WARN.
	if got := authDefaultExemptMigrationDiagnostics([]PolicyRule{cr, sso}, false); got != nil {
		t.Errorf("no WARN when default is not Exempt, got %+v", got)
	}
	// Exempt but only an Exempt rule (no CR/SSO) → no WARN.
	if got := authDefaultExemptMigrationDiagnostics([]PolicyRule{validExemptRule()}, true); got != nil {
		t.Errorf("no WARN when there are no CR/SSO rules, got %+v", got)
	}
}
