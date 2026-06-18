package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Phase 2 Slice 3 — CredentialRequired wired into the runtime no-credentials
// auth path. A matched CR rule emits a deterministic 407 credential challenge,
// returns immediately (Stage-2 never runs), creates no identity, and increments
// culvert_auth_credential_required_total. Session/credentials/Exempt/malformed
// behavior is unchanged. proxy.go touched minimally; socks5.go untouched.

func crCount() int64 { return atomic.LoadInt64(&statAuthCredentialRequired) }

// p2s3CR builds a CR rule scoped to the test client (127.0.0.0/8) → host.
func p2s3CR(name, host string) PolicyRule {
	r := validCRRule()
	r.Name, r.DestFQDN = name, host
	r.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}}
	return r
}

// ── Core: CR challenge ───────────────────────────────────────────────────────

func TestP2S3_CRChallenge_NoCreds407(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p2s3-cr.example.test"
	policyStore.Add(p2s3CR("cr-vendor", host))

	startCR, startFail := crCount(), atomic.LoadInt64(&statAuthFail)
	w := httptest.NewRecorder()
	r := makeRequest("http://"+host+"/", nil) // no credentials
	handleRequest(w, r)

	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CR-matched no-creds request must 407, got %d", w.Code)
	}
	if got := w.Header().Get("Proxy-Authenticate"); got != `Basic realm="Culvert"` {
		t.Errorf("Proxy-Authenticate = %q", got)
	}
	// OIDC Link header is suppressed on CR.
	if w.Header().Get("Link") != "" {
		t.Errorf("CR 407 must omit the OIDC Link header, got %q", w.Header().Get("Link"))
	}
	// No identity is created / forwarded.
	if r.Header.Get("X-User-Identity") != "" {
		t.Errorf("CR must not set X-User-Identity, got %q", r.Header.Get("X-User-Identity"))
	}
	// Metrics: CR counter +1, statAuthFail +1.
	if crCount() != startCR+1 {
		t.Errorf("CR metric must increment on a challenge: %d → %d", startCR, crCount())
	}
	if atomic.LoadInt64(&statAuthFail) != startFail+1 {
		t.Errorf("statAuthFail must increment for 407-counter compatibility")
	}
	// Request-log record: distinct CRED_REQUIRED status, CR fields, no identity.
	e := findLogByHost(t, host)
	if e.Status != "CRED_REQUIRED" {
		t.Errorf("log status = %q, want CRED_REQUIRED", e.Status)
	}
	if e.AuthOutcome != "CredentialRequired" || e.AuthPolicyRuleName != "cr-vendor" {
		t.Errorf("CR auth log fields not attached: %+v", e)
	}
	if e.Identity != "" {
		t.Errorf("CR record must carry no identity, got %q", e.Identity)
	}
}

// CR returns immediately — Stage-2 never runs. With an access rule that would
// otherwise ALLOW the request, the response is still 407 (challenge), not 200.
func TestP2S3_CRDoesNotRunStage2(t *testing.T) {
	setupAuthGateTest(t)
	prevAction := defaultPolicyAction()
	setDefaultPolicyAction("allow") // would allow if Stage-2 ran
	t.Cleanup(func() { setDefaultPolicyAction(prevAction) })
	const host = "p2s3-stage2.example.test"
	policyStore.Add(p2s3CR("cr-1", host))
	policyStore.Add(PolicyRule{Priority: 5, Name: "allow-all", Action: ActionAllow, DestFQDN: host})

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CR must challenge BEFORE Stage-2: got %d, want 407", w.Code)
	}
	// The log record must be the CR challenge, not a policy decision.
	if e := findLogByHost(t, host); e.Status != "CRED_REQUIRED" {
		t.Errorf("Stage-2 must not run on a CR challenge, got status %q", e.Status)
	}
}

// CR browser request: SSO captive redirect is suppressed (407, not 302).
func TestP2S3_CRSuppressesBrowserRedirect(t *testing.T) {
	setupAuthGateTest(t)
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "test-idp", Name: "Test IdP", Type: IdPTypeOIDC, Enabled: true}},
		live:     map[string]IdentityProvider{"test-idp": &testProxyIdentityProvider{}},
	}
	t.Cleanup(func() { idpRegistry = origReg })
	const host = "p2s3-browser.example.test"
	policyStore.Add(p2s3CR("cr-1", host))

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "Mozilla/5.0"}))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CR must suppress the SSO redirect and 407 even for browsers, got %d", w.Code)
	}
}

// ── Credentials/session win; failed/malformed never reach CR ─────────────────

func TestP2S3_ValidSessionWinsOverCR(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p2s3-session.example.test"
	policyStore.Add(p2s3CR("cr-1", host))
	start := crCount()

	w := httptest.NewRecorder()
	r := makeRequest("http://"+host+"/", nil)
	r.AddCookie(sessionCookieForIdentity(t, &Identity{Sub: "bob@example.com", Provider: "test-idp"}))
	handleRequest(w, r)
	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("a valid session must authenticate, not hit the CR challenge")
	}
	if crCount() != start {
		t.Error("CR metric must not move when a session wins")
	}
}

func TestP2S3_ValidCredentialsWinOverCR(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p2s3-creds.example.test"
	policyStore.Add(p2s3CR("cr-1", host))
	start := crCount()

	creds := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"Proxy-Authorization": "Basic " + creds}))
	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("valid credentials must authenticate, not hit the CR challenge")
	}
	if crCount() != start {
		t.Error("CR metric must not move when valid credentials win")
	}
}

func TestP2S3_FailedAndMalformedCredsNeverCR(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p2s3-badcreds.example.test"
	policyStore.Add(p2s3CR("cr-1", host))

	for name, hdr := range map[string]string{
		"wrong password":     "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong")),
		"bad base64":         "Basic not-base64!!!",
		"unsupported scheme": "Bearer token",
	} {
		start := crCount()
		w := httptest.NewRecorder()
		handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"Proxy-Authorization": hdr}))
		if w.Code != http.StatusProxyAuthRequired {
			t.Errorf("%s: must 407 (auth fail), got %d", name, w.Code)
		}
		if crCount() != start {
			t.Errorf("%s: presented credentials must never become a CR challenge (metric moved)", name)
		}
		// And it must NOT be logged as a CR challenge.
		if e := findLogByHost(t, host); e.Status == "CRED_REQUIRED" {
			t.Errorf("%s: presented credentials must not produce a CRED_REQUIRED record", name)
		}
	}
}

// ── Empty CR ruleset is byte-identical to today's no-creds 407 ───────────────

func TestP2S3_EmptyCRRuleset_ByteIdentical(t *testing.T) {
	setupAuthGateTest(t) // no CR rules
	startCR := crCount()

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://p2s3-empty.example.test/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("no-creds 407 expected, got %d", w.Code)
	}
	if w.Header().Get("Proxy-Authenticate") != `Basic realm="Culvert"` {
		t.Error("Proxy-Authenticate header changed")
	}
	if w.Body.String() != "Proxy Authentication Required\n" {
		t.Errorf("407 body changed: %q", w.Body.String())
	}
	if crCount() != startCR {
		t.Error("CR metric must not move with no CR rules")
	}
	// The record is the generic AUTH_FAIL, not CRED_REQUIRED.
	if e := findLogByHost(t, "p2s3-empty.example.test"); e.Status != "AUTH_FAIL" {
		t.Errorf("empty-ruleset record = %q, want AUTH_FAIL", e.Status)
	}
}

// ── Kill switch does not disable CR; UnauthMode skips the gate ───────────────

func TestP2S3_KillSwitchDoesNotDisableCR(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p2s3-kill.example.test"
	policyStore.Add(p2s3CR("cr-1", host))
	setAuthExemptDisabled(true)
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	start := crCount()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("kill switch must NOT disable CR — request must still 407, got %d", w.Code)
	}
	if crCount() != start+1 {
		t.Error("CR challenge must still fire (and count) under the kill switch")
	}
}

func TestP2S3_UnauthModeSkipsCR(t *testing.T) {
	setupAuthGateTest(t)
	cfg.SetUnauthMode(true)
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	const host = "p2s3-unauth.example.test"
	policyStore.Add(p2s3CR("cr-1", host))

	start := crCount()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("UnauthMode skips the auth gate — CR must not fire")
	}
	if crCount() != start {
		t.Error("CR metric must not move under UnauthMode")
	}
}

// ── Exempt behavior unchanged (CR branch must not break it) ──────────────────

func TestP2S3_ExemptStillWaives(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p2s3-exempt.example.test"
	ex := validExemptRule()
	ex.Name, ex.DestFQDN = "ex-1", host
	ex.SubjectMatch = &SubjectMatch{SchemaVersion: 1, All: []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}}}
	policyStore.Add(ex)
	startCR := crCount()

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("Exempt must still waive the challenge (no 407)")
	}
	if crCount() != startCR {
		t.Error("an Exempt decision must not touch the CR metric")
	}
	if e := findLogByHost(t, host); e.AuthOutcome != "Exempt" {
		t.Errorf("Exempt record outcome = %q, want Exempt", e.AuthOutcome)
	}
}

// ── CONNECT + CR ─────────────────────────────────────────────────────────────

func TestP2S3_ConnectCRChallenge(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p2s3-connect.example.test"
	cr := p2s3CR("cr-connect", host)
	cr.Auth.Protocol = "connect"
	policyStore.Add(cr)

	start := crCount()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://"+host+":443", http.NoBody)
	r.Host = host + ":443"
	r.RemoteAddr = "127.0.0.1:12345"
	handleRequest(w, r)
	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT + CR must 407, got %d", w.Code)
	}
	if crCount() != start+1 {
		t.Error("CONNECT CR challenge must increment the CR metric")
	}
}
