package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Phase 1 Slice 7 — runtime wiring of AuthOutcome Exempt into the proxy's
// no-credentials auth path. Covers the required behavior matrix: session wins,
// credentials win, failed credentials always 407, exempt only when credentials
// are absent, no identity creation, authSource="exempt" visible to Stage-2,
// default-deny still applies, kill switch, UnauthMode untouched, and the
// byte-identical empty-ruleset contract.

// slice7ExemptRule returns an enabled exempt rule scoped to the test client
// (127.0.0.0/8, the RemoteAddr makeRequest sets) and the given destination.
func slice7ExemptRule(destFQDN string) PolicyRule {
	enabled := true
	return PolicyRule{
		Priority: 1,
		Name:     "slice7-exempt",
		RuleType: ruleTypeAuth,
		Enabled:  &enabled,
		SubjectMatch: &SubjectMatch{
			SchemaVersion: 1,
			All:           []SubjectPredicate{{Type: subjectPredicateCIDR, Values: []string{"127.0.0.0/8"}}},
		},
		DestFQDN: destFQDN,
		Auth:     &AuthRuleSpec{Outcome: OutcomeExempt, Owner: "ops", Reason: "slice7 test"},
	}
}

// setupAuthGateTest configures an auth-required proxy (local bcrypt user) with
// a clean policy store and a released kill switch.
func setupAuthGateTest(t *testing.T) {
	t.Helper()
	setupProxyTest(t)
	if err := cfg.SetAuth("alice", "secret"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	setAuthExemptDisabled(false)
	t.Cleanup(func() { setAuthExemptDisabled(false) })
}

func exemptCount() int64 { return atomic.LoadInt64(&statAuthExempt) }

// ── Exempt skips the challenge; Stage-2 default-deny still applies ───────────

func TestSlice7_Exempt_SkipsChallenge_DefaultDenyApplies(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-dd.example.test"
	policyStore.Add(slice7ExemptRule(host))

	before := exemptCount()
	w := httptest.NewRecorder()
	r := makeRequest("http://"+host+"/", nil) // no credentials, non-browser
	handleRequest(w, r)

	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("exempt request must not receive a 407 challenge")
	}
	if got := w.Header().Get("Proxy-Authenticate"); got != "" {
		t.Errorf("exempt response must not carry Proxy-Authenticate, got %q", got)
	}
	// Default-deny still applies: the request proceeds to Stage-2 and is blocked.
	if w.Code != http.StatusForbidden {
		t.Errorf("default-deny must still apply to exempt traffic: got %d, want 403", w.Code)
	}
	if got := r.Header.Get("X-User-Identity"); got != "" {
		t.Errorf("X-User-Identity must not be set for exempt requests, got %q", got)
	}
	if got := exemptCount(); got != before+1 {
		t.Errorf("exempt metric: %d → %d, want +1", before, got)
	}
	// Log entry carries the auth observability block and no identity.
	e := findLogByHost(t, host)
	if e.AuthOutcome != "Exempt" || e.AuthPolicyRuleName != "slice7-exempt" {
		t.Errorf("log entry missing exempt fields: %+v", e)
	}
	if e.Identity != "" {
		t.Errorf("exempt log entry must carry no identity, got %q", e.Identity)
	}
	if e.Status != "POLICY_DEFAULT_DENY" {
		t.Errorf("expected POLICY_DEFAULT_DENY status, got %q", e.Status)
	}
}

// ── Stage-2 sees authSource="exempt"; exempt-targeted rules can match ────────

func TestSlice7_Exempt_Stage2SeesAuthSourceExempt(t *testing.T) {
	setupAuthGateTest(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("X-User-Identity"); got != "" {
			t.Errorf("backend received X-User-Identity = %q, want absent", got)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(backend.Close)
	host := strings.TrimPrefix(backend.URL, "http://")
	hostOnly := host[:strings.LastIndex(host, ":")]

	policyStore.Add(slice7ExemptRule(hostOnly))
	policyStore.Add(PolicyRule{
		Priority: 2, Name: "allow-exempt-traffic", Action: ActionAllow,
		AuthSource: "exempt", DestFQDN: hostOnly,
	})

	w := httptest.NewRecorder()
	r := makeRequest(backend.URL+"/", nil)
	handleRequest(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("an AuthSource=exempt allow rule must match exempt traffic: got %d, want 200", w.Code)
	}
	if body := w.Body.String(); body != "ok" {
		t.Errorf("expected backend body, got %q", body)
	}
	e := findLogByHost(t, host)
	if e.RuleMatched != "allow-exempt-traffic" {
		t.Errorf("Stage-2 matched %q, want allow-exempt-traffic", e.RuleMatched)
	}
	if e.AuthOutcome != "Exempt" || e.Identity != "" {
		t.Errorf("exempt log fields wrong: %+v", e)
	}
}

func TestSlice7_UnauthRuleDoesNotMatchExemptTraffic(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-unauth.example.test"
	policyStore.Add(slice7ExemptRule(host))
	// This rule matches plain unauthenticated traffic only — NOT exempt traffic.
	policyStore.Add(PolicyRule{
		Priority: 2, Name: "allow-unauth-only", Action: ActionAllow,
		AuthSource: "unauth", DestFQDN: host,
	})

	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	// authSource is "exempt", so the unauth-scoped rule must not match and
	// default-deny applies.
	if w.Code != http.StatusForbidden {
		t.Fatalf("AuthSource=unauth rule must not match exempt traffic: got %d, want 403", w.Code)
	}
	if e := findLogByHost(t, host); e.RuleMatched != "" || e.Status != "POLICY_DEFAULT_DENY" {
		t.Errorf("expected default deny with no rule, got %+v", e)
	}
}

// Control for the test above: in UnauthMode the same rule DOES match, because
// authSource stays "unauth" (the auth gate — and exempt evaluation — is skipped).
func TestSlice7_UnauthMode_GateAndExemptSkipped(t *testing.T) {
	setupAuthGateTest(t)
	cfg.SetUnauthMode(true)
	t.Cleanup(func() { cfg.SetUnauthMode(false) })
	const host = "slice7-unauthmode.example.test"
	policyStore.Add(slice7ExemptRule(host)) // present but must never be evaluated
	policyStore.Add(PolicyRule{
		Priority: 2, Name: "allow-unauth-only", Action: ActionAllow,
		AuthSource: "unauth", DestFQDN: host,
	})

	before := exemptCount()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	if got := exemptCount(); got != before {
		t.Errorf("UnauthMode must skip exempt evaluation entirely: metric %d → %d", before, got)
	}
	e := findLogByHost(t, host)
	if e.RuleMatched != "allow-unauth-only" {
		t.Errorf("UnauthMode traffic must still match AuthSource=unauth rules, got %+v", e)
	}
	if e.AuthOutcome != "" {
		t.Errorf("UnauthMode entries must carry no auth outcome, got %q", e.AuthOutcome)
	}
}

// ── Credentials always win; failures are never exempted ─────────────────────

func TestSlice7_FailedCredentials_Still407_NeverExempt(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-badcreds.example.test"
	policyStore.Add(slice7ExemptRule(host))

	before := exemptCount()
	creds := base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{
		"Proxy-Authorization": "Basic " + creds,
	}))

	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("failed credentials must 407 even with a matching exempt rule: got %d", w.Code)
	}
	if got := exemptCount(); got != before {
		t.Errorf("failed credentials must never increment the exempt metric: %d → %d", before, got)
	}
}

// A PRESENT but malformed Proxy-Authorization header (bad base64, unsupported
// scheme, missing colon) makes parseProxyAuth return ok=false — but it is still
// presented credentials and must take the 407 path, never an exemption. This is
// the regression test for the resolveNoCredAuthOutcome header-presence guard.
func TestSlice7_MalformedCredentials_Still407_NeverExempt(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-malformed.example.test"
	policyStore.Add(slice7ExemptRule(host))

	for name, header := range map[string]string{
		"bad base64":         "Basic not-base64!!!",
		"unsupported scheme": "Bearer some-opaque-token",
		"missing colon":      "Basic " + base64.StdEncoding.EncodeToString([]byte("no-colon-here")),
	} {
		before := exemptCount()
		w := httptest.NewRecorder()
		handleRequest(w, makeRequest("http://"+host+"/", map[string]string{
			"Proxy-Authorization": header,
		}))
		if w.Code != http.StatusProxyAuthRequired {
			t.Errorf("%s: malformed Proxy-Authorization must 407 even with a matching exempt rule, got %d", name, w.Code)
		}
		if got := exemptCount(); got != before {
			t.Errorf("%s: malformed credentials must never increment the exempt metric: %d → %d", name, before, got)
		}
	}
}

func TestSlice7_ValidCredentialsWin(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-goodcreds.example.test"
	policyStore.Add(slice7ExemptRule(host))

	before := exemptCount()
	creds := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	w := httptest.NewRecorder()
	r := makeRequest("http://"+host+"/", map[string]string{
		"Proxy-Authorization": "Basic " + creds,
	})
	handleRequest(w, r)

	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("valid credentials must authenticate")
	}
	if got := exemptCount(); got != before {
		t.Errorf("authenticated requests must not evaluate exempt: metric %d → %d", before, got)
	}
	e := findLogByHost(t, host)
	if e.Identity != "alice" {
		t.Errorf("authenticated identity must be recorded, got %q", e.Identity)
	}
	if e.AuthOutcome != "" {
		t.Errorf("authenticated entries must carry no auth outcome, got %q", e.AuthOutcome)
	}
}

func TestSlice7_ValidSessionWins(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-session.example.test"
	policyStore.Add(slice7ExemptRule(host))

	before := exemptCount()
	w := httptest.NewRecorder()
	r := makeRequest("http://"+host+"/", nil)
	r.AddCookie(sessionCookieForIdentity(t, &Identity{Sub: "bob@example.com", Provider: "test-idp"}))
	handleRequest(w, r)

	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("a valid session must authenticate without a challenge")
	}
	if got := exemptCount(); got != before {
		t.Errorf("session-authenticated requests must not evaluate exempt: metric %d → %d", before, got)
	}
	if e := findLogByHost(t, host); e.Identity != "bob@example.com" || e.AuthOutcome != "" {
		t.Errorf("session identity must win (no exempt fields), got %+v", e)
	}
}

// Documented Slice 7 decision: a stale/expired session cookie with no
// Proxy-Authorization is treated as "no credentials" and is exempt-eligible.
func TestSlice7_StaleSessionCookie_ExemptEligible(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-stale.example.test"
	policyStore.Add(slice7ExemptRule(host))

	if len(sessionSecret) == 0 {
		initSessionSecret()
	}
	value, err := encodeSession(&Session{
		Sub: "bob@example.com", Provider: "test-idp",
		Exp: time.Now().Add(-time.Hour).Unix(), // expired
		Jti: newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encode session: %v", err)
	}

	before := exemptCount()
	w := httptest.NewRecorder()
	r := makeRequest("http://"+host+"/", nil)
	r.AddCookie(&http.Cookie{
		Name: sessionCookieName, Value: value, Path: "/",
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	handleRequest(w, r)

	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("expired session + matching exempt rule must be exempt-eligible (treated as no credentials)")
	}
	if got := exemptCount(); got != before+1 {
		t.Errorf("expected exempt metric +1 for stale-session request: %d → %d", before, got)
	}
	if e := findLogByHost(t, host); e.Identity != "" {
		t.Errorf("stale session must not produce an identity, got %q", e.Identity)
	}
}

// ── No-match behavior is byte-identical to today ─────────────────────────────

func TestSlice7_EmptyAuthRuleset_407ByteIdentical(t *testing.T) {
	setupAuthGateTest(t) // zero policy rules of any kind

	failBefore := atomic.LoadInt64(&statAuthFail)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://slice7-noauthrules.example.test/", nil))

	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("got %d, want 407", w.Code)
	}
	if got := w.Header().Get("Proxy-Authenticate"); got != `Basic realm="Culvert"` {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, `Basic realm="Culvert"`)
	}
	if body := w.Body.String(); body != "Proxy Authentication Required\n" {
		t.Errorf("407 body changed: %q", body)
	}
	if got := atomic.LoadInt64(&statAuthFail); got != failBefore+1 {
		t.Errorf("statAuthFail must still increment on the no-credentials 407: %d → %d", failBefore, got)
	}
}

func TestSlice7_NoMatchingExemptRule_407(t *testing.T) {
	setupAuthGateTest(t)
	// Exempt rule exists but for a DIFFERENT destination — must not fire.
	policyStore.Add(slice7ExemptRule("other.example.test"))

	before := exemptCount()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://slice7-nomatch.example.test/", nil))

	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("non-matching exempt rule must leave the 407 path unchanged: got %d", w.Code)
	}
	if got := exemptCount(); got != before {
		t.Errorf("metric must not move on a non-match: %d → %d", before, got)
	}
}

// ── Browser SSO redirect: preserved on no-match, bypassed on explicit match ──

func TestSlice7_BrowserRedirect_PreservedAndBypassed(t *testing.T) {
	setupAuthGateTest(t)
	origRegistry := idpRegistry
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "test-idp", Name: "Test IdP", Type: IdPTypeOIDC, Enabled: true}},
		live:     map[string]IdentityProvider{"test-idp": &testProxyIdentityProvider{}},
	}
	t.Cleanup(func() { idpRegistry = origRegistry })

	browserHeaders := map[string]string{"User-Agent": "Mozilla/5.0"}

	// (a) No exempt rule → captive redirect unchanged.
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://slice7-redirect.example.test/", browserHeaders))
	if w.Code != http.StatusFound {
		t.Fatalf("browser with no exempt match must still get the SSO redirect: got %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, "/auth/test-idp") {
		t.Errorf("unexpected redirect target %q", loc)
	}

	// (b) Matching exempt rule → redirect bypassed, Stage-2 default-deny applies.
	const host = "slice7-bypass.example.test"
	policyStore.Add(slice7ExemptRule(host))
	before := exemptCount()
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", browserHeaders))
	if w.Code == http.StatusFound || w.Code == http.StatusProxyAuthRequired {
		t.Fatalf("matched exempt rule must bypass the SSO redirect: got %d", w.Code)
	}
	if w.Code != http.StatusForbidden {
		t.Errorf("exempt browser traffic still hits default-deny: got %d, want 403", w.Code)
	}
	if got := exemptCount(); got != before+1 {
		t.Errorf("expected exempt metric +1: %d → %d", before, got)
	}
}

// ── Kill switch ──────────────────────────────────────────────────────────────

func TestSlice7_KillSwitch_Forces407(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-kill.example.test"
	policyStore.Add(slice7ExemptRule(host))
	setAuthExemptDisabled(true)
	t.Cleanup(func() { setAuthExemptDisabled(false) })

	before := exemptCount()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))

	if w.Code != http.StatusProxyAuthRequired {
		t.Fatalf("kill switch must force the 407 path: got %d", w.Code)
	}
	if got := exemptCount(); got != before {
		t.Errorf("kill switch engaged: metric must not move: %d → %d", before, got)
	}
}

// ── CONNECT ──────────────────────────────────────────────────────────────────

func TestSlice7_Connect_ExemptProceedsToPolicy(t *testing.T) {
	setupAuthGateTest(t)
	const host = "slice7-connect.example.test"
	rule := slice7ExemptRule(host)
	rule.Auth.Protocol = "connect"
	policyStore.Add(rule)

	before := exemptCount()
	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://"+host+":443", http.NoBody)
	r.Host = host + ":443"
	r.RemoteAddr = "127.0.0.1:12345"
	handleRequest(w, r)

	if w.Code == http.StatusProxyAuthRequired {
		t.Fatal("CONNECT with a matching connect-protocol exempt rule must not 407")
	}
	// Default-deny applies to the tunnel before any dial happens.
	if w.Code != http.StatusForbidden {
		t.Errorf("CONNECT exempt traffic still hits default-deny: got %d, want 403", w.Code)
	}
	if got := exemptCount(); got != before+1 {
		t.Errorf("expected exempt metric +1 for CONNECT: %d → %d", before, got)
	}
}
