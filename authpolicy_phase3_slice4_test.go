package main

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

// Phase 3 Slice 4 — SSORequired wired into the runtime no-credentials path.
// Browser + eligible IdP → 302; non-browser/CONNECT/no-eligible-IdP → 403
// fail-closed (no 407). classifyClient is used for SSORequired only; the Default
// path stays legacy-pinned. proxy.go touched only in the no-cred arm; socks5.go
// untouched.

func ssoCount() int64 { return atomic.LoadInt64(&statAuthSSORequired) }

// ssoTestProvider is a browser-SSO-capable IdP whose CaptiveLoginURL returns a
// same-origin path (accepted by isSafeCaptiveRedirect). Name carries the
// oidc:/saml: prefix so stripIdPPrefix yields the bare profile ID.
type ssoTestProvider struct{ name string }

// ssoCaptiveCalls counts CaptiveLoginURL invocations, so a test can assert that a
// denied (non-browser/CONNECT) SSO request never generates a provider login URL
// (which, for real OIDC/SAML, would allocate capped PKCE/SAML callback state).
var ssoCaptiveCalls atomic.Int64

func (p *ssoTestProvider) Verify(string, string) bool                       { return false }
func (p *ssoTestProvider) ResolveIdentity(string, string) (*Identity, bool) { return nil, false }
func (p *ssoTestProvider) Name() string                                     { return p.name }
func (p *ssoTestProvider) CaptiveLoginURL(relay string, _ *http.Request) string {
	ssoCaptiveCalls.Add(1)
	return "/auth/" + stripIdPPrefix(p.name) + "?relay=" + url.QueryEscape(relay)
}

// withSSORegistry installs an IdP registry from the given profiles (live
// providers compiled for enabled ones), restoring the prior global on cleanup.
func withSSORegistry(t *testing.T, profiles ...*IdPProfile) {
	t.Helper()
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	live := map[string]IdentityProvider{}
	for _, p := range profiles {
		if !p.Enabled {
			continue
		}
		prefix := "oidc:"
		if p.Type == IdPTypeSAML {
			prefix = "saml:"
		}
		live[p.ID] = &ssoTestProvider{name: prefix + p.ID}
	}
	idpRegistry = &IdPRegistry{profiles: profiles, live: live}
}

func idp(id string, typ IdPType, enabled bool) *IdPProfile {
	return &IdPProfile{ID: id, Name: id, Type: typ, Enabled: enabled}
}

// localSSO returns an SSORequired rule scoped to 127.0.0.0/8 → host with the
// given providerRefs.
func localSSO(host string, refs ...string) PolicyRule {
	r := scopeLocal(validSSORule(), "sso-rt", host)
	r.Auth.ProviderRefs = refs
	return r
}

// browserReq builds a browser-classified no-cred request (Accept: text/html).
func browserReq(host string) *http.Request {
	return makeRequest("http://"+host+"/", map[string]string{"Accept": "text/html"})
}

// ── Browser redirect ─────────────────────────────────────────────────────────

func TestP3S4_Browser_RedirectsForOIDCAndSAML(t *testing.T) {
	for _, typ := range []IdPType{IdPTypeOIDC, IdPTypeSAML} {
		setupAuthGateTest(t)
		withFreshPolicyStore(t)
		withSSORegistry(t, idp("corp", typ, true))
		const host = "p3s4-one.example.test"
		policyStore.Add(localSSO(host))

		start := ssoCount()
		w := httptest.NewRecorder()
		handleRequest(w, browserReq(host))
		if w.Code != http.StatusFound {
			t.Fatalf("%s: browser SSO must 302, got %d", typ, w.Code)
		}
		if loc := w.Header().Get("Location"); !strings.Contains(loc, "/auth/corp") {
			t.Errorf("%s: redirect to the provider login URL expected, got %q", typ, loc)
		}
		if ssoCount() != start+1 {
			t.Errorf("%s: SSO metric must increment on redirect", typ)
		}
		e := findLogByHost(t, host)
		if e.Status != "SSO_REDIRECT" || e.AuthOutcome != "SSORequired" || e.AuthPolicyRuleName != "sso-rt" {
			t.Errorf("%s: SSO redirect log fields: %+v", typ, e)
		}
		if e.Identity != "" {
			t.Errorf("%s: SSO must not create identity, got %q", typ, e.Identity)
		}
	}
}

func TestP3S4_Browser_ManyIdPs_ScopedSelect(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp-a", IdPTypeOIDC, true), idp("corp-b", IdPTypeSAML, true))
	const host = "p3s4-many.example.test"
	policyStore.Add(localSSO(host)) // empty refs → all compatible

	w := httptest.NewRecorder()
	handleRequest(w, browserReq(host))
	if w.Code != http.StatusFound {
		t.Fatalf("multi-IdP SSO must 302 to the selection page, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/auth/select") || !strings.Contains(loc, "providers=") {
		t.Errorf("multi-IdP must redirect to a scoped /auth/select, got %q", loc)
	}
	if !strings.Contains(loc, "corp-a") || !strings.Contains(loc, "corp-b") {
		t.Errorf("scoped select must carry both eligible IDs, got %q", loc)
	}
}

func TestP3S4_ProviderRefs_DirectToOne(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp-a", IdPTypeOIDC, true), idp("corp-b", IdPTypeSAML, true))
	const host = "p3s4-direct.example.test"
	policyStore.Add(localSSO(host, "corp-b")) // scoped to one → direct redirect

	w := httptest.NewRecorder()
	handleRequest(w, browserReq(host))
	if w.Code != http.StatusFound {
		t.Fatalf("single providerRef must direct-redirect (302), got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, "/auth/select") || !strings.Contains(loc, "/auth/corp-b") {
		t.Errorf("single providerRef must redirect directly to that provider, got %q", loc)
	}
}

func TestP3S4_ProviderRefs_DisabledOrMissing_FailClosed(t *testing.T) {
	setupAuthGateTest(t)
	withSSORegistry(t, idp("corp-a", IdPTypeOIDC, true), idp("old", IdPTypeOIDC, false))
	const host = "p3s4-badref.example.test"

	for name, refs := range map[string][]string{
		"disabled ref": {"old"},
		"missing ref":  {"ghost"},
	} {
		withFreshPolicyStore(t)
		policyStore.Add(localSSO(host, refs...))
		w := httptest.NewRecorder()
		handleRequest(w, browserReq(host))
		if w.Code != http.StatusForbidden {
			t.Errorf("%s: no eligible IdP must fail closed 403, got %d", name, w.Code)
		}
	}
}

// ── Fail-closed: non-browser, CONNECT, no IdP ────────────────────────────────

func TestP3S4_NonBrowser_FailsClosed(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	const host = "p3s4-nonbrowser.example.test"
	policyStore.Add(localSSO(host))

	start := ssoCount()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "curl/8.0", "Accept": "application/json"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-browser SSO must fail closed 403, got %d", w.Code)
	}
	if w.Header().Get("Proxy-Authenticate") != "" {
		t.Errorf("SSO 403 must NOT offer a Basic challenge (no 407 affordance), got %q", w.Header().Get("Proxy-Authenticate"))
	}
	if ssoCount() != start+1 {
		t.Error("SSO metric must increment on fail-closed")
	}
	if e := findLogByHost(t, host); e.Status != "SSO_DENIED" || e.AuthOutcome != "SSORequired" {
		t.Errorf("SSO denied log fields: %+v", e)
	}
}

// A denied (non-browser / CONNECT) SSO request must NOT generate a provider
// login URL — generating one allocates capped PKCE/SAML callback state, which a
// stream of denied requests could churn (Codex P2). The portal URL is resolved
// only for browser clients.
func TestP3S4_DeniedRequestAllocatesNoSSOState(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true)) // single eligible → CaptiveLoginURL path
	const host = "p3s4-nostate.example.test"
	policyStore.Add(localSSO(host))

	// Non-browser → 403, and CaptiveLoginURL must not have been called.
	ssoCaptiveCalls.Store(0)
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "curl/8.0"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-browser SSO must 403, got %d", w.Code)
	}
	if n := ssoCaptiveCalls.Load(); n != 0 {
		t.Errorf("denied non-browser request must not allocate SSO state: CaptiveLoginURL called %d times", n)
	}

	// Browser → 302, and CaptiveLoginURL is called exactly once (legitimate).
	ssoCaptiveCalls.Store(0)
	w = httptest.NewRecorder()
	handleRequest(w, browserReq(host))
	if w.Code != http.StatusFound {
		t.Fatalf("browser SSO must 302, got %d", w.Code)
	}
	if n := ssoCaptiveCalls.Load(); n != 1 {
		t.Errorf("browser redirect must generate the login URL once, got %d", n)
	}
}

func TestP3S4_Connect_FailsClosed(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	const host = "p3s4-connect.example.test"
	policyStore.Add(localSSO(host))

	w := httptest.NewRecorder()
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "http://"+host+":443", http.NoBody)
	r.Host = host + ":443"
	r.RemoteAddr = "127.0.0.1:12345"
	handleRequest(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("CONNECT SSO must fail closed 403 (cannot redirect a tunnel), got %d", w.Code)
	}
}

func TestP3S4_NoEligibleIdP_FailsClosed(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t) // empty registry
	const host = "p3s4-noidp.example.test"
	policyStore.Add(localSSO(host))

	w := httptest.NewRecorder()
	handleRequest(w, browserReq(host))
	if w.Code != http.StatusForbidden {
		t.Fatalf("no eligible IdP must fail closed 403 even for a browser, got %d", w.Code)
	}
}

// ── Credentials / session win; failed creds never reach SSO ──────────────────

func TestP3S4_SessionAndValidCredentialsWin(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	const host = "p3s4-win.example.test"
	policyStore.Add(localSSO(host))
	start := ssoCount()

	// Valid session wins → request is authenticated and proceeds past the auth
	// gate (Stage-2 default-deny may then 403; that is NOT an SSO response). The
	// proof that SSO did not fire is: no 302 redirect and the SSO metric unmoved.
	w := httptest.NewRecorder()
	rs := browserReq(host)
	rs.AddCookie(sessionCookieForIdentity(t, &Identity{Sub: "bob@example.com", Provider: "corp"}))
	handleRequest(w, rs)
	if w.Code == http.StatusFound {
		t.Fatalf("valid session must authenticate, not SSO-redirect; got 302")
	}

	// Valid Basic credentials win (setupAuthGateTest set alice/secret).
	creds := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"Proxy-Authorization": "Basic " + creds}))
	if w.Code == http.StatusFound {
		t.Fatalf("valid credentials must authenticate, not SSO-redirect; got 302")
	}
	if ssoCount() != start {
		t.Error("SSO metric must not move when a session/credentials win")
	}
}

func TestP3S4_FailedMalformedCredsNeverSSO(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	const host = "p3s4-badcreds.example.test"
	policyStore.Add(localSSO(host))

	for name, hdr := range map[string]string{
		"wrong password":     "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong")),
		"bad base64":         "Basic not-base64!!!",
		"unsupported scheme": "Bearer token",
	} {
		start := ssoCount()
		w := httptest.NewRecorder()
		handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"Proxy-Authorization": hdr, "Accept": "text/html"}))
		if w.Code != http.StatusProxyAuthRequired {
			t.Errorf("%s: presented credentials must 407 (never SSO), got %d", name, w.Code)
		}
		if ssoCount() != start {
			t.Errorf("%s: presented credentials must never become an SSO response (metric moved)", name)
		}
		if e := findLogByHost(t, host); e.Status == "SSO_REDIRECT" || e.Status == "SSO_DENIED" {
			t.Errorf("%s: presented credentials must not produce an SSO record (%s)", name, e.Status)
		}
	}
}

// ── No identity / no Stage-2 / not Allow ─────────────────────────────────────

func TestP3S4_NoIdentity_NoStage2_NotAllow(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	const host = "p3s4-notallow.example.test"
	policyStore.Add(localSSO(host))
	// A default-allow access rule that WOULD allow if Stage-2 ran.
	policyStore.Add(PolicyRule{Priority: 5, Name: "allow-all", Action: ActionAllow, DestFQDN: host})

	// Browser → 302 (not 200): SSO returns before Stage-2; no identity forwarded.
	w := httptest.NewRecorder()
	r := browserReq(host)
	handleRequest(w, r)
	if w.Code != http.StatusFound {
		t.Fatalf("SSO must challenge BEFORE Stage-2 (302), not allow; got %d", w.Code)
	}
	if r.Header.Get("X-User-Identity") != "" {
		t.Errorf("SSO must not set X-User-Identity, got %q", r.Header.Get("X-User-Identity"))
	}
	// Non-browser → 403 (not 200), also before Stage-2.
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "curl/8.0"}))
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-browser SSO must 403 before Stage-2, not allow; got %d", w.Code)
	}
}

// ── Priority activation + isolation ──────────────────────────────────────────

func TestP3S4_PriorityActivation(t *testing.T) {
	setupAuthGateTest(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	const host = "p3s4-prio.example.test"
	mk := func(base PolicyRule, name string, prio int) PolicyRule {
		r := scopeLocal(base, name, host)
		r.Priority = prio
		return r
	}

	// SSO@1 + Exempt@2 → SSO wins (302) by priority.
	withFreshPolicyStore(t)
	policyStore.Add(mk(validSSORule(), "sso-1", 1))
	policyStore.Add(mk(validExemptRule(), "ex-2", 2))
	start := ssoCount()
	w := httptest.NewRecorder()
	handleRequest(w, browserReq(host))
	if w.Code != http.StatusFound {
		t.Fatalf("SSO@1 must win over Exempt@2 (302), got %d", w.Code)
	}
	if ssoCount() != start+1 {
		t.Error("SSO@1 win must increment the SSO metric")
	}

	// Exempt@1 + SSO@2 → Exempt waives: the request proceeds (Stage-2 default-deny
	// may 403, but it is NOT an SSO response). Proof: SSO metric unmoved + the log
	// records the Exempt outcome.
	withFreshPolicyStore(t)
	policyStore.Add(mk(validExemptRule(), "ex-1", 1))
	policyStore.Add(mk(validSSORule(), "sso-2", 2))
	start = ssoCount()
	w = httptest.NewRecorder()
	handleRequest(w, browserReq(host))
	if w.Code == http.StatusFound {
		t.Fatalf("Exempt@1 must win over SSO@2 (waive, no SSO redirect), got 302")
	}
	if ssoCount() != start {
		t.Error("Exempt@1 win must NOT touch the SSO metric")
	}
	if e := findLogByHost(t, host); e.AuthOutcome != "Exempt" {
		t.Errorf("Exempt@1 must win: log outcome = %q, want Exempt", e.AuthOutcome)
	}
}

// classifyClient drives SSORequired only; the Default path stays legacy-pinned.
func TestP3S4_DefaultPathUnchanged(t *testing.T) {
	setupAuthGateTest(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))

	// No SSO rule: Default path uses browserRedirectEligibleLegacy (Mozilla).
	withFreshPolicyStore(t)
	const host = "p3s4-default.example.test"
	// Mozilla GET → legacy redirect (302).
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "Mozilla/5.0"}))
	if w.Code != http.StatusFound {
		t.Errorf("Default path: Mozilla GET must still 302 (legacy), got %d", w.Code)
	}
	// Non-Mozilla, html-Accept (classifyClient=Browser) but NO SSO rule → Default
	// path uses the legacy predicate → 407 (proving classifyClient is NOT used here).
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "curl/8.0", "Accept": "text/html"}))
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("Default path must stay legacy-pinned: non-Mozilla html GET → 407, got %d", w.Code)
	}

	// With an SSO rule, the SAME non-Mozilla html client → 302 (classifyClient=Browser).
	policyStore.Add(scopeLocal(validSSORule(), "sso-default", host))
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", map[string]string{"User-Agent": "curl/8.0", "Accept": "text/html"}))
	if w.Code != http.StatusFound {
		t.Errorf("SSO path uses classifyClient: non-Mozilla html GET → 302, got %d", w.Code)
	}
}

func TestP3S4_ExemptAndCRUnchanged(t *testing.T) {
	setupAuthGateTest(t)
	const host = "p3s4-iso.example.test"

	withFreshPolicyStore(t)
	policyStore.Add(scopeLocal(validExemptRule(), "ex", host))
	start := ssoCount()
	w := httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	// Exempt waives → Stage-2 default-deny (403) is fine; what matters is it is
	// NOT an SSO response (no redirect, SSO metric unmoved, outcome Exempt).
	if w.Code == http.StatusFound {
		t.Errorf("Exempt must waive, not SSO-redirect; got 302")
	}
	if ssoCount() != start {
		t.Errorf("Exempt must not touch the SSO metric")
	}
	if e := findLogByHost(t, host); e.AuthOutcome != "Exempt" {
		t.Errorf("Exempt outcome expected in log, got %q", e.AuthOutcome)
	}

	withFreshPolicyStore(t)
	policyStore.Add(scopeLocal(validCRRule(), "cr", host))
	w = httptest.NewRecorder()
	handleRequest(w, makeRequest("http://"+host+"/", nil))
	if w.Code != http.StatusProxyAuthRequired {
		t.Errorf("CR must still 407, got %d", w.Code)
	}
	if e := findLogByHost(t, host); e.Status != "CRED_REQUIRED" {
		t.Errorf("CR record unchanged expected, got %q", e.Status)
	}
}

// providerRefs values must never appear in the request-log record.
func TestP3S4_ProviderRefsNotLogged(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("secret-idp-id", IdPTypeOIDC, true))
	const host = "p3s4-nolog.example.test"
	policyStore.Add(localSSO(host, "secret-idp-id"))

	w := httptest.NewRecorder()
	handleRequest(w, browserReq(host))
	e := findLogByHost(t, host)
	if strings.Contains(e.AuthPolicyRuleName, "secret-idp-id") {
		t.Errorf("providerRef value leaked into the rule name field")
	}
	for _, typ := range e.AuthSubjectMatchTypes {
		if typ == "secret-idp-id" {
			t.Errorf("providerRef value leaked into subject-match types")
		}
	}
}

// ── /auth/select scoped filter (supporting change) ───────────────────────────

func TestP3S4_AuthSelect_ScopedByProviders(t *testing.T) {
	withSSORegistry(t, idp("corp-a", IdPTypeOIDC, true), idp("corp-b", IdPTypeSAML, true))

	// providers=corp-a → only corp-a's button rendered.
	w := httptest.NewRecorder()
	authSelectProvider(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/select?relay=%2F&providers=corp-a", http.NoBody))
	body := w.Body.String()
	if !strings.Contains(body, "/auth/corp-a") || strings.Contains(body, "/auth/corp-b") {
		t.Errorf("scoped /auth/select must list only corp-a, got: %s", body)
	}

	// Absent providers= → all listed (backward-compatible Default flow).
	w = httptest.NewRecorder()
	authSelectProvider(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/auth/select?relay=%2F", http.NoBody))
	body = w.Body.String()
	if !strings.Contains(body, "/auth/corp-a") || !strings.Contains(body, "/auth/corp-b") {
		t.Errorf("unscoped /auth/select must list all providers, got: %s", body)
	}
}
