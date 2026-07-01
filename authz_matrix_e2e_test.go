package main

// Authentication × Authorization matrix, end-to-end through the REAL proxy
// socket. The product invariant under test: AUTHENTICATION NEVER IMPLIES
// AUTHORIZATION. A perfectly authenticated user in the wrong group must be
// denied; identity only enables policy evaluation, it never grants access.
//
// Traffic is driven through a real proxy listener (not handleRequest directly):
// Basic credentials via the proxy URL userinfo (Go sends Proxy-Authorization),
// and browser-style auth via a signed session cookie on the forwarded request.
// Each case asserts BOTH the proxy response AND whether the upstream was
// actually reached.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// startAuthProxy boots a real proxy listener with: default-DENY policy, a test
// IdP provider (token→identity+groups), a local bcrypt backstop user (so invalid
// credentials get a 407 rather than the no-local-user "auth disabled" pass), and
// the supplied access rules.
func startAuthProxy(t *testing.T, provider IdentityProvider, rules []PolicyRule) *url.URL {
	t.Helper()
	setupProxyTest(t) // resets globals; defaultPolicyAction = deny

	origReg := idpRegistry
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "test-idp", Name: "Test IdP", Type: IdPTypeOIDC, Enabled: true, EmailDomains: []string{"example.com"}}},
		live:     map[string]IdentityProvider{"test-idp": provider},
	}
	t.Cleanup(func() { idpRegistry = origReg })

	if err := cfg.SetAuth("admin", "admin-pass"); err != nil {
		t.Fatalf("SetAuth: %v", err)
	}
	t.Cleanup(func() { cfg.SetAuth("", "") }) //nolint:errcheck

	policyStore.rules = nil
	for i := range rules {
		policyStore.Add(rules[i])
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			handleHealth(w, r)
			return
		}
		handleRequest(w, r)
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	return u
}

// engRule allows the "engineering" group on any destination.
func engRule() []PolicyRule {
	return []PolicyRule{{Priority: 10, Name: "engineering-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow}}
}

func testProvider() *testProxyIdentityProvider {
	return &testProxyIdentityProvider{idByToken: map[string]*Identity{
		"eng-token": {Sub: "alice", Email: "alice@example.com", Groups: []string{"engineering"}, Provider: "test-idp"},
		"fin-token": {Sub: "bob", Email: "bob@example.com", Groups: []string{"finance"}, Provider: "test-idp"},
	}}
}

// proxiedGet sends a GET to targetURL through the proxy. If user!="" it sets
// Basic creds via the proxy userinfo; cookie (if non-nil) is attached to the
// forwarded request. Returns the status code.
func proxiedGet(t *testing.T, proxyURL *url.URL, targetURL, user, pass string, cookie *http.Cookie) int {
	t.Helper()
	p := *proxyURL
	if user != "" {
		p.User = url.UserPassword(user, pass)
	}
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(&p)},
		Timeout:   5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, targetURL, http.NoBody)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// TestAuthzMatrix_BasicCredentials walks the Basic-auth rows of the matrix and
// asserts the auth≠authz invariant: valid creds in the WRONG group are denied.
func TestAuthzMatrix_BasicCredentials(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), engRule())

	cases := []struct {
		name        string
		user, pass  string
		wantStatus  int
		wantReached bool
	}{
		// 407 = NOT AUTHENTICATED (no creds → challenge). Contrast the wrong-group
		// row below, which is 403 = AUTHENTICATED BUT NOT AUTHORIZED. That 407↔403
		// split IS the auth≠authz boundary.
		{"unauthenticated_challenged_407", "", "", http.StatusProxyAuthRequired, false},
		{"valid_creds_right_group_allow", "alice", "eng-token", http.StatusOK, true},
		{"valid_creds_wrong_group_denied", "bob", "fin-token", http.StatusForbidden, false}, // AUTH ✓ AUTHZ ✗
		{"invalid_credentials_407", "nobody", "bad-token", http.StatusProxyAuthRequired, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := cb.hitCount()
			got := proxiedGet(t, proxyURL, backend.URL+"/", tc.user, tc.pass, nil)
			if got != tc.wantStatus {
				t.Errorf("status = %d, want %d", got, tc.wantStatus)
			}
			reached := cb.hitCount() > before
			if reached != tc.wantReached {
				t.Errorf("upstream reached = %v, want %v", reached, tc.wantReached)
			}
		})
	}
}

// TestAuthzMatrix_BlockBeatsGroupAllow proves an explicit block rule overrides an
// otherwise-authorizing group-allow: a correctly authenticated, correctly
// grouped user is still blocked. (Authorization is policy, not identity.)
func TestAuthzMatrix_BlockBeatsGroupAllow(t *testing.T) {
	backend, cb := startCountingBackend(t)
	rules := []PolicyRule{
		{Priority: 1, Name: "block-all", DestFQDN: "*", Action: ActionBlockPage}, // higher priority (lower number)
		{Priority: 10, Name: "engineering-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow},
	}
	proxyURL := startAuthProxy(t, testProvider(), rules)

	got := proxiedGet(t, proxyURL, backend.URL+"/", "alice", "eng-token", nil)
	if got != http.StatusForbidden {
		t.Errorf("authenticated eng user against a block rule: status %d, want 403", got)
	}
	if cb.hitCount() != 0 {
		t.Errorf("block rule: upstream reached %d times, want 0", cb.hitCount())
	}
}

// TestAuthzMatrix_SessionCookie covers the browser-SSO rows: a valid session in
// the right group is allowed; an EXPIRED session is treated as unauthenticated
// and denied (auth state must not survive expiry).
func TestAuthzMatrix_SessionCookie(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), engRule())
	if len(sessionSecret) == 0 {
		initSessionSecret()
	}

	mkCookie := func(groups []string, exp time.Time) *http.Cookie {
		val, err := encodeSession(&Session{Sub: "alice", Email: "alice@example.com", Groups: groups, Provider: "test-idp", Exp: exp.Unix(), Jti: newSessionJti()})
		if err != nil {
			t.Fatalf("encode session: %v", err)
		}
		return &http.Cookie{Name: sessionCookieName, Value: val, Path: "/"}
	}

	t.Run("valid_session_right_group_allow", func(t *testing.T) {
		before := cb.hitCount()
		got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", mkCookie([]string{"engineering"}, time.Now().Add(time.Hour)))
		if got != http.StatusOK {
			t.Errorf("valid eng session: status %d, want 200", got)
		}
		if cb.hitCount() <= before {
			t.Errorf("valid session should reach upstream")
		}
	})

	t.Run("expired_session_denied", func(t *testing.T) {
		before := cb.hitCount()
		got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", mkCookie([]string{"engineering"}, time.Now().Add(-time.Hour)))
		if got != http.StatusProxyAuthRequired {
			t.Errorf("expired session: status %d, want 407 (treated as unauthenticated → challenge)", got)
		}
		if cb.hitCount() > before {
			t.Errorf("expired session must NOT reach upstream")
		}
	})

	t.Run("valid_session_wrong_group_denied", func(t *testing.T) {
		before := cb.hitCount()
		got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", mkCookie([]string{"finance"}, time.Now().Add(time.Hour)))
		if got != http.StatusForbidden {
			t.Errorf("wrong-group session: status %d, want 403 (auth ✓ authz ✗)", got)
		}
		if cb.hitCount() > before {
			t.Errorf("wrong-group session must NOT reach upstream")
		}
	})
}

// TestAuthzMatrix_ExemptOpensUnmatchedTraffic proves the Stage-1 Exempt default
// (open mode) lets UNAUTHENTICATED traffic through when an allow rule matches —
// confirming the default-auth-outcome seam is the source of truth.
func TestAuthzMatrix_ExemptOpensUnmatchedTraffic(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(),
		[]PolicyRule{{Priority: 1, Name: "allow-all", DestFQDN: "*", Action: ActionAllow}})

	// Default (require auth): unauth + allow-all rule. Stage-2 allows, but the
	// allow rule has no source constraint, so unauth is allowed here already —
	// switch the rule to be group-scoped to make auth matter, then flip Exempt.
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow})

	// Default outcome: unauth has no group → denied.
	if got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", nil); got != http.StatusProxyAuthRequired {
		t.Errorf("default(require-auth) unauth: status %d, want 407 (challenge)", got)
	}

	// Flip to Exempt + an open allow-all rule: unauth now flows.
	cfg.SetDefaultAuthOutcome(OutcomeExempt)
	t.Cleanup(func() { cfg.SetDefaultAuthOutcome(OutcomeDefault) })
	policyStore.rules = nil
	policyStore.Add(PolicyRule{Priority: 1, Name: "allow-all", DestFQDN: "*", Action: ActionAllow})

	before := cb.hitCount()
	if got := proxiedGet(t, proxyURL, backend.URL+"/", "", "", nil); got != http.StatusOK {
		t.Errorf("exempt + allow-all unauth: status %d, want 200", got)
	}
	if cb.hitCount() <= before {
		t.Errorf("exempt open mode should reach upstream for unauth traffic")
	}
}

// TestAuthzMatrix_IdentityHeaderSpoofIgnored proves a client cannot grant itself
// authorization by injecting the internal X-User-Identity header: the spoofed
// identity is stripped and the request is evaluated as its real (unauthorized)
// self.
func TestAuthzMatrix_IdentityHeaderSpoofIgnored(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(),
		[]PolicyRule{{Priority: 1, Name: "eng-allow", DestFQDN: "*", SourceIdentity: "alice", Action: ActionAllow}})

	// Unauthenticated, but spoofing X-User-Identity: alice (who WOULD be allowed).
	p := *proxyURL
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(&p)}, Timeout: 5 * time.Second}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, backend.URL+"/", http.NoBody)
	req.Header.Set("X-User-Identity", "alice")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("spoofed X-User-Identity: status %d, want 407 — the spoofed header must not authenticate the client", resp.StatusCode)
	}
	if cb.hitCount() != 0 {
		t.Errorf("spoofed-identity request reached upstream %d times, want 0", cb.hitCount())
	}
}
