package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func lbOIDCProvider(id, tokenURL string) *OIDCFlowProvider {
	return &OIDCFlowProvider{
		profile: &IdPProfile{ID: id, Name: id, Type: IdPTypeOIDC, Enabled: true},
		cfg:     &OIDCProfileConfig{ClientID: "culvert-client"},
		disc:    &oidcDiscoveryDoc{AuthorizationEndpoint: "https://idp.example/authorize", TokenEndpoint: tokenURL},
		client:  &http.Client{Timeout: 5 * time.Second},
		cache:   map[string]*oidcCacheEntry{},
	}
}

func lbFreshPKCE(t *testing.T) {
	t.Helper()
	orig := globalPKCEStore
	globalPKCEStore = newPKCEStore()
	t.Cleanup(func() { globalPKCEStore = orig })
}

func lbState(t *testing.T, loginURL string) string {
	t.Helper()
	u, err := url.Parse(loginURL)
	if err != nil || u.Query().Get("state") == "" {
		t.Fatalf("login URL %q carries no state", loginURL)
	}
	return u.Query().Get("state")
}

// No login state exists without a browser binding: both providers refuse to
// mint for an unbound (or nil) request.
func TestLoginBinding_UnboundMintingIsRefused(t *testing.T) {
	lbFreshPKCE(t)
	plain := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	oidc := lbOIDCProvider("corp-oidc", "https://idp.example/token")
	if got := oidc.CaptiveLoginURL("/", plain); got != "" {
		t.Fatalf("OIDC minted unbound state: %q", got)
	}
	if got := oidc.CaptiveLoginURL("/", nil); got != "" {
		t.Fatalf("OIDC minted state for a nil request: %q", got)
	}
	if globalPKCEStore.Len() != 0 {
		t.Fatal("an unbound attempt left state behind")
	}
	if got := oidc.CaptiveLoginURL("/", boundLogin(t, plain)); got == "" {
		t.Fatal("OIDC refused a bound request")
	}
	resetSAMLStateStore(t)
	saml := testSAMLRedirectProvider(t)
	if got := saml.CaptiveLoginURL("/", plain); got != "" {
		t.Fatalf("SAML minted unbound state: %q", got)
	}
	if got := saml.CaptiveLoginURL("/", nil); got != "" {
		t.Fatalf("SAML minted state for a nil request: %q", got)
	}
}

// Login CSRF on OIDC: a callback from a browser that did not start the login
// is refused BEFORE the authorization code is redeemed at the IdP.
func TestOIDCCallback_RequiresTheStartingBrowser(t *testing.T) {
	lbFreshPKCE(t)
	var tokenCalls atomic.Int64
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		tokenCalls.Add(1)
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer tokenSrv.Close()
	p := lbOIDCProvider("corp-oidc", tokenSrv.URL)
	mint := func() string {
		return lbState(t, p.CaptiveLoginURL("/", boundLogin(t, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))))
	}
	callback := func(state, cookie string) *http.Request {
		r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/oidc/callback?code=c&state="+state, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: loginBindCookieName, Value: cookie}) //nolint:gosec // request-side fixture: Secure/HttpOnly/SameSite are response attributes
		}
		return r
	}
	other := "b3RoZXItYnJvd3Nlci1iaW5kaW5nLXZhbHVlLTAxMjM"
	for name, cookie := range map[string]string{"no cookie": "", "another browser": other} {
		state := mint()
		if _, err := p.ExchangeCode(callback(state, cookie), "c", state); !errors.Is(err, errLoginNotBound) {
			t.Fatalf("%s: %v, want errLoginNotBound", name, err)
		}
	}
	if n := tokenCalls.Load(); n != 0 {
		t.Fatalf("a refused callback still redeemed the code at the IdP (%d token calls)", n)
	}
	// The starting browser gets past the binding (here to a failing token
	// endpoint — the point is that the binding did not stop it).
	state := mint()
	if _, err := p.ExchangeCode(callback(state, testLoginBindValue), "c", state); err == nil || errors.Is(err, errLoginNotBound) {
		t.Fatalf("starting browser: %v", err)
	}
	if tokenCalls.Load() != 1 {
		t.Fatalf("starting browser's code was not redeemed (%d calls)", tokenCalls.Load())
	}
}

// /auth/select sets the binding cookie (HttpOnly, Lax, Path=/, host-only),
// reuses a well-formed existing one, and records it in the state it mints.
func TestAuthSelect_BindsTheStateItMints(t *testing.T) {
	lbFreshPKCE(t)
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	p := lbOIDCProvider("corp-oidc", "https://idp.example/token")
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{p.profile},
		live:     map[string]IdentityProvider{"corp-oidc": p},
	}
	rec := httptest.NewRecorder()
	authSelectProvider(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/select?relay=/", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("single provider: %d, want 302 straight to the IdP", rec.Code)
	}
	var bind *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == loginBindCookieName {
			bind = c
		}
	}
	if bind == nil || !bind.HttpOnly || bind.SameSite != http.SameSiteLaxMode || bind.Path != "/" || bind.Domain != "" || !loginBindValueOK(bind.Value) {
		t.Fatalf("binding cookie %+v", bind)
	}
	state := lbState(t, rec.Header().Get("Location"))
	entry, ok := globalPKCEStore.Peek(state)
	if !ok || entry.bind != sha256.Sum256([]byte(bind.Value)) {
		t.Fatal("minted state is not bound to the cookie just set")
	}
	// A browser that already holds a well-formed binding keeps it.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/select?relay=/", nil)
	req.AddCookie(&http.Cookie{Name: loginBindCookieName, Value: testLoginBindValue}) //nolint:gosec // request-side fixture: Secure/HttpOnly/SameSite are response attributes
	rec = httptest.NewRecorder()
	authSelectProvider(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == loginBindCookieName && c.Value != testLoginBindValue {
			t.Fatal("an existing binding was replaced (it would break a login in another tab)")
		}
	}
}

// Without proxy.base_url there is no UI origin to send a browser to (the
// request's Host is the destination site): the redirect is withheld and the
// request gets the ordinary challenge. With it, the target is the UI host.
func TestCaptiveRedirect_TargetsTheUIHost(t *testing.T) {
	setupAuthGateTest(t)
	withFreshPolicyStore(t)
	withSSORegistry(t, idp("corp", IdPTypeOIDC, true))
	req := func() *http.Request {
		return makeRequest("http://dest.example.test/page", map[string]string{"User-Agent": "Mozilla/5.0"})
	}
	w := httptest.NewRecorder()
	handleRequest(w, req())
	if loc := w.Header().Get("Location"); w.Code != http.StatusFound || !strings.HasPrefix(loc, "https://culvert-ui.test/auth/select?") {
		t.Fatalf("with base_url: %d %q", w.Code, loc)
	}
	SetProxyBaseURL("")
	w = httptest.NewRecorder()
	handleRequest(w, req())
	if w.Code != http.StatusProxyAuthRequired || w.Header().Get("Location") != "" {
		t.Fatalf("without base_url: %d %q, want 407 and no redirect", w.Code, w.Header().Get("Location"))
	}
}
