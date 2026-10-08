package main

// Gates for the login-binding review round (#1528): cookie injection on
// HTTPS, a junk copy blocking a login, the signed sign-in relay (zero-click
// open redirect), a proxy.base_url path prefix, and the warning gate under a
// clock rollback.

import (
	"context"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func lbHTTPS(r *http.Request) *http.Request { r.Header.Set("X-Forwarded-Proto", "https"); return r }

func lbReq(target string) *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
}

// On HTTPS the binding is a __Host- cookie (Secure, Path=/, no Domain) and
// ONLY that name counts: a plain-named cookie — the only kind a sibling
// subdomain or an HTTP origin can plant — never matches, even when it carries
// a value Culvert legitimately issued (the attacker's own).
func TestLoginBinding_HTTPSUsesHostPrefixAndIgnoresPlantedCookies(t *testing.T) {
	rec := httptest.NewRecorder()
	if _, err := ensureLoginBinding(rec, lbHTTPS(lbReq("/auth/select"))); err != nil {
		t.Fatal(err)
	}
	var set *http.Cookie
	for _, c := range rec.Result().Cookies() {
		set = c
	}
	if set == nil || set.Name != "__Host-ps_login_bind" || !set.Secure || set.Path != "/" || set.Domain != "" {
		t.Fatalf("HTTPS binding cookie %+v, want __Host-ps_login_bind, Secure, Path=/, no Domain", set)
	}
	want := sha256.Sum256([]byte(testLoginBindValue))
	planted := lbHTTPS(lbReq("/auth/oidc/callback"))
	planted.AddCookie(&http.Cookie{Name: loginBindCookieName, Value: testLoginBindValue})
	if loginBindingMatches(want, planted) {
		t.Fatal("HTTPS accepted a plain-named (plantable) binding cookie")
	}
	genuine := lbHTTPS(lbReq("/auth/oidc/callback"))
	genuine.AddCookie(&http.Cookie{Name: loginBindSecureCookieName, Value: testLoginBindValue})
	if !loginBindingMatches(want, genuine) {
		t.Fatal("HTTPS refused the genuine __Host- binding cookie")
	}
	// Plain HTTP keeps the plain name (a __Host- cookie needs Secure).
	rec = httptest.NewRecorder()
	if _, err := ensureLoginBinding(rec, lbReq("/auth/select")); err != nil {
		t.Fatal(err)
	}
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Name != loginBindCookieName || c[0].Path != "/" {
		t.Fatalf("HTTP binding cookie %+v", c)
	}
}

// A junk copy of the cookie sent first (planted at a longer path) must not
// block the browser's genuine binding.
func TestLoginBinding_JunkCopyDoesNotBlockTheGenuineOne(t *testing.T) {
	want := sha256.Sum256([]byte(testLoginBindValue))
	r := lbReq("/auth/saml/complete")
	r.AddCookie(&http.Cookie{Name: loginBindCookieName, Value: "junk"})
	r.AddCookie(&http.Cookie{Name: loginBindCookieName, Value: "b3RoZXItYnJvd3Nlci1iaW5kaW5nLXZhbHVlLTAxMjM"})
	r.AddCookie(&http.Cookie{Name: loginBindCookieName, Value: testLoginBindValue})
	if !loginBindingMatches(want, r) {
		t.Fatal("a junk or foreign copy ahead of the genuine binding blocked the login")
	}
	r = lbReq("/auth/saml/complete")
	r.AddCookie(&http.Cookie{Name: loginBindCookieName, Value: "junk"})
	if loginBindingMatches(want, r) {
		t.Fatal("junk alone matched")
	}
}

// The sign-in page honours only a relay the captive redirect signed.
func TestSelectRelay_OnlyASignedRelayIsHonoured(t *testing.T) {
	if !sessionSecretSet() {
		initSessionSecret()
	}
	now := time.Now()
	const evil = "https://evil.example/"
	q := url.Values{"relay": {evil}, "providers": {"corp"}}
	signSelectQuery(q, now)
	if got := selectRelayFromQuery(q, now); got != evil {
		t.Fatalf("signed relay: %q", got)
	}
	cases := map[string]url.Values{
		"unsigned (hand-made link)": {"relay": {evil}},
		"relay tampered":            {"relay": {"https://other.example/"}, "providers": {"corp"}, "exp": q["exp"], "sig": q["sig"]},
		"providers tampered":        {"relay": {evil}, "providers": {"corp,other"}, "exp": q["exp"], "sig": q["sig"]},
		"expiry tampered":           {"relay": {evil}, "providers": {"corp"}, "exp": {strconv.FormatInt(now.Add(time.Hour*24).Unix(), 10)}, "sig": q["sig"]},
		"garbage signature":         {"relay": {evil}, "providers": {"corp"}, "exp": q["exp"], "sig": {"!!"}},
	}
	for name, v := range cases {
		if got := selectRelayFromQuery(v, now); got != "/" {
			t.Errorf("%s: relay %q honoured, want /", name, got)
		}
	}
	if got := selectRelayFromQuery(q, now.Add(selectRelayTTL+time.Second)); got != "/" {
		t.Fatalf("expired signed relay honoured: %q", got)
	}
}

// End to end: a hand-made /auth/select link mints login state whose relay is
// "/", while the proxy's own captive redirect keeps the destination.
func TestAuthSelect_UnsignedRelayIsNotAnOpenRedirect(t *testing.T) {
	if !sessionSecretSet() {
		initSessionSecret()
	}
	lbFreshPKCE(t)
	orig := idpRegistry
	t.Cleanup(func() { idpRegistry = orig })
	p := lbOIDCProvider("corp-oidc", "https://idp.example/token")
	idpRegistry = &IdPRegistry{profiles: []*IdPProfile{p.profile}, live: map[string]IdentityProvider{"corp-oidc": p}}
	prevBase := cfg.ProxyBaseURL()
	t.Cleanup(func() { SetProxyBaseURL(prevBase) })
	SetProxyBaseURL("https://culvert-ui.test")
	relayOf := func(target string) string {
		rec := httptest.NewRecorder()
		authSelectProvider(rec, lbReq(target))
		entry, ok := globalPKCEStore.Peek(lbState(t, rec.Header().Get("Location")))
		if !ok {
			t.Fatalf("%s: no state minted", target)
		}
		return entry.relayURL
	}
	if got := relayOf("/auth/select?relay=" + url.QueryEscape("https://evil.example/")); got != "/" {
		t.Fatalf("hand-made link kept relay %q", got)
	}
	sel := uiSelectURL("http://app.example/page", nil)
	u, err := url.Parse(sel)
	if err != nil || u.Host != "culvert-ui.test" {
		t.Fatalf("captive select URL %q", sel)
	}
	if got := relayOf(u.RequestURI()); got != "http://app.example/page" {
		t.Fatalf("captive redirect lost its own relay: %q", got)
	}
}

// A proxy.base_url path prefix keeps the SAML ACS → complete hop under the
// prefix; the host never comes from the request.
func TestUIBasePathPrefix(t *testing.T) {
	prev := cfg.ProxyBaseURL()
	t.Cleanup(func() { SetProxyBaseURL(prev) })
	for base, want := range map[string]string{
		"":                              "",
		"https://ui.example":            "",
		"https://ui.example/":           "",
		"https://ui.example/culvert":    "/culvert",
		"https://ui.example/a/culvert/": "/a/culvert",
		"https://ui.example//evil.test": "",
	} {
		SetProxyBaseURL(base)
		if got := uiBasePathPrefix(); got != want {
			t.Errorf("base %q: prefix %q, want %q", base, got, want)
		}
	}
}

// A clock that moved backwards re-arms the warning gate instead of silencing
// it until the clock catches up.
func TestCaptiveNoBaseURLWarning_ClockRollbackRearms(t *testing.T) {
	prev := captiveNoBaseURLLast.Load()
	t.Cleanup(func() { captiveNoBaseURLLast.Store(prev) })
	future := time.Now().Add(time.Hour).Unix()
	captiveNoBaseURLLast.Store(future)
	noteCaptiveNoBaseURL()
	if got := captiveNoBaseURLLast.Load(); got >= future {
		t.Fatalf("gate stayed armed at a future stamp (%d >= %d): the warning is silent after a clock rollback", got, future)
	}
	if !strings.HasPrefix(loginBindSecureCookieName, "__Host-") {
		t.Fatal("secure binding cookie lost its __Host- prefix")
	}
}
