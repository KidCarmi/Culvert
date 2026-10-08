//go:build uie2e

package main

// F-SSO-SCOPE-1, real browser through Culvert. Every Culvert component is the
// product's own handler on a REAL TCP listener: the admin UI chain
// (newAdminUIHandler — every middleware), the forward proxy (handleRequest)
// and the login flow (/auth/select → OIDC callback). Headless Chromium is
// configured with Culvert as its HTTP proxy for web traffic (the UI and the
// IdP are reached directly, as a PAC file would arrange), so the origin is
// only ever reached THROUGH Culvert. The only synthetic party is the OIDC
// IdP: an in-process RS256 issuer (ephemeral key, PKCE S256, nonce) whose
// login page lets the browser pick the user.
//
// Everything listens on the host's first non-loopback IPv4 address, because
// a login from a loopback address is refused binding by design.
//
// Journey (each step asserts the browser's view AND whether the origin was
// reached):
//  1. not signed in → the proxy sends the browser to sign in; origin untouched
//  2. sign in as alice (engineering) → origin reachable, request attributed
//     to alice
//  3. sign out → the binding is gone; the origin is not reachable
//  4. sign in as bob (finance) → policy denies (403); origin untouched
//  5. transport turned off → no sign-in redirect; the challenge explains why

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/playwright-community/playwright-go"
)

func e2eHostIPv4(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("no interface addresses: %v", err)
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && !n.IP.IsLoopback() {
			return n.IP.String()
		}
	}
	t.Skip("no non-loopback IPv4 address: the journey needs a client address that is not loopback")
	return ""
}

func e2eServe(t *testing.T, host string, h http.Handler) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", host+":0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln) //nolint:errcheck // closed in cleanup
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// e2eOIDCIdP is a minimal OIDC provider: an authorize page that lets the
// browser pick a user, a PKCE-checking token endpoint and a JWKS.
type e2eOIDCIdP struct {
	issuer string
	key    *rsa.PrivateKey
	mu     sync.Mutex
	codes  map[string]e2eCode
	users  map[string][]string // sub → groups
}

type e2eCode struct{ sub, nonce, challenge, redirect string }

func (p *e2eOIDCIdP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/authorize":
		q := r.URL.Query()
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, `<!DOCTYPE html><html><body><h1>Test IdP sign-in</h1><form method="post" action="/authorize?%s">`, html.EscapeString(r.URL.RawQuery))
			for sub := range p.users {
				fmt.Fprintf(w, `<button type="submit" name="user" value="%s" id="login-%s">Sign in as %s</button>`, sub, sub, sub)
			}
			fmt.Fprint(w, `</form></body></html>`)
			return
		}
		_ = r.ParseForm()
		sub := r.PostForm.Get("user")
		if _, ok := p.users[sub]; !ok || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "bad login", http.StatusBadRequest)
			return
		}
		code := e2eRand()
		p.mu.Lock()
		p.codes[code] = e2eCode{sub: sub, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	case "/token":
		_ = r.ParseForm()
		p.mu.Lock()
		c, ok := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || r.PostForm.Get("redirect_uri") != c.redirect {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		now := time.Now()
		tok := jwtv5.NewWithClaims(jwtv5.SigningMethodRS256, jwtv5.MapClaims{
			"iss": p.issuer, "aud": "culvert-e2e", "sub": c.sub, "email": c.sub + "@example.com",
			"groups": p.users[c.sub], "nonce": c.nonce, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		})
		tok.Header["kid"] = "e2e"
		raw, err := tok.SignedString(p.key)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"access_token": e2eRand(), "id_token": raw, "token_type": "Bearer"})
	case "/jwks":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "e2e", "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(p.key.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(p.key.E)).Bytes()),
		}}})
	default:
		http.NotFound(w, r)
	}
}

func e2eRand() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// ssoE2E is the running journey: real listeners, the test IdP and a Chromium
// page whose web traffic goes through Culvert's proxy.
type ssoE2E struct {
	host, originAddr, issuer, uiAddr, proxyAddr, origin string
	hits                                                *atomic.Int64
	page                                                playwright.Page
}

func newSSOE2E(t *testing.T) *ssoE2E {
	t.Helper()
	host := e2eHostIPv4(t)
	setupProxyTest(t) // resets globals; default-deny
	if err := cfg.SetAuth("e2e-admin", "E2e-admin-pass-1!"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cfg.SetAuth("", "") }) //nolint:errcheck // test cleanup
	if !sessionSecretSet() {
		initSessionSecret()
	}
	withFreshPolicyStore(t)
	policyStore.Add(PolicyRule{Priority: 10, Name: "e2e-eng-allow", DestFQDN: "*", SourceGroup: "engineering", Action: ActionAllow})

	// Origin: counts every request for the page that reaches it (the
	// browser's own /favicon.ico fetches are not page visits).
	originHits := new(atomic.Int64)
	// It listens on LOOPBACK — a different host from the UI. Cookies are scoped
	// by host, not port: an origin on the UI's address would receive the SSO
	// session cookie through the proxy and be authenticated by THAT, proving
	// nothing about the binding. On another host only the binding can
	// identify the browser.
	originAddr := e2eServe(t, "127.0.0.1", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/page" {
			http.NotFound(w, r)
			return
		}
		originHits.Add(1)
		fmt.Fprint(w, "<html><body>origin-ok</body></html>")
	}))

	// IdP.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idpSrv := &e2eOIDCIdP{key: key, codes: map[string]e2eCode{}, users: map[string][]string{"alice": {"engineering"}, "bob": {"finance"}}}
	idpAddr := e2eServe(t, host, idpSrv)
	idpSrv.issuer = "http://" + idpAddr

	// Admin UI (login flow) and proxy.
	uiAddr := e2eServe(t, host, newAdminUIHandler())
	proxyAddr := e2eServe(t, host, http.HandlerFunc(handleRequest))
	prevBase := cfg.ProxyBaseURL()
	SetProxyBaseURL("http://" + uiAddr)
	t.Cleanup(func() { SetProxyBaseURL(prevBase) })

	// The OIDC provider: the product's own type and flow; its HTTP client is a
	// plain one only because the production dialer refuses private addresses
	// (the SSRF guard), and this test's IdP lives on one.
	resetPKCEStoreForE2E(t)
	prof := &IdPProfile{ID: "corp", Name: "Corp SSO (e2e)", Type: IdPTypeOIDC, Enabled: true}
	client := &http.Client{Timeout: 10 * time.Second}
	prov := &OIDCFlowProvider{
		profile: prof,
		cfg:     &OIDCProfileConfig{ClientID: "culvert-e2e", Issuer: idpSrv.issuer},
		disc:    &oidcDiscoveryDoc{Issuer: idpSrv.issuer, AuthorizationEndpoint: idpSrv.issuer + "/authorize", TokenEndpoint: idpSrv.issuer + "/token", JWKsURI: idpSrv.issuer + "/jwks"},
		client:  client,
		cache:   map[string]*oidcCacheEntry{},
		ttl:     oidcFlowCacheTTL,
		jwks:    &jwksCache{jwksURI: idpSrv.issuer + "/jwks", client: client, keys: make(map[string]interface{})},
	}
	origReg := idpRegistry
	idpRegistry = &IdPRegistry{profiles: []*IdPProfile{prof}, live: map[string]IdentityProvider{"corp": prov}}
	t.Cleanup(func() { idpRegistry = origReg })
	withSSOSurrogate(t, ssoSurrogateSettings{Enabled: true})
	// The browser runs on this host, so the address it signs in from is one
	// of the appliance's own — refused binding in production. Stand it in for
	// a client on another machine (the only seam in the journey).
	prevSelf := ssoSurrogateSelfAddr
	ssoSurrogateSelfAddr = func(netip.Addr) bool { return false }
	t.Cleanup(func() { ssoSurrogateSelfAddr = prevSelf })

	// <-loopback> makes Chromium send loopback traffic (the origin) through the
	// proxy too; the UI and the IdP are reached directly.
	browser := uiE2EBrowserWithArgs(t, "--proxy-server=http://"+proxyAddr, "--proxy-bypass-list=<-loopback>;"+uiAddr+";"+idpAddr)
	bctx, err := browser.NewContext()
	if err != nil {
		t.Fatal(err)
	}
	page, err := bctx.NewPage()
	if err != nil {
		t.Fatal(err)
	}
	return &ssoE2E{host: host, originAddr: originAddr, issuer: idpSrv.issuer, uiAddr: uiAddr, proxyAddr: proxyAddr,
		origin: "http://" + originAddr + "/page", hits: originHits, page: page}
}

func (e *ssoE2E) visit(t *testing.T, step string) (code int, body string) {
	t.Helper()
	resp, err := e.page.Goto(e.origin, playwright.PageGotoOptions{WaitUntil: playwright.WaitUntilStateLoad})
	if err != nil {
		t.Fatalf("%s: goto: %v", step, err)
	}
	body, _ = e.page.Content()
	return resp.Status(), body
}

func (e *ssoE2E) signIn(t *testing.T, step, user string) {
	t.Helper()
	if !strings.HasPrefix(e.page.URL(), e.issuer+"/authorize") {
		t.Fatalf("%s: browser is not on the IdP sign-in page: %s", step, e.page.URL())
	}
	if err := e.page.Locator("#login-" + user).Click(); err != nil {
		t.Fatalf("%s: click: %v", step, err)
	}
	// The callback returns the browser to the UI host (a private-address
	// relay is not followed — isSafeRedirectURL).
	if err := e.page.WaitForURL("http://"+e.uiAddr+"/**", playwright.PageWaitForURLOptions{Timeout: playwright.Float(15000)}); err != nil {
		t.Fatalf("%s: login did not complete: %v (at %s)", step, err, e.page.URL())
	}
}

func TestUIE2E_SSOIPBinding_BrowserThroughCulvert(t *testing.T) {
	e := newSSOE2E(t)
	originHits, page, origin, uiAddr, proxyAddr, originAddr, host := e.hits, e.page, e.origin, e.uiAddr, e.proxyAddr, e.originAddr, e.host
	idpIssuer := e.issuer
	visit := func(step string) (int, string) { t.Helper(); return e.visit(t, step) }
	signIn := func(step, user string) { t.Helper(); e.signIn(t, step, user) }

	// 1. Not signed in: sent to sign in (UI host → IdP), origin untouched.
	before := originHits.Load()
	if _, _ = visit("1"); !strings.HasPrefix(page.URL(), idpIssuer+"/authorize") || originHits.Load() != before {
		t.Fatalf("1: unauthenticated browser at %s, origin hits %d→%d", page.URL(), before, originHits.Load())
	}
	t.Logf("PASS 1 not signed in → sent to sign in at %s; origin not reached", strings.SplitN(page.URL(), "?", 2)[0])

	// 2. Sign in as alice (engineering) → the origin is reachable through
	//    Culvert and the request is attributed to her.
	signIn("2", "alice")
	code, body := visit("2")
	if code != http.StatusOK || !strings.Contains(body, "origin-ok") || originHits.Load() != before+1 {
		t.Fatalf("2: alice: status %d, origin hits %d→%d, body %.200q", code, before, originHits.Load(), body)
	}
	if e := findLogByHost(t, originAddr); e.Identity != "alice" || e.AuthSource != "sso-ip:corp" {
		t.Fatalf("2: request attributed to %q via %q, want alice via sso-ip:corp", e.Identity, e.AuthSource)
	}
	t.Logf("PASS 2 signed in as alice (engineering) → origin (another host: no session cookie reaches it) 200 through Culvert, attributed to alice by the binding")

	// 3. Sign out → binding removed → origin not reachable.
	if _, err := page.Goto("http://" + uiAddr + "/api/auth/status"); err != nil { // a UI-host page, for a same-origin POST
		t.Fatal(err)
	}
	st, err := page.Evaluate(`fetch('/auth/logout', {method: 'POST', redirect: 'manual'}).then(r => r.type + ':' + r.status)`)
	if err != nil {
		t.Fatalf("3: logout: %v", err)
	}
	if ssoSurrogate.Len() != 0 {
		t.Fatalf("3: logout (%v) left %d binding(s)", st, ssoSurrogate.Len())
	}
	before = originHits.Load()
	visit("3")
	if !strings.HasPrefix(page.URL(), idpIssuer+"/authorize") || originHits.Load() != before {
		t.Fatalf("3: after sign-out at %s, origin hits %d→%d", page.URL(), before, originHits.Load())
	}
	t.Logf("PASS 3 signed out → binding removed; sent to sign in again; origin not reached")

	// 4. Sign in as bob (finance) → policy denies.
	before = originHits.Load()
	signIn("4", "bob")
	code, body = visit("4")
	if !strings.Contains(body, "Access Denied") {
		t.Fatalf("4: bob: not the block page: %.200q", body)
	}
	if code != http.StatusForbidden || originHits.Load() != before {
		t.Fatalf("4: bob: status %d, origin hits %d→%d", code, before, originHits.Load())
	}
	t.Logf("PASS 4 signed in as bob (finance) → 403 by policy; origin not reached")

	// 5. Transport off → no redirect; the challenge says why.
	rt, _ := resolveSSOSurrogateSettings(ssoSurrogateSettings{Enabled: false})
	applySSOSurrogate(rt)
	before = originHits.Load()
	// Chromium answers a 407 Basic challenge it has no credentials for with
	// net::ERR_INVALID_AUTH_CREDENTIALS rather than rendering the body: that
	// failure IS the browser-side evidence of a challenge instead of a
	// sign-in redirect.
	_, gerr := page.Goto(origin)
	if gerr == nil || !strings.Contains(gerr.Error(), "ERR_INVALID_AUTH_CREDENTIALS") || strings.HasPrefix(page.URL(), idpIssuer) || originHits.Load() != before {
		t.Fatalf("5: off: goto err %v at %s, origin hits %d→%d", gerr, page.URL(), before, originHits.Load())
	}
	// The challenge body, from the same proxy for the same client address.
	pu, _ := url.Parse("http://" + proxyAddr)
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(pu),
		DialContext: (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(host)}}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, origin, http.NoBody)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatalf("5: direct check: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired || resp.Header.Get("Location") != "" || !strings.Contains(string(b), "IP-bound sign-in is disabled") || originHits.Load() != before {
		t.Fatalf("5: off: %d %q %q", resp.StatusCode, resp.Header.Get("Location"), b)
	}
	t.Logf("PASS 5 transport off → the browser is challenged (ERR_INVALID_AUTH_CREDENTIALS), not sent to sign in; the 407 says %q; origin not reached", strings.TrimSpace(string(b)))
}

func resetPKCEStoreForE2E(t *testing.T) {
	t.Helper()
	orig := globalPKCEStore
	globalPKCEStore = newPKCEStore()
	t.Cleanup(func() { globalPKCEStore = orig })
}
