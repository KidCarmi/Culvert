package main

// LAB-ONLY (#1528, ASTRA closeout): cookie-purpose replay end to end through a
// real SAML login. The lab copies this file into a checkout of the EXACT
// candidate source and runs it there; it is not part of the product tree.
//
// Everything is real HTTP against the product's own handlers: the admin UI
// chain (newAdminUIHandler, every middleware), the proxy listener
// (handleRequest) and a counting upstream. The only synthetic party is the
// SAML IdP: an ephemeral in-process signer (key generated per run, never
// written). It proves the SP flow and the cookie purposes, NOT
// interoperability with any vendor IdP, and says nothing about OIDC.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

// labSAMLIdP returns the SP under test and an ephemeral IdP that signs for it.
func labSAMLIdP(t *testing.T) (*SAMLProvider, *saml.IdentityProvider) {
	t.Helper()
	provider := testSAMLRedirectProvider(t)
	provider.sp.EntityID = "https://proxy.example"
	provider.sp.AuthnNameIDFormat = saml.EmailAddressNameIDFormat
	key, cert := newSAMLTestKeyPair(t, "Culvert lab IdP (ephemeral)")
	idp := &saml.IdentityProvider{
		Key:                     key,
		Certificate:             cert,
		MetadataURL:             *mustParseSAMLTestURL(t, "https://idp.example/metadata"),
		SSOURL:                  *mustParseSAMLTestURL(t, "https://idp.example/sso"),
		ServiceProviderProvider: testSAMLServiceProviderProvider{metadata: provider.sp.Metadata()},
	}
	provider.sp.IDPMetadata = idp.Metadata()
	return provider, idp
}

// labIdPRespond plays the IdP for one AuthnRequest URL: parse and validate the
// request the SP issued, sign an assertion for a fixed user, return the
// base64 SAMLResponse the browser would POST to the ACS.
func labIdPRespond(t *testing.T, idp *saml.IdentityProvider, loginURL string) string {
	t.Helper()
	req, err := saml.NewIdpAuthnRequest(idp, httptest.NewRequestWithContext(context.Background(), http.MethodGet, loginURL, nil))
	if err != nil {
		t.Fatalf("IdP: parse AuthnRequest: %v", err)
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("IdP: validate AuthnRequest: %v", err)
	}
	sess := &saml.Session{
		NameID: "alice@example.com", NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserEmail: "alice@example.com", UserCommonName: "Alice Example", Groups: []string{"engineering"},
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, sess); err != nil {
		t.Fatalf("IdP: make assertion: %v", err)
	}
	if err := req.MakeResponse(); err != nil {
		t.Fatalf("IdP: make response: %v", err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("IdP: serialize response: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

type labHTTP struct {
	t *testing.T
	c *http.Client
}

func newLabHTTP(t *testing.T) labHTTP {
	return labHTTP{t: t, c: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (h labHTTP) do(method, u string, body io.Reader, hdr map[string]string, cookies ...*http.Cookie) (*http.Response, string) {
	h.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, u, body)
	if err != nil {
		h.t.Fatalf("new request %s %s: %v", method, u, err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := h.c.Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", method, u, err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

func labCookie(resp *http.Response, name string) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	return nil
}

// renamed carries a cookie's signed VALUE under another cookie NAME: the
// replay ASTRA asked for, with no re-signing.
func renamed(c *http.Cookie, name string) *http.Cookie {
	return &http.Cookie{Name: name, Value: c.Value} // #nosec G124 -- request-side replay fixture
}

func TestLabSAMLCookiePurposeReplay(t *testing.T) {
	backend, cb := startCountingBackend(t)
	proxyURL := startAuthProxy(t, testProvider(), []PolicyRule{{Priority: 10, Name: "lab-allow-all", DestFQDN: "*", Action: ActionAllow}})
	if !sessionSecretSet() {
		initSessionSecret()
	}
	resetSAMLStateStore(t)
	provider, idp := labSAMLIdP(t)
	prevReg := idpRegistry
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "corp-saml", Name: "Corp SAML (lab)", Type: IdPTypeSAML, Enabled: true}},
		live:     map[string]IdentityProvider{"corp-saml": provider},
	}
	t.Cleanup(func() { idpRegistry = prevReg })
	ui := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(ui.Close)
	h := newLabHTTP(t)
	proxyGet := func(c *http.Cookie) (int, bool) {
		before := cb.hitCount()
		code := proxiedGet(t, proxyURL, backend.URL+"/", "", "", c)
		return code, cb.hitCount() > before
	}

	// 1-2. A real browser login: /auth/select (binding cookie + AuthnRequest)
	//      → IdP → signed response POSTed to the ACS with the IdP's Origin
	//      → (two-step candidates) 303 to /auth/saml/complete with the
	//      binding cookie → portal session.
	portal, stats := labSAMLLogin(t, h, ui.URL, idp, true)
	t.Logf("login: %s", stats)

	// Login CSRF (two-step candidates only): a login completed by a browser
	// that did NOT start it — no binding cookie — must produce no session.
	if _, csrf := labSAMLLogin(t, h, ui.URL, idp, false); csrf != "" {
		t.Logf("login-CSRF: %s", csrf)
	}

	// 3. A genuine admin UI session from the real login API.
	lb, _ := json.Marshal(map[string]string{"user": "admin", "pass": "admin-pass"})
	resp, body := h.do(http.MethodPost, ui.URL+"/api/auth/login", bytes.NewReader(lb), map[string]string{"Content-Type": "application/json", "Origin": ui.URL})
	admin := labCookie(resp, uiSessionCookieName)
	if resp.StatusCode != http.StatusOK || admin == nil {
		t.Fatalf("admin login: %d, cookie %v: %s", resp.StatusCode, admin != nil, body)
	}

	adminAPI := func(c *http.Cookie) int {
		var cs []*http.Cookie
		if c != nil {
			cs = append(cs, c)
		}
		r, _ := h.do(http.MethodGet, ui.URL+"/api/auth/users", nil, nil, cs...)
		return r.StatusCode
	}
	type row struct {
		name      string
		got, want int
		reached   bool
		wantReach bool
	}
	var rows []row
	add := func(name string, got, want int, reached, wantReach bool) {
		rows = append(rows, row{name, got, want, reached, wantReach})
	}

	// Controls: each cookie works where it belongs; nothing works without one.
	c, r := proxyGet(nil)
	add("proxy, no cookie (control)", c, http.StatusProxyAuthRequired, r, false)
	c, r = proxyGet(portal)
	add("proxy, SAML portal cookie as ps_session (positive control)", c, http.StatusOK, r, true)
	add("admin API, no cookie (control)", adminAPI(nil), http.StatusUnauthorized, false, false)
	add("admin API, admin cookie as ps_ui_session (positive control)", adminAPI(admin), http.StatusOK, false, false)

	// Replays across purposes, signed values unchanged.
	add("admin API, SAML portal value renamed to ps_ui_session", adminAPI(renamed(portal, uiSessionCookieName)), http.StatusUnauthorized, false, false)
	add("admin API, SAML portal cookie under its own name", adminAPI(portal), http.StatusUnauthorized, false, false)
	c, r = proxyGet(renamed(admin, sessionCookieName))
	add("proxy, admin value renamed to ps_session", c, http.StatusProxyAuthRequired, r, false)
	c, r = proxyGet(admin)
	add("proxy, admin cookie under its own name", c, http.StatusProxyAuthRequired, r, false)

	for _, x := range rows {
		ok := x.got == x.want && x.reached == x.wantReach
		verdict := "PASS"
		if !ok {
			verdict = "FAIL"
			t.Errorf("%s: status %d (want %d), upstream reached %v (want %v)", x.name, x.got, x.want, x.reached, x.wantReach)
		}
		t.Logf("%s | %s: %d, upstream reached %v", verdict, x.name, x.got, x.reached)
	}
}

// labBindCookie returns the login-binding cookie a response set, whatever its
// prefix (ps_login_bind, or __Host-ps_login_bind on HTTPS).
func labBindCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if strings.HasSuffix(c.Name, "ps_login_bind") && c.Value != "" {
			return c
		}
	}
	return nil
}

// labSAMLLogin drives one real browser login. asStarter=false completes it
// WITHOUT the starting browser's binding cookie (the login-CSRF attempt) and
// returns ("", "...") describing the refusal, or fails the test if a session
// was issued. Candidates without the two-step flow skip the CSRF attempt.
func labSAMLLogin(t *testing.T, h labHTTP, uiURL string, idp *saml.IdentityProvider, asStarter bool) (*http.Cookie, string) {
	t.Helper()
	resp, page := h.do(http.MethodGet, uiURL+"/auth/select?relay="+url.QueryEscape("https://app.example/protected"), nil, nil)
	bind := labBindCookie(resp)
	var loginURL string
	switch resp.StatusCode {
	case http.StatusFound: // one provider: straight to the IdP
		loginURL = resp.Header.Get("Location")
	case http.StatusOK:
		m := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("/auth/select offered no provider link: %s", page)
		}
		loginURL = html.UnescapeString(m[1])
	default:
		t.Fatalf("/auth/select: %d", resp.StatusCode)
	}
	lu, err := url.Parse(loginURL)
	if err != nil || lu.Host != "idp.example" || lu.Query().Get("SAMLRequest") == "" || lu.Query().Get("RelayState") == "" {
		t.Fatalf("login is not an AuthnRequest to the IdP: %q", loginURL)
	}
	form := url.Values{"RelayState": {lu.Query().Get("RelayState")}, "SAMLResponse": {labIdPRespond(t, idp, loginURL)}}.Encode()
	formHdr := map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://idp.example"}
	resp, body := h.do(http.MethodPost, uiURL+"/auth/saml/callback", strings.NewReader(form), formHdr)
	if resp.StatusCode == http.StatusFound { // one-step candidate: the ACS set the session
		if !asStarter {
			return nil, ""
		}
		portal := labCookie(resp, sessionCookieName)
		if portal == nil {
			t.Fatalf("SAML callback: 302 without a portal cookie: %s", body)
		}
		return portal, fmt.Sprintf("one-step ACS: 302, %s set", sessionCookieName)
	}
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, "/auth/saml/complete?t=") {
		t.Fatalf("SAML callback: %d %q: %s", resp.StatusCode, loc, body)
	}
	if labCookie(resp, sessionCookieName) != nil || labCookie(resp, uiSessionCookieName) != nil {
		t.Fatal("the ACS issued a session before the browser binding was checked")
	}
	var cookies []*http.Cookie
	if asStarter {
		if bind == nil {
			t.Fatal("/auth/select set no login-binding cookie")
		}
		cookies = append(cookies, bind)
	}
	resp, body = h.do(http.MethodGet, uiURL+loc, nil, nil, cookies...)
	portal := labCookie(resp, sessionCookieName)
	if !asStarter {
		if portal != nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("LOGIN CSRF: a login completed without the starting browser's binding: %d, session %v", resp.StatusCode, portal != nil)
		}
		return nil, fmt.Sprintf("PASS | completion without the starting browser's binding cookie: %d, no session", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusFound || portal == nil {
		t.Fatalf("SAML completion: %d, portal cookie %v: %s", resp.StatusCode, portal != nil, body)
	}
	// The completion token is single use.
	if r2, _ := h.do(http.MethodGet, uiURL+loc, nil, nil, cookies...); labCookie(r2, sessionCookieName) != nil {
		t.Fatal("completion token redeemed twice")
	}
	return portal, fmt.Sprintf("two-step: ACS 303 -> /auth/saml/complete with %s -> 302, %s set; token single-use", bind.Name, sessionCookieName)
}
