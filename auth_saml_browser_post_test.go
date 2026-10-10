package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A browser delivers the SAML response as a cross-site form POST from the
// IdP's page, so it carries the IdP's Origin (or "null"). The admin plane's
// same-origin CSRF check refused every such login with 403 until the ACS was
// exempted (lab SAML replay, #1528); the existing SAML tests never set Origin.

func samlBrowserPostServer(t *testing.T) (*httptest.Server, signedSAMLFixture) {
	t.Helper()
	configuredCfg(t)
	withSessionKey(t)
	fixture := newSignedSAMLFixture(t, nil)
	prev := idpRegistry
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{{ID: "corp-saml", Name: "Corp SAML", Type: IdPTypeSAML, Enabled: true}},
		live:     map[string]IdentityProvider{"corp-saml": fixture.provider},
	}
	t.Cleanup(func() { idpRegistry = prev })
	srv := httptest.NewServer(newAdminUIHandler())
	t.Cleanup(srv.Close)
	return srv, fixture
}

// samlBrowserPost returns the status, Location and cookies; the body is closed here.
func samlBrowserPost(t *testing.T, target, origin, method string, form url.Values) (status int, location string, cookies []*http.Cookie) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	return samlDo(t, req)
}

func samlDo(t *testing.T, req *http.Request) (status int, location string, cookies []*http.Cookie) {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location"), resp.Cookies()
}

// samlComplete follows the ACS's 303 to /auth/saml/complete, presenting
// cookie (the browser's ps_login_bind) when non-empty.
func samlComplete(t *testing.T, srv *httptest.Server, location, cookie string) (int, []*http.Cookie) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+location, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: loginBindCookieName, Value: cookie}) //nolint:gosec // request-side fixture: Secure/HttpOnly/SameSite are response attributes
	}
	status, _, cookies := samlDo(t, req)
	return status, cookies
}

func hasSession(cookies []*http.Cookie) bool {
	for _, c := range cookies {
		if c.Name == sessionCookieName && c.Value != "" {
			return true
		}
	}
	return false
}

// The ACS accepts the browser's cross-site POST, issues NO session itself, and
// hands off to /auth/saml/complete, which the starting browser completes.
func TestSAMLCallback_AcceptsTheBrowsersCrossSitePost(t *testing.T) {
	for _, origin := range []string{"https://idp.example", "null", ""} {
		t.Run("origin="+origin, func(t *testing.T) {
			srv, fixture := samlBrowserPostServer(t)
			form := url.Values{"RelayState": {fixture.state}, "SAMLResponse": {fixture.samlResponse}}
			status, loc, cookies := samlBrowserPost(t, srv.URL+"/auth/saml/callback", origin, http.MethodPost, form)
			if status != http.StatusSeeOther || !strings.HasPrefix(loc, "/auth/saml/complete?t=") {
				t.Fatalf("SAML callback with Origin %q: %d %q, want 303 to /auth/saml/complete", origin, status, loc)
			}
			if hasSession(cookies) {
				t.Fatal("the ACS issued a session before the browser binding was checked")
			}
			status, cookies = samlComplete(t, srv, loc, testLoginBindValue)
			if status != http.StatusFound || !hasSession(cookies) {
				t.Fatalf("completion by the starting browser: %d, session %v", status, hasSession(cookies))
			}
		})
	}
}

// Login CSRF: a login another browser started is never completed here.
func TestSAMLComplete_RequiresTheStartingBrowser(t *testing.T) {
	other := "b3RoZXItYnJvd3Nlci1iaW5kaW5nLXZhbHVlLTAxMjM"
	if !loginBindValueOK(other) {
		t.Fatal("bad fixture value")
	}
	for name, cookie := range map[string]string{"no cookie": "", "another browser": other, "malformed": "x"} {
		t.Run(name, func(t *testing.T) {
			srv, fixture := samlBrowserPostServer(t)
			form := url.Values{"RelayState": {fixture.state}, "SAMLResponse": {fixture.samlResponse}}
			_, loc, _ := samlBrowserPost(t, srv.URL+"/auth/saml/callback", "https://idp.example", http.MethodPost, form)
			status, cookies := samlComplete(t, srv, loc, cookie)
			if status != http.StatusForbidden || hasSession(cookies) {
				t.Fatalf("%s: %d, session %v — want 403 and no session", name, status, hasSession(cookies))
			}
			// The token was consumed: even the right browser cannot reuse it.
			if status, cookies := samlComplete(t, srv, loc, testLoginBindValue); status != http.StatusBadRequest || hasSession(cookies) {
				t.Fatalf("token reuse after a refusal: %d, session %v", status, hasSession(cookies))
			}
		})
	}
	// An unknown or missing token is refused.
	srv, _ := samlBrowserPostServer(t)
	if status, cookies := samlComplete(t, srv, "/auth/saml/complete?t=deadbeef", testLoginBindValue); status != http.StatusBadRequest || hasSession(cookies) {
		t.Fatalf("unknown token: %d", status)
	}
}

// The exemption is exactly POST /auth/saml/callback: every other cross-origin
// mutating request is still refused by the same check.
func TestSAMLCallback_OriginExemptionIsExact(t *testing.T) {
	srv, fixture := samlBrowserPostServer(t)
	form := url.Values{"RelayState": {fixture.state}, "SAMLResponse": {fixture.samlResponse}}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/api/auth/login"},
		{http.MethodPost, "/auth/saml/callback/"},
		{http.MethodPost, "/auth/saml/callbackx"},
		{http.MethodPut, "/auth/saml/callback"},
		{http.MethodDelete, "/auth/saml/callback"},
		{http.MethodPost, "/auth/saml/complete"},
		{http.MethodPost, "/api/auth/users"},
	} {
		status, _, _ := samlBrowserPost(t, srv.URL+tc.path, "https://idp.example", tc.method, form)
		if status != http.StatusForbidden {
			t.Errorf("%s %s from a foreign origin: %d, want 403", tc.method, tc.path, status)
		}
	}
	// The response the refused requests carried is still unredeemed: the
	// genuine callback succeeds afterwards (nothing above consumed it).
	if status, _, _ := samlBrowserPost(t, srv.URL+"/auth/saml/callback", "https://idp.example", http.MethodPost, form); status != http.StatusSeeOther {
		t.Fatalf("genuine callback after the refused ones: %d, want 303", status)
	}
}
