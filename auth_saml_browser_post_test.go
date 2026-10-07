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

// samlBrowserPost returns the status and cookies; the body is closed here.
func samlBrowserPost(t *testing.T, target, origin, method string, form url.Values) (int, []*http.Cookie) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Cookies()
}

func TestSAMLCallback_AcceptsTheBrowsersCrossSitePost(t *testing.T) {
	for _, origin := range []string{"https://idp.example", "null", ""} {
		t.Run("origin="+origin, func(t *testing.T) {
			srv, fixture := samlBrowserPostServer(t)
			form := url.Values{"RelayState": {fixture.state}, "SAMLResponse": {fixture.samlResponse}}
			status, cookies := samlBrowserPost(t, srv.URL+"/auth/saml/callback", origin, http.MethodPost, form)
			if status != http.StatusFound {
				t.Fatalf("SAML callback with Origin %q: %d, want 302", origin, status)
			}
			var got bool
			for _, c := range cookies {
				got = got || (c.Name == sessionCookieName && c.Value != "")
			}
			if !got {
				t.Fatalf("SAML callback with Origin %q set no %s cookie", origin, sessionCookieName)
			}
		})
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
		{http.MethodPost, "/api/auth/users"},
	} {
		status, _ := samlBrowserPost(t, srv.URL+tc.path, "https://idp.example", tc.method, form)
		if status != http.StatusForbidden {
			t.Errorf("%s %s from a foreign origin: %d, want 403", tc.method, tc.path, status)
		}
	}
	// The response the refused requests carried is still unredeemed: the
	// genuine callback succeeds afterwards (nothing above consumed it).
	if status, _ := samlBrowserPost(t, srv.URL+"/auth/saml/callback", "https://idp.example", http.MethodPost, form); status != http.StatusFound {
		t.Fatalf("genuine callback after the refused ones: %d, want 302", status)
	}
}
