package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// TestIsSafeCaptiveRedirect covers the inline guard at proxy.go that gates
// the captive-portal redirect. The intent: same-origin paths and admin-
// configured absolute http(s) URLs are allowed; anything else is rejected.
func TestIsSafeCaptiveRedirect(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		// Empty / clearly bogus.
		{"empty", "", false},

		// Same-origin paths (admin-trusted IdP selection page, etc.).
		{"plain root", "/", true},
		{"auth select with relay", "/auth/select?relay=https%3A%2F%2Fexample.com%2F", true},
		{"deep path", "/some/path?x=1", true},

		// Protocol-relative URL → attacker host. MUST be rejected.
		{"protocol-relative", "//evil.example.com/login", false},
		{"protocol-relative slash-backslash", "/\\evil.example.com", false},

		// Custom schemes / data / javascript.
		{"javascript", "javascript:alert(1)", false},
		{"data uri", "data:text/html,<h1>x</h1>", false},
		{"ftp", "ftp://example.com/", false},
		{"file", "file:///etc/passwd", false},

		// Absolute URLs without host.
		{"http no host", "http://", false},
		{"https no host", "https://", false},

		// Valid admin-configured IdP URLs (absolute http/https with host).
		// NOTE: this guard does NOT call isPrivateHost — IdP URLs are admin
		// configuration, not user input. Private-host filtering is reserved
		// for redirects derived from request data (see isSafeRedirectURL).
		{"https IdP", "https://login.example.com/oauth/authorize?client_id=x", true},
		{"http IdP (lab)", "http://idp.lab.local/sso", true},

		// Malformed URL.
		{"missing scheme", "://no-scheme.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isSafeCaptiveRedirect(tc.in)
			if got != tc.want {
				t.Fatalf("isSafeCaptiveRedirect(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestSAMLCallback_RelayStateGuard sanity-checks the inline guard pattern
// used in authSAMLCallback: relayURL is only honoured when it parses to an
// absolute http(s) URL targeting a public host. We exercise the same shape
// check used at the call site — running the full SAML handler requires a
// configured provider and a valid signed assertion, which is outside the
// scope of a unit test.
func TestSAMLRelayStateInlineGuard(t *testing.T) {
	check := func(relayURL string) string {
		safeRelay := "/"
		if relayURL != "" {
			if u, err := url.Parse(relayURL); err == nil &&
				u.IsAbs() && (u.Scheme == "http" || u.Scheme == "https") &&
				isPrivateHost(u.Host) == nil {
				safeRelay = u.String()
			}
		}
		return safeRelay
	}

	cases := []struct {
		name string
		in   string
		want string // "/" or echo
	}{
		{"empty falls back", "", "/"},
		{"javascript falls back", "javascript:alert(1)", "/"},
		{"data uri falls back", "data:text/html,x", "/"},
		{"protocol-relative falls back", "//evil.example.com/", "/"},
		{"private host falls back", "http://127.0.0.1/x", "/"},
		{"private rfc1918 falls back", "http://10.0.0.5/", "/"},
		{"relative path falls back (not absolute)", "/some/path", "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := check(tc.in); got != tc.want {
				t.Fatalf("guard(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestCaptivePortalRedirect_RejectsUnsafe confirms the proxy auth path does
// not perform an http.Redirect when resolveCaptivePortalURL produces an
// unsafe-shaped value. We invoke the guard directly; the surrounding handler
// requires full proxy state to test end-to-end.
func TestCaptivePortalRedirect_RejectsUnsafe(t *testing.T) {
	for _, raw := range []string{
		"//evil.example.com/login",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"://broken",
	} {
		if isSafeCaptiveRedirect(raw) {
			t.Errorf("isSafeCaptiveRedirect(%q) = true, want false", raw)
		}
	}
}

// TestCaptivePortalRedirect_AcceptsKnownShapes mirrors the real values
// resolveCaptivePortalURL can return.
func TestCaptivePortalRedirect_AcceptsKnownShapes(t *testing.T) {
	for _, raw := range []string{
		"/auth/select?relay=" + url.QueryEscape("http://internal.example/"),
		"https://idp.example.com/oauth/authorize?client_id=abc",
	} {
		if !isSafeCaptiveRedirect(raw) {
			t.Errorf("isSafeCaptiveRedirect(%q) = false, want true", raw)
		}
	}
}

// TestCaptivePortalRedirect_HandlerSmoke wires up an httptest server with a
// handler that mimics the proxy.go decision: only redirect when the guard
// passes. Confirms behavior end-to-end at the http.Handler level.
func TestCaptivePortalRedirect_HandlerSmoke(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		loginURL := r.URL.Query().Get("u")
		if loginURL != "" && isSafeCaptiveRedirect(loginURL) {
			http.Redirect(w, r, loginURL, http.StatusFound)
			return
		}
		http.Error(w, "no redirect", http.StatusProxyAuthRequired)
	})

	cases := []struct {
		name           string
		login          string
		wantStatus     int
		wantLocPrefix  string // "" = no Location expected
		wantLocExactly string // optional exact match (overrides prefix)
	}{
		{"empty → 407", "", http.StatusProxyAuthRequired, "", ""},
		{"javascript → 407", "javascript:alert(1)", http.StatusProxyAuthRequired, "", ""},
		{"protocol-relative → 407", "//evil/", http.StatusProxyAuthRequired, "", ""},
		{"safe relative path → 302", "/auth/select?relay=x", http.StatusFound, "", "/auth/select?relay=x"},
		{"absolute https → 302", "https://idp.example.com/sso", http.StatusFound, "https://", "https://idp.example.com/sso"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/?u="+url.QueryEscape(tc.login), nil)
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
			if tc.wantLocExactly != "" {
				if loc := rec.Header().Get("Location"); loc != tc.wantLocExactly {
					t.Fatalf("Location = %q, want %q", loc, tc.wantLocExactly)
				}
			} else if tc.wantLocPrefix != "" {
				if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, tc.wantLocPrefix) {
					t.Fatalf("Location = %q, want prefix %q", loc, tc.wantLocPrefix)
				}
			}
		})
	}
}
