package main

// ui_auth_logout_guard_test.go — AU-54 and AU-55 (Codex P2 x2, PR #1437).
//
// AU-55: a cross-site GET to /auth/logout carried the SameSite=Lax portal
// cookie and performed a durable, fleet-wide revocation. It now mutates
// NOTHING and answers a same-origin confirmation page; same-origin, same-site,
// none and an absent Sec-Fetch-Site keep the browser-navigation behaviour.
//
// AU-54: the durable revocation sat on a public route outside every limiter.
// A cookie-bearing logout is now charged to the same per-client limiter the
// /api/ mutations use, and over it NOTHING happens — the cookie is not
// cleared while the revocation is skipped (that would be fail-open).

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/lockout"
)

// withFreshAPILimiter isolates the process-wide apiLimiter for one test.
func withFreshAPILimiter(t *testing.T) {
	t.Helper()
	prev := apiLimiter
	apiLimiter = lockout.NewAPIRateLimiter()
	t.Cleanup(func() { apiLimiter = prev })
}

func au55LogoutRequest(method, value, fetchSite string) *http.Request {
	req := logoutRequestWithCookie(sessionCookieName, value)
	req.Method = method
	req.Host = "culvert.example"
	req.RemoteAddr = "198.51.100.7:4242"
	if fetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", fetchSite)
	}
	return req
}

func clearedPortalCookie(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// DEFECT (AU-55): a cross-site GET mutates nothing.
func TestAU55_CrossSiteLogoutMutatesNothingAndAsksToConfirm(t *testing.T) {
	withChaos68Revocations(t)
	withFreshAPILimiter(t)
	value, key := logoutTestSession(t, "au55-cross-site")

	w := httptest.NewRecorder()
	securityMiddleware(http.HandlerFunc(authLogout)).ServeHTTP(w, au55LogoutRequest(http.MethodGet, value, "cross-site"))

	if sessionRevoked.IsRevoked(key) {
		t.Fatal("a cross-site GET revoked the session: any site the user visits can still drive a durable fleet-wide write")
	}
	if _, err := decodeSession(value); err != nil {
		t.Fatalf("the session no longer decodes after a cross-site GET: %v", err)
	}
	if clearedPortalCookie(w) {
		t.Error("a cross-site GET cleared the cookie; the confirmation answer must change nothing")
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, want 200 with the confirmation page", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, `<form method="POST" action="/auth/logout">`) {
		t.Errorf("the confirmation page has no same-origin POST form:\n%s", body)
	}
	if strings.Contains(body, "<script") {
		t.Error("the confirmation page carries a script; it must need none under the nonce-only CSP")
	}
	// Same headers as every page securityMiddleware serves.
	if csp := w.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP %q is not the server-rendered pages' policy", csp)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("headers XFO=%q Cache-Control=%q, want DENY and no-store",
			w.Header().Get("X-Frame-Options"), w.Header().Get("Cache-Control"))
	}
}

// CONTROL (AU-55): every non-cross-site value, and an absent header, keep the
// browser-navigation behaviour — revoke, clear, redirect. The absent case is
// the recorded fail-closed choice: refusing to revoke for a client that sends
// no Fetch Metadata would leave a logged-out token valid.
func TestAU55_ControlOwnNavigationStillRevokes(t *testing.T) {
	for _, site := range []string{"same-origin", "same-site", "none", ""} {
		t.Run("Sec-Fetch-Site="+site, func(t *testing.T) {
			withChaos68Revocations(t)
			withFreshAPILimiter(t)
			value, key := logoutTestSession(t, "au55-own-"+site)

			w := httptest.NewRecorder()
			securityMiddleware(http.HandlerFunc(authLogout)).ServeHTTP(w, au55LogoutRequest(http.MethodGet, value, site))

			if w.Code != http.StatusFound {
				t.Fatalf("status %d, want the 302 navigation surface", w.Code)
			}
			if !sessionRevoked.IsRevoked(key) {
				t.Error("the user's own logout did not revoke the token")
			}
			if !clearedPortalCookie(w) {
				t.Error("the user's own logout did not clear the cookie")
			}
		})
	}
}

// The confirmation form's POST is accepted and revokes; a forged cross-site
// POST is refused by securityMiddleware's same-origin check before the handler.
func TestAU55_ConfirmationPostRevokesAndForeignPostIsRefused(t *testing.T) {
	t.Run("same-origin POST from the confirmation page", func(t *testing.T) {
		withChaos68Revocations(t)
		withFreshAPILimiter(t)
		value, key := logoutTestSession(t, "au55-post")
		req := au55LogoutRequest(http.MethodPost, value, "same-origin")
		req.Header.Set("Origin", "https://culvert.example")

		w := httptest.NewRecorder()
		securityMiddleware(http.HandlerFunc(authLogout)).ServeHTTP(w, req)
		if w.Code != http.StatusFound || !sessionRevoked.IsRevoked(key) || !clearedPortalCookie(w) {
			t.Fatalf("status %d revoked=%v cleared=%v; the confirmed POST must log out",
				w.Code, sessionRevoked.IsRevoked(key), clearedPortalCookie(w))
		}
	})
	t.Run("cross-site POST", func(t *testing.T) {
		withChaos68Revocations(t)
		withFreshAPILimiter(t)
		value, key := logoutTestSession(t, "au55-forged-post")
		req := au55LogoutRequest(http.MethodPost, value, "")
		req.Header.Set("Origin", "https://attacker.example")

		w := httptest.NewRecorder()
		securityMiddleware(http.HandlerFunc(authLogout)).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403 from the same-origin check", w.Code)
		}
		if sessionRevoked.IsRevoked(key) {
			t.Fatal("a cross-site POST revoked the session")
		}
	})
}

// DEFECT (AU-54): past the per-client limit the logout is refused WHOLE.
func TestAU54_LogoutLoopIsAdmittedThenRefusedWithoutClearing(t *testing.T) {
	withChaos68Revocations(t)
	withFreshAPILimiter(t)

	for i := range apiRateBurst {
		value, key := logoutTestSession(t, "au54-loop")
		w := httptest.NewRecorder()
		authLogout(w, au55LogoutRequest(http.MethodGet, value, "same-origin"))
		if w.Code != http.StatusFound || !sessionRevoked.IsRevoked(key) {
			t.Fatalf("logout %d inside the limit: status %d revoked=%v", i+1, w.Code, sessionRevoked.IsRevoked(key))
		}
	}
	tracked := sessionRevoked.Tracked()

	value, key := logoutTestSession(t, "au54-loop")
	w := httptest.NewRecorder()
	authLogout(w, au55LogoutRequest(http.MethodGet, value, "same-origin"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("logout %d: status %d, want 429", apiRateBurst+1, w.Code)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("the 429 carries no Retry-After")
	}
	if sessionRevoked.IsRevoked(key) || sessionRevoked.Tracked() != tracked {
		t.Error("an over-limit logout still added a durable revocation entry")
	}
	if clearedPortalCookie(w) {
		t.Fatal("an over-limit logout cleared the cookie while skipping the revocation: the user is told they are signed out while the token stays valid")
	}

	// CONTROL: the limit is per client — another address is admitted.
	other := au55LogoutRequest(http.MethodGet, value, "same-origin")
	other.RemoteAddr = "203.0.113.9:4242"
	w = httptest.NewRecorder()
	authLogout(w, other)
	if w.Code != http.StatusFound || !sessionRevoked.IsRevoked(key) {
		t.Fatalf("a different client was refused (status %d): the limiter is not per-client", w.Code)
	}
}

// CONTROL (AU-54): a request with no session cookie has nothing to revoke and
// is not charged, so clicking Log out with an already-cleared cookie can never
// exhaust a real logout's budget.
func TestAU54_ControlCookielessLogoutIsNotCharged(t *testing.T) {
	withChaos68Revocations(t)
	withFreshAPILimiter(t)
	for range apiRateBurst + 5 {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/logout", http.NoBody)
		req.RemoteAddr = "198.51.100.7:4242"
		w := httptest.NewRecorder()
		authLogout(w, req)
		if w.Code != http.StatusFound {
			t.Fatalf("a cookieless logout answered %d", w.Code)
		}
	}
	value, key := logoutTestSession(t, "au54-after-cookieless")
	w := httptest.NewRecorder()
	authLogout(w, au55LogoutRequest(http.MethodGet, value, ""))
	if w.Code != http.StatusFound || !sessionRevoked.IsRevoked(key) {
		t.Fatalf("a real logout after cookieless ones was refused (status %d)", w.Code)
	}
}

// The budget is the SAME one the /api/ mutations spend: a client that has
// used it on admin mutations cannot then drive portal-logout writes.
func TestAU54_PortalLogoutSharesTheAPIMutationBudget(t *testing.T) {
	withChaos68Revocations(t)
	withFreshAPILimiter(t)
	noop := securityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for range apiRateBurst {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/au54-noop", http.NoBody)
		req.RemoteAddr = "198.51.100.7:4242"
		noop.ServeHTTP(httptest.NewRecorder(), req)
	}
	value, key := logoutTestSession(t, "au54-shared")
	w := httptest.NewRecorder()
	authLogout(w, au55LogoutRequest(http.MethodGet, value, ""))
	if w.Code != http.StatusTooManyRequests || sessionRevoked.IsRevoked(key) {
		t.Fatalf("status %d revoked=%v; the portal logout must spend the /api/ mutation budget", w.Code, sessionRevoked.IsRevoked(key))
	}
}
