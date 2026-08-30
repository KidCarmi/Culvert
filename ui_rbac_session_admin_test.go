package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// sessionAdmin and the auditEventDiff actor enrichment must read the admin
// UI cookie (ps_ui_session), not the proxy-user cookie (ps_session). Cookies
// are host-scoped, so a browser holding a captive-portal proxy session would
// otherwise attribute admin actions to the proxy-user identity — and admin
// UI logins (which only set ps_ui_session) would always audit as "unknown".

func uiSessionCookieForTest(t *testing.T, sub string) *http.Cookie {
	t.Helper()
	tok, err := encodeSession(&Session{
		Sub:      sub,
		Provider: "local",
		Role:     string(RoleAdmin),
		Exp:      time.Now().Add(time.Hour).Unix(),
		Jti:      newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	// Attributes are inert on a request cookie (handler just reads Value) but
	// satisfy gosec G124 without a //nolint suppression.
	return &http.Cookie{Name: uiSessionCookieName, Value: tok, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func proxySessionCookieForTest(t *testing.T, sub string) *http.Cookie {
	t.Helper()
	tok, err := encodeSession(&Session{
		Sub:      sub,
		Provider: "oidc",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Jti:      newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}
	return &http.Cookie{Name: sessionCookieName, Value: tok, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}

func TestSessionAdmin_ReadsUISessionCookie(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/policy", nil)
	r.AddCookie(uiSessionCookieForTest(t, "alice-admin"))

	if got := sessionAdmin(r); got != "alice-admin" {
		t.Fatalf("sessionAdmin = %q, want %q", got, "alice-admin")
	}
}

func TestSessionAdmin_IgnoresProxyUserCookie(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/policy", nil)
	r.AddCookie(proxySessionCookieForTest(t, "browsing-user"))

	if got := sessionAdmin(r); got != "unknown" {
		t.Fatalf("sessionAdmin = %q, want %q (proxy-user cookie must not attribute admin actions)", got, "unknown")
	}
}

// TestSessionAdmin_BasicAuthUsernameFromContext is the Codex P2 (round-11) proof: an admin action
// taken via the HTTP Basic fallback (no session cookie) is attributed to the real actor — the UI
// middleware stores the authenticated username in context and sessionAdmin resolves it — rather than
// "unknown".
func TestSessionAdmin_BasicAuthUsernameFromContext(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/mcp/canary/shadow-exit-review", nil)
	r = r.WithContext(context.WithValue(r.Context(), uiUserKey{}, "basic-admin"))
	if got := sessionAdmin(r); got != "basic-admin" {
		t.Fatalf("sessionAdmin must resolve the Basic-auth username from context, got %q", got)
	}
	// With neither a cookie nor a context username, the actor is unknown.
	r2 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/x", nil)
	if got := sessionAdmin(r2); got != "unknown" {
		t.Fatalf("sessionAdmin with no identity must be unknown, got %q", got)
	}
	// The session cookie still wins over any context username.
	r3 := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/x", nil)
	r3.AddCookie(uiSessionCookieForTest(t, "cookie-admin"))
	r3 = r3.WithContext(context.WithValue(r3.Context(), uiUserKey{}, "basic-admin"))
	if got := sessionAdmin(r3); got != "cookie-admin" {
		t.Fatalf("the session cookie identity must win over the context username, got %q", got)
	}
}

func TestAuditEvent_ActorEnrichedFromUISession(t *testing.T) {
	// Both cookies present: the admin identity must win, not the proxy user.
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/policy", nil)
	r.RemoteAddr = "198.51.100.77:4242" // TEST-NET-2 discriminator
	r.AddCookie(uiSessionCookieForTest(t, "carol-admin"))
	r.AddCookie(proxySessionCookieForTest(t, "browsing-user"))

	baseline := time.Now().UnixMilli()
	auditEvent(r, "test.actor_enrichment", "obj", "detail")

	want := "carol-admin@198.51.100.77"
	for _, e := range auditGet() {
		if e.TS >= baseline && e.Action == "test.actor_enrichment" && e.Actor == want {
			return
		}
	}
	t.Fatalf("no audit entry with actor %q and action %q found after baseline", want, "test.actor_enrichment")
}
