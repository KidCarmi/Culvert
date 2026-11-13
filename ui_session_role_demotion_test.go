package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// SEC-UISESS-DEMOTE-1. The admin session cookie carries the role the roster
// granted AT LOGIN, and classifyUISession honoured that copy for the cookie's
// whole lifetime (up to the 7-day session TTL) while checking the live roster
// only for the account's EXISTENCE. Demoting an administrator through
// POST /api/auth/users therefore changed nothing for a session they already
// held: every admin-only route stayed reachable, including the one that
// assigns roles, so the demoted account could simply promote itself back.
//
// Driven through the production middleware chain and the real handlers; the
// cookies are minted by setUISessionCookie, the only production minter.

// demotionRig is a configured two-admin roster behind the real handler chain.
func demotionRig(t *testing.T) (h http.Handler, alice, mallory *http.Cookie) {
	t.Helper()
	withSessionKey(t)
	prev := cfg
	t.Cleanup(func() { cfg = prev })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	for _, name := range []string{"alice", "mallory"} {
		if err := cfg.SetUIUser(name, "Sup3rSecret!x", RoleAdmin); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	mint := func(name string) *http.Cookie {
		rec := httptest.NewRecorder()
		if err := setUISessionCookie(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", http.NoBody), name, RoleAdmin); err != nil {
			t.Fatalf("mint %s session: %v", name, err)
		}
		for _, c := range rec.Result().Cookies() {
			if c.Name == uiSessionCookieName {
				return c
			}
		}
		t.Fatalf("no %s cookie minted for %s", uiSessionCookieName, name)
		return nil
	}
	return d0WrappedHandler(t), mint("alice"), mint("mallory")
}

func demotionDo(h http.Handler, c *http.Cookie, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.61:4242"
	req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) // #nosec G124 -- request-side test cookie, never sent to a browser
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func demotionRosterRole(t *testing.T, name string) UIRole {
	t.Helper()
	for _, u := range cfg.ListUIUsers() {
		if u.Username == name {
			return u.Role
		}
	}
	t.Fatalf("%s is not in the roster", name)
	return ""
}

// DEFECT GATE. Pre-fix: the demoted session lists the roster (200) and then
// re-assigns itself admin (200), leaving the roster reading admin again.
func TestSessionRole_DemotedAdminSessionLosesAdmin(t *testing.T) {
	h, alice, mallory := demotionRig(t)

	// Precondition: before the demotion mallory's session IS an admin session.
	if rec := demotionDo(h, mallory, http.MethodGet, "/api/auth/users", ""); rec.Code != http.StatusOK {
		t.Fatalf("precondition: admin session refused on /api/auth/users: %d %s", rec.Code, rec.Body.String())
	}

	// alice demotes mallory through the real admin API.
	if rec := demotionDo(h, alice, http.MethodPost, "/api/auth/users", `{"username":"mallory","role":"viewer"}`); rec.Code != http.StatusOK {
		t.Fatalf("demotion request failed: %d %s", rec.Code, rec.Body.String())
	}
	if got := demotionRosterRole(t, "mallory"); got != RoleViewer {
		t.Fatalf("roster role after demotion = %q, want viewer", got)
	}

	// The session mallory already held must no longer be an admin session.
	if rec := demotionDo(h, mallory, http.MethodGet, "/api/auth/users", ""); rec.Code != http.StatusForbidden {
		t.Errorf("demoted session read the admin-only roster: got %d, want 403", rec.Code)
	}
	if rec := demotionDo(h, mallory, http.MethodPost, "/api/auth/users", `{"username":"mallory","role":"admin"}`); rec.Code != http.StatusForbidden {
		t.Errorf("demoted session re-assigned its own role: got %d, want 403", rec.Code)
	}
	if got := demotionRosterRole(t, "mallory"); got != RoleViewer {
		t.Errorf("demoted account promoted itself back: roster role = %q, want viewer", got)
	}
}

// CONTROL. A demotion narrows the session; it does not end it. The account is
// still a viewer, and /api/auth/status reports the role now actually granted.
func TestSessionRole_DemotedSessionKeepsItsNewRole(t *testing.T) {
	h, alice, mallory := demotionRig(t)
	if rec := demotionDo(h, alice, http.MethodPost, "/api/auth/users", `{"username":"mallory","role":"viewer"}`); rec.Code != http.StatusOK {
		t.Fatalf("demotion request failed: %d %s", rec.Code, rec.Body.String())
	}
	if rec := demotionDo(h, mallory, http.MethodGet, "/api/audit", ""); rec.Code != http.StatusOK {
		t.Fatalf("demoted session lost viewer access: got %d, want 200", rec.Code)
	}
	rec := demotionDo(h, mallory, http.MethodGet, "/api/auth/status", "")
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode status body %q: %v", rec.Body.String(), err)
	}
	if role, _ := body["role"].(string); role != string(RoleViewer) {
		t.Fatalf("/api/auth/status role = %q after demotion, want viewer (%v)", role, body)
	}
}

// CONTROL. The roster is a ceiling, not a source: a session minted at a lower
// role is not raised when the roster role is higher, and an unchanged roster
// leaves the session at exactly the role it was minted with.
func TestSessionRole_RosterIsACeilingNotASource(t *testing.T) {
	withSessionKey(t)
	prev := cfg
	t.Cleanup(func() { cfg = prev })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	if err := cfg.SetUIUser("bob", "Sup3rSecret!x", RoleAdmin); err != nil {
		t.Fatalf("seed roster: %v", err)
	}
	for _, minted := range []UIRole{RoleViewer, RoleOperator, RoleAdmin} {
		code, got, reached := driveMiddleware(t, string(minted))
		if !reached || code != http.StatusOK {
			t.Fatalf("session minted %q refused: status=%d reached=%v", minted, code, reached)
		}
		if got != minted {
			t.Fatalf("session minted %q injected as %q under an admin roster entry", minted, got)
		}
	}
}
