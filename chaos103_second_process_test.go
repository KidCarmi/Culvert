package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// chaos103_second_process_test.go — CHAOS-103.
//
// The failure these gates exist for was reproduced end to end against a build
// of main (f31744c), two processes on one /data, different ports:
//
//	A (the gateway)         B (the accidental instance, booted first)
//	POST /api/setup/complete  →  roster on disk = [alice]
//	                          GET  /api/setup/status      → needsSetup:true
//	                          GET  /api/auth/users        → 200, no credentials
//	                          POST /api/policy            → 200, Allow+Bypass rule persisted
//	                          POST /api/auth/users        → 200, new admin persisted
//	                          POST /api/setup/complete     → roster on disk = [attacker]
//	A restarts                →  alice 401, attacker is the only admin
//
// Nothing in either process logged a word about the other. Two mechanisms close
// it and each is gated separately, because the second one has to hold where the
// first degrades by design:
//
//   - datadir_writer_lock_test.go — the second process does not boot.
//   - these gates — the unauthenticated bootstrap window is decided by the
//     DURABLE roster, so it is closed even in a process that did boot.

// chaos103SecondProcess puts the global cfg in the exact state the second
// process was in: a loaded-and-empty in-memory roster, pointed at a roster file
// that a DIFFERENT process has since filled in.
func chaos103SecondProcess(t *testing.T) {
	t.Helper()
	withRosterOnDisk(t, adminRoster(t, RoleAdmin))
	if cfg.IsConfigured() {
		t.Fatal("premise broken: the second process must believe it is unconfigured, or these gates prove nothing")
	}
}

// TestCHAOS103_MiddlewareGrantsNoAuthorityToASecondProcess is the gate that
// matters most. uiAuthMiddleware's first-run branch injects RoleAdmin into the
// request context with no credentials at all; in the second process that branch
// was live forever.
func TestCHAOS103_MiddlewareGrantsNoAuthorityToASecondProcess(t *testing.T) {
	chaos103SecondProcess(t)

	var reached bool
	var granted UIRole
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		granted, _ = r.Context().Value(uiRoleKey{}).(UIRole)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/users", http.NoBody)
	req.RemoteAddr = "198.51.100.42:0"
	uiAuthMiddleware(sentinel).ServeHTTP(rec, req)

	if reached {
		t.Fatalf("an unauthenticated admin request reached the handler as %q — the bootstrap window is open in a process that is not bootstrapping", granted)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestCHAOS103_MiddlewareStillBootstrapsAGenuineFreshInstall is the negative
// control for the gate above. If closing the window also closed it on a real
// first run, a new install could never be configured — so this asserts the
// branch the fix must leave alone, and it is what makes the gate above
// non-vacuous.
func TestCHAOS103_MiddlewareStillBootstrapsAGenuineFreshInstall(t *testing.T) {
	withRosterOnDisk(t, "") // configured path, no file: a real first run

	var reached bool
	var granted UIRole
	sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		granted, _ = r.Context().Value(uiRoleKey{}).(UIRole)
		w.WriteHeader(http.StatusOK)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/auth/users", http.NoBody)
	req.RemoteAddr = "198.51.100.43:0"
	uiAuthMiddleware(sentinel).ServeHTTP(rec, req)

	if !reached {
		t.Fatalf("a genuine fresh install must still reach the admin surface during setup (status=%d)", rec.Code)
	}
	if granted != RoleAdmin {
		t.Fatalf("first-run grant = %q, want %q", granted, RoleAdmin)
	}
}

// TestCHAOS103_AuthStatusReportsNoSessionInASecondProcess pins the surface the
// shipped console reads to decide whether to render the admin UI or the wizard.
// Reporting a logged-in admin here is how the second process looked like a
// legitimately open install to a browser.
func TestCHAOS103_AuthStatusReportsNoSessionInASecondProcess(t *testing.T) {
	chaos103SecondProcess(t)

	rec := httptest.NewRecorder()
	apiAuthStatus(rec, getReq("/api/auth/status"))

	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["loggedIn"] == true {
		t.Fatalf("/api/auth/status reported a logged-in principal with no credentials: %v", got)
	}
	if got["role"] == string(RoleAdmin) {
		t.Fatalf("/api/auth/status reported RoleAdmin with no credentials: %v", got)
	}
}

// TestCHAOS103_LoginMintsNoSessionForAnArbitraryUserInASecondProcess covers the
// third gate on the same predicate: apiAuthLogin's pre-setup branch forces
// (RoleAdmin, ok) for ANY credentials, which in the second process would mint a
// real signed admin session for an attacker-chosen username — and that session
// stays valid against the live roster the moment the name happens to exist
// (ui_auth.go records the same hazard for the genuine window).
func TestCHAOS103_LoginMintsNoSessionForAnArbitraryUserInASecondProcess(t *testing.T) {
	chaos103SecondProcess(t)
	resetSetupLockout()
	t.Cleanup(resetSetupLockout)

	rec := httptest.NewRecorder()
	apiAuthLogin(rec, jsonReq(http.MethodPost, "/api/auth/login", map[string]any{
		"user": "alice", "pass": "not-alices-password",
	}))

	if rec.Code == http.StatusOK {
		t.Fatalf("login succeeded with the wrong password: status=%d body=%q", rec.Code, rec.Body.String())
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == uiSessionCookieName && c.Value != "" {
			t.Fatalf("a refused login still minted a session cookie %q", c.Name)
		}
	}
}
