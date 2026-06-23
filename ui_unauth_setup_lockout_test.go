package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestUnauthSetup_DoesNotLockOutAdminUI is a regression test for the first-run
// admin-UI lockout bug.
//
// Completing first-run setup in unauth/open mode (POST /api/setup/complete
// {"unauth":true}) enables unauthMode but creates NO admin user. Before the
// fix, cfg.AuthEnabled() returned true (it counts unauthMode), so:
//
//   - uiAuthMiddleware gated every /api/ route → 401 to anonymous callers,
//   - apiAuthStatus reported loggedIn=false → the SPA showed a login overlay,
//   - apiLogin refused (no user to verify against),
//   - apiSetupComplete returned 403 ("already complete").
//
// With no credential to satisfy any of these, the operator was permanently
// locked out of the very UI they need to manage policy or add an admin. The
// correct behaviour: when no admin credential is configured (no local user,
// no external provider), the admin UI operates open as RoleAdmin —
// independent of unauthMode — exactly as it does on a brand-new install.
func TestUnauthSetup_DoesNotLockOutAdminUI(t *testing.T) {
	// Simulate the post-{"unauth":true}-setup state: no admin user, no
	// provider, unauthMode=true. Snapshot and clear the RBAC roster too —
	// AdminCredentialsConfigured counts uiUsers, and SetAuth("","") does not
	// clear the roster, so a roster populated by an earlier test would
	// otherwise keep the UI gated and mask the lockout this test pins.
	prevUser := cfg.GetUser()
	prevUnauth := cfg.UnauthMode()
	cfg.mu.Lock()
	prevUsers := cfg.uiUsers
	cfg.uiUsers = map[string]*uiAdminUser{}
	cfg.mu.Unlock()
	if err := cfg.SetAuth("", ""); err != nil { // ensure no local user
		t.Fatalf("SetAuth clear: %v", err)
	}
	cfg.SetUnauthMode(true)
	t.Cleanup(func() {
		cfg.SetUnauthMode(prevUnauth)
		_ = cfg.SetAuth(prevUser, "")
		cfg.mu.Lock()
		cfg.uiUsers = prevUsers
		cfg.mu.Unlock()
	})

	// 1. uiAuthMiddleware must let an anonymous request through as RoleAdmin
	//    on a non-public /api/ route, not reject it with 401.
	t.Run("middleware_keeps_ui_open", func(t *testing.T) {
		var reached bool
		var gotRole any
		sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			gotRole = r.Context().Value(uiRoleKey{})
			w.WriteHeader(http.StatusOK)
		})
		handler := uiAuthMiddleware(sentinel)
		req := httptest.NewRequest(http.MethodGet, "/api/config", http.NoBody)
		req.RemoteAddr = "198.51.100.50:0"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if !reached {
			t.Fatalf("admin UI locked out: anonymous /api/config got %d, want the handler reached with RoleAdmin", rec.Code)
		}
		if gotRole != RoleAdmin {
			t.Fatalf("injected role = %v, want %v", gotRole, RoleAdmin)
		}
	})

	// 2. apiAuthStatus must report loggedIn=true as admin, so the SPA renders
	//    the dashboard instead of an unsatisfiable login overlay.
	t.Run("auth_status_reports_open_admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/auth/status", http.NoBody)
		req.RemoteAddr = "198.51.100.51:0"
		rec := httptest.NewRecorder()
		apiAuthStatus(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("apiAuthStatus status = %d, want 200", rec.Code)
		}
		var body struct {
			LoggedIn bool   `json:"loggedIn"`
			Role     string `json:"role"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode auth/status: %v (body=%s)", err, rec.Body.String())
		}
		if !body.LoggedIn {
			t.Fatalf("auth/status loggedIn=false → SPA shows a login overlay no credential can satisfy; want loggedIn=true")
		}
		if body.Role != string(RoleAdmin) {
			t.Fatalf("auth/status role = %q, want %q", body.Role, RoleAdmin)
		}
	})

	// 3. Recovery path: creating an admin via the /api/auth/users handler
	//    (SetUIUser populates the RBAC roster but NOT the legacy c.user field)
	//    must immediately re-gate the UI. Without counting uiUsers, the UI
	//    would stay open as anonymous RoleAdmin and apiAuthLogin would accept
	//    arbitrary credentials until a restart synced c.user from disk.
	t.Run("creating_admin_regates_ui", func(t *testing.T) {
		if err := cfg.SetUIUser("recovery_admin", "Recover1Pass", RoleAdmin); err != nil {
			t.Fatalf("SetUIUser: %v", err)
		}
		t.Cleanup(func() { cfg.mu.Lock(); delete(cfg.uiUsers, "recovery_admin"); cfg.mu.Unlock() })

		if !cfg.AdminCredentialsConfigured() {
			t.Fatalf("after SetUIUser created an admin, AdminCredentialsConfigured()=false → UI stays open to anonymous admin (P1 hole); want true")
		}

		var reached bool
		sentinel := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			w.WriteHeader(http.StatusOK)
		})
		handler := uiAuthMiddleware(sentinel)
		req := httptest.NewRequest(http.MethodGet, "/api/config", http.NoBody)
		req.RemoteAddr = "198.51.100.52:0"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if reached {
			t.Fatalf("anonymous /api/config reached the handler after an admin was created; UI must re-gate (want 401)")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("anonymous /api/config after admin creation got %d, want 401", rec.Code)
		}
	})
}
