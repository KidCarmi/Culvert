package main

// auth_password_change_no_versioning_test.go — regression coverage
// for the Category D-sec triage finding in
// roadmap/CONFIG-VERSIONING-TRIAGE.md.
//
// Background
// ==========
// apiAuthChangePassword (ui_auth.go:241) handles self-service
// password change. Before this fix it called:
//
//   auditEvent(r, "auth.password_change", ...)
//   saveConfigVersion(sessionAdmin(r), "auth.password_change")
//
// The saveConfigVersion call was misleading and security-dangerous:
//
//   1. captureConfigBackup (configversion.go:59-79) does NOT capture
//      password hashes — they live in ui_users.json, which is not in
//      the rollback surface. So the snapshot was a no-op for
//      password state today.
//   2. If a future PR extended the rollback surface to include
//      ui_users.json, rolling back to a prior version would restore
//      the OLD password hash — a security regression by definition,
//      since the operator typically changes the password BECAUSE the
//      prior one was compromised.
//
// This PR removes the saveConfigVersion call. The audit trail
// (auditEvent) is preserved — that is the appropriate observability
// tier for password changes.
//
// This test pins the new contract: a successful password change must
// NOT create a config-version envelope with Action="auth.password_change".

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// snapshotConfigVersionsDir redirects the package-global
// configVersionsDir to a fresh t.TempDir() and resets
// configVersionSeq to 0. Restores both on t.Cleanup. Returns the
// tmp dir so the caller can inspect the snapshot files. Same
// whitebox idiom as snapshotClusterUpdateState / snapshotLoginLimiter
// from earlier PRs.
func snapshotConfigVersionsDir(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	origDir := configVersionsDir
	configVersionsDir = tmp
	t.Cleanup(func() { configVersionsDir = origDir })

	configVersionMu.Lock()
	origSeq := configVersionSeq
	configVersionSeq = 0
	configVersionMu.Unlock()
	t.Cleanup(func() {
		configVersionMu.Lock()
		configVersionSeq = origSeq
		configVersionMu.Unlock()
	})
	return tmp
}

// snapshotCfgUIUsers captures and restores cfg.uiUsers + cfg.user +
// cfg.passHash so tests that seed or mutate UI admin users do not
// pollute siblings under -shuffle=on / -count=N. Same idiom as
// PR #241 cfg.uiUsers snapshot.
func snapshotCfgUIUsers(t *testing.T) {
	t.Helper()
	cfg.mu.Lock()
	prevUsers := make(map[string]*uiAdminUser, len(cfg.uiUsers))
	for k, v := range cfg.uiUsers {
		prevUsers[k] = v
	}
	prevUser := cfg.user
	prevPassHash := cfg.passHash
	cfg.mu.Unlock()
	t.Cleanup(func() {
		cfg.mu.Lock()
		cfg.uiUsers = prevUsers
		cfg.user = prevUser
		cfg.passHash = prevPassHash
		cfg.mu.Unlock()
	})
}

// TestAPIAuthChangePassword_DoesNotCreateConfigVersion is the
// regression guard for the Category D-sec fix. With the
// saveConfigVersion call re-added to apiAuthChangePassword, this
// test fails because an envelope with Meta.Action="auth.password_change"
// appears in the config-versions directory.
func TestAPIAuthChangePassword_DoesNotCreateConfigVersion(t *testing.T) {
	tmp := snapshotConfigVersionsDir(t)
	snapshotCfgUIUsers(t)

	const (
		testUser    = "pwchange_no_version_test"
		testOldPass = "OldPass1234"
		testNewPass = "NewPass5678"
	)

	if err := cfg.SetUIUser(testUser, testOldPass, RoleAdmin); err != nil {
		t.Fatalf("seed test user: %v", err)
	}

	// Mint an admin UI session cookie for the test user —
	// apiAuthChangePassword reads sessionAdmin(r) (which reads the
	// ps_ui_session cookie) and rejects username=="unknown".
	cookieValue, err := encodeSession(&Session{
		Sub:      testUser,
		Provider: "local",
		Role:     "admin",
		Exp:      time.Now().Add(time.Hour).Unix(),
		Jti:      newSessionJti(),
	})
	if err != nil {
		t.Fatalf("encodeSession: %v", err)
	}

	// Inject RoleAdmin into context so requireRole(RoleViewer) passes
	// (the production middleware chain does this; we bypass middleware
	// by calling the handler directly).
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	body := strings.NewReader(`{"current_password":"` + testOldPass + `","new_password":"` + testNewPass + `"}`)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/auth/change-password", body)
	r.Header.Set("Content-Type", "application/json")
	// Cookie attributes are inert here — request never crosses the
	// network; the handler just calls r.Cookie(name) which returns the
	// value regardless. Setting Secure/HttpOnly/SameSite satisfies
	// gosec G124 without a //nolint suppression.
	r.AddCookie(&http.Cookie{
		Name:     uiSessionCookieName,
		Value:    cookieValue,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	w := httptest.NewRecorder()
	apiAuthChangePassword(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("apiAuthChangePassword status = %d; want %d (body: %s)",
			w.Code, http.StatusOK, w.Body.String())
	}

	// Verify the password actually changed (proves the handler
	// successfully ran the mutation path through to the audit+jsonOK
	// branch — i.e. the saveConfigVersion call would have run if it
	// were still present).
	if _, ok := cfg.VerifyUIUser(testUser, testNewPass); !ok {
		t.Fatalf("VerifyUIUser with NEW password failed; the handler did not actually change the password")
	}

	assertNoPasswordChangeVersion(t, tmp)
}

// assertNoPasswordChangeVersion reads every envelope in dir and
// fails the test if any has Meta.Action="auth.password_change". This
// is the key contract pinned by the test above; extracted to keep
// the test body small.
func assertNoPasswordChangeVersion(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read tmp dir: %v", err)
	}
	type envelope struct {
		Meta struct {
			Version int    `json:"version"`
			Actor   string `json:"actor"`
			Action  string `json:"action"`
		} `json:"meta"`
	}
	for _, e := range entries {
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("unmarshal %s: %v", e.Name(), err)
		}
		if env.Meta.Action == "auth.password_change" {
			t.Errorf("config-version envelope %s has Meta.Action=%q — the saveConfigVersion call was re-added; password change must NOT create a config version (security-sensitive, Category D-sec)",
				e.Name(), env.Meta.Action)
		}
	}
}
