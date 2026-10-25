package main

// Workstream B pre-review F-B1: a pre-RBAC roster (a bare array, no role field)
// used to load its accounts with role "", VerifyUIUser returned "", login minted
// a role-less cookie, and the session gate (sessionRoleOrReject) refused it on
// every request — a login loop that locked the appliance's own admin out. A
// role-less roster also synced no legacy c.user, so IsConfigured() could read
// false and reopen first-time setup. The loader now migrates "" to RoleAdmin,
// which is what a role-less account always meant.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func writeBareArrayRoster(t *testing.T, records []map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ui_users.json")
	b, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFB1_RolelessRosterAccountLogsInAsAdmin(t *testing.T) {
	withSessionKey(t)
	prev := cfg
	t.Cleanup(func() { cfg = prev })
	cfg = &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}

	hash, err := bcrypt.GenerateFromPassword([]byte("Sup3rSecret!x"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// The only account carries no role: the pre-RBAC single-admin shape.
	path := writeBareArrayRoster(t, []map[string]string{{"username": "old", "pass_hash": hex.EncodeToString(hash)}})
	cfg.SetUIUsersFile(path)
	if err := cfg.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}

	if !cfg.IsConfigured() {
		t.Fatal("a roster whose only account is the pre-RBAC admin must count as configured (setup must stay closed)")
	}
	role, ok := cfg.VerifyUIUser("old", "Sup3rSecret!x")
	if !ok || role != RoleAdmin {
		t.Fatalf("VerifyUIUser = (%q, %v), want (admin, true)", role, ok)
	}

	// The session the login mints must be accepted on the next request.
	rec := httptest.NewRecorder()
	if err := setUISessionCookie(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/api/auth/login", http.NoBody), "old", role); err != nil {
		t.Fatal(err)
	}
	var gotRole UIRole
	h := uiAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRole, _ = r.Context().Value(uiRoleKey{}).(UIRole)
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/stats", http.NoBody)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK || gotRole != RoleAdmin {
		t.Fatalf("after login: status %d role %q, want 200 admin (the login loop is back)", rec2.Code, gotRole)
	}
}

// The migration is persisted by the next ordinary save, not by the loader.
func TestFB1_MigratedRoleIsPersistedByTheNextSave(t *testing.T) {
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	hash, err := bcrypt.GenerateFromPassword([]byte("Sup3rSecret!x"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	path := writeBareArrayRoster(t, []map[string]string{{"username": "old", "pass_hash": hex.EncodeToString(hash)}})
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(after, before) {
		t.Fatal("the loader must not write the roster")
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("save: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env struct {
		Users []struct {
			Username string `json:"username"`
			Role     string `json:"role"`
		} `json:"users"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("saved roster: %v", err)
	}
	if len(env.Users) != 1 || env.Users[0].Role != string(RoleAdmin) {
		t.Fatalf("saved roster must carry role admin, got %+v", env.Users)
	}
}
