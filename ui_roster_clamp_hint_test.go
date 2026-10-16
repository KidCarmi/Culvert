package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The server reports uiRosterRoleClamped on /api/stats (SEC-RBAC-ROLE-1); the
// Admin Users panel must surface it, or an admin whose account was lowered to
// viewer at load sees only a lost privilege with no explanation.
func TestAdminUsersPanel_SurfacesRosterRoleClamp(t *testing.T) {
	b, err := os.ReadFile(staticIndexHTMLPath())
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, want := range []string{
		`id="roster-role-clamp-hint"`,
		`id="roster-role-clamp-text"`,
		`s.uiRosterRoleClamped`,
		// A clamped sole administrator cannot edit roles from this panel;
		// the hint must name the host-shell break-glass (main.go
		// runResetPasswordCommand sets RoleAdmin).
		`--reset-password username:newpassword`,
		// The per-account marker tells the admin WHICH viewer rows to repair.
		`u.roleClamped`,
		`held at viewer`,
	} {
		if !strings.Contains(html, want) {
			t.Errorf("static/index.html missing %q", want)
		}
	}
	// The hint must live inside the users view, next to the roster it explains.
	v := strings.Index(html, `id="view-users"`)
	h := strings.Index(html, `id="roster-role-clamp-hint"`)
	if v < 0 || h < v || h-v > 2000 {
		t.Errorf("clamp hint is not inside the Admin Users view (view=%d hint=%d)", v, h)
	}
}

// TestListUIUsers_MarksClampedAccounts pins the per-account clamp flag the
// Admin Users list renders: only the clamped record is marked, and the raw
// persisted role is never exposed.
func TestListUIUsers_MarksClampedAccounts(t *testing.T) {
	path, _ := seedRosterWithRole(t, "auditor")
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := c.SetUIUser("plainviewer", "Sup3rSecret!y", RoleViewer); err != nil {
		t.Fatalf("add viewer: %v", err)
	}
	got := map[string]bool{}
	for _, u := range c.ListUIUsers() {
		got[u.Username] = u.RoleClamped
	}
	if !got["bob"] || got["plainviewer"] {
		t.Fatalf("roleClamped = %v, want only the clamped account (bob) marked", got)
	}
	b, err := json.Marshal(c.ListUIUsers())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "auditor") {
		t.Fatalf("user list must not expose the raw persisted role: %s", b)
	}
}
