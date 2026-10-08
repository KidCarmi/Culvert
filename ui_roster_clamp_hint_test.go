package main

import (
	"os"
	"strings"
	"testing"
)

// The server reports uiRosterRoleClamped on /api/stats (SEC-RBAC-ROLE-1); the
// Admin Users panel must surface it, or an admin whose account was lowered to
// viewer at load sees only a lost privilege with no explanation.
func TestAdminUsersPanel_SurfacesRosterRoleClamp(t *testing.T) {
	b, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(b)
	for _, want := range []string{
		`id="roster-role-clamp-hint"`,
		`id="roster-role-clamp-text"`,
		`s.uiRosterRoleClamped`,
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
