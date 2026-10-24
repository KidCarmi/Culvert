package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRosterRoleClamp_DeprecatedAliasesKept pins the T-64 deprecation window:
// the pre-rename names shipped in tagged builds (v1.0.252 onward), so the
// canonical admin-roster names and the old ui-roster names must both carry the
// same value until the aliases are removed in an announced change.
func TestRosterRoleClamp_DeprecatedAliasesKept(t *testing.T) {
	path, _ := seedRosterWithRole(t, "auditor")
	c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("load: %v", err)
	}
	origCfg := cfg
	cfg = c
	t.Cleanup(func() { cfg = origCfg })

	health := map[string]any{}
	addRequestLogHealth(health)
	if health["adminRosterRoleClamped"] != 1 || health["uiRosterRoleClamped"] != 1 {
		t.Fatalf("/healthz must carry both clamp keys = 1, got admin=%v ui=%v",
			health["adminRosterRoleClamped"], health["uiRosterRoleClamped"])
	}

	w := httptest.NewRecorder()
	r := adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/stats", http.NoBody))
	apiStats(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("/api/stats status = %d", w.Code)
	}
	var stats map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode /api/stats: %v", err)
	}
	if stats["adminRosterRoleClamped"] != float64(1) || stats["uiRosterRoleClamped"] != float64(1) {
		t.Fatalf("/api/stats must carry both clamp keys = 1, got admin=%v ui=%v",
			stats["adminRosterRoleClamped"], stats["uiRosterRoleClamped"])
	}

	var b strings.Builder
	liveFeedWritePrometheus(&b)
	out := b.String()
	for _, name := range []string{"culvert_admin_roster_role_clamped_total", "culvert_ui_roster_role_clamped_total"} {
		if !strings.Contains(out, "\n# TYPE "+name+" counter\n"+name+" ") {
			t.Fatalf("metrics must expose %s", name)
		}
	}
}
