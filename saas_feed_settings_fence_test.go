package main

// saas_feed_settings_fence_test.go — 2D-B.0c: the SaaS settings revision
// fence (two admins can never silently overwrite each other) and the
// persist-before-apply durability order (a persist failure means the target
// was NEVER applied — no rollback branch, runtime and disk stay agreed).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func dispatchSettingsURL(role UIRole, method, target, body string) *httptest.ResponseRecorder {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, role)
	r := httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	w := httptest.NewRecorder()
	apiSaaSFeedSettings(w, r)
	return w
}

func settingsRevisionFromGET(t *testing.T) string {
	t.Helper()
	w := dispatchSettingsURL(RoleViewer, http.MethodGet, "/api/saas-feed/settings", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET settings = %d", w.Code)
	}
	var resp struct {
		Revision string `json:"revision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Revision == "" {
		t.Fatal("GET must carry the server-owned settings revision")
	}
	return resp.Revision
}

func TestSettingsFence_TwoAdminsCannotSilentlyOverwrite(t *testing.T) {
	f3a2ResetFeedDurable(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")

	// A and B load the same revision.
	revShared := settingsRevisionFromGET(t)

	// A changes config (fenced) — succeeds.
	w := dispatchSettingsURL(RoleAdmin, http.MethodPut, "/api/saas-feed/settings?ifRevision="+url.QueryEscape(revShared),
		`{"managed":true,"enabled":true,"refresh":"12h"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("A's fenced PUT = %d (%s)", w.Code, w.Body.String())
	}
	var aView struct {
		Revision       string `json:"revision"`
		RefreshSeconds int64  `json:"refresh_seconds"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &aView)
	if aView.Revision == "" || aView.Revision == revShared || aView.RefreshSeconds != 12*3600 {
		t.Fatalf("A's view = %+v", aView)
	}

	// B's stale PUT (would disable the feed) → structured 409, nothing applied.
	w = dispatchSettingsURL(RoleAdmin, http.MethodPut, "/api/saas-feed/settings?ifRevision="+url.QueryEscape(revShared),
		`{"managed":true,"enabled":false}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("B's stale PUT = %d, want 409 (%s)", w.Code, w.Body.String())
	}
	var conflict struct {
		Error           string `json:"error"`
		CurrentRevision string `json:"currentRevision"`
		YourRevision    string `json:"yourRevision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("conflict decode: %v (%s)", err, w.Body.String())
	}
	if conflict.CurrentRevision != aView.Revision || conflict.YourRevision != revShared {
		t.Fatalf("structured conflict = %+v", conflict)
	}
	d := getSaaSFeedDurable()
	if !d.Enabled || d.RefreshSeconds != 12*3600 {
		t.Fatalf("B's stale target must not apply: %+v", d)
	}

	// B refetches and retries with the current revision — succeeds.
	w = dispatchSettingsURL(RoleAdmin, http.MethodPut, "/api/saas-feed/settings?ifRevision="+url.QueryEscape(aView.Revision),
		`{"managed":true,"enabled":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("B's refreshed PUT = %d (%s)", w.Code, w.Body.String())
	}
	if getSaaSFeedDurable().Enabled {
		t.Fatal("B's refreshed change did not apply")
	}
}

func TestSettingsFence_PersistFailureNeverAppliesTarget(t *testing.T) {
	f3a2ResetFeedDurable(t)
	// Parent path is a regular FILE → AtomicWrite fails (real filesystem fault).
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	swapAdminSettingsPath(t, filepath.Join(blocker, "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")

	before := getSaaSFeedDurable()
	rev := settingsRevisionFromGET(t)
	w := dispatchSettingsURL(RoleAdmin, http.MethodPut, "/api/saas-feed/settings?ifRevision="+url.QueryEscape(rev),
		`{"managed":true,"enabled":true,"refresh":"6h"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("persist-failure PUT = %d, want 500 (%s)", w.Code, w.Body.String())
	}
	after := getSaaSFeedDurable()
	if after != before {
		t.Fatalf("persist failure must never apply the target: before=%+v after=%+v", before, after)
	}
	// The revision is unchanged — a follow-up fenced PUT with the ORIGINAL
	// token still passes the fence (no phantom advance from the failed write).
	if settingsRevisionFromGET(t) != rev {
		t.Fatal("failed persist must not advance the settings revision")
	}
}

func TestSettingsFence_LegacyPutWithoutRevisionUnchanged(t *testing.T) {
	f3a2ResetFeedDurable(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")

	if w := dispatchSettingsURL(RoleAdmin, http.MethodPut, "/api/saas-feed/settings", `{"managed":true,"enabled":true}`); w.Code != http.StatusOK {
		t.Fatalf("legacy PUT = %d (%s)", w.Code, w.Body.String())
	}
	if d := getSaaSFeedDurable(); !d.Managed || !d.Enabled {
		t.Fatalf("legacy PUT did not apply: %+v", d)
	}
}
