package main

// saas_feed_overrides_fence_test.go — 2D-B.0b handler contract: the override
// revision on GET, the fenced ?ifRevision= full-set replacement (structured
// 409 on a stale token — no last-write-wins), and the returned revision. The
// durable/rollback matrix lives in internal/catoverride.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func dispatchOverridesURL(role UIRole, method, target, body string) *httptest.ResponseRecorder {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, role)
	r := httptest.NewRequestWithContext(ctx, method, target, strings.NewReader(body))
	w := httptest.NewRecorder()
	apiSaaSFeedOverrides(w, r)
	return w
}

func overridesRevision(t *testing.T) string {
	t.Helper()
	w := dispatchOverridesURL(RoleViewer, http.MethodGet, "/api/saas-feed/overrides", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET overrides = %d", w.Code)
	}
	var resp struct {
		Revision string `json:"revision"`
		Editable bool   `json:"editable"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Revision == "" {
		t.Fatal("GET must carry the server-owned override revision")
	}
	return resp.Revision
}

func TestOverridesFence_StaleFullSetReplacementIs409(t *testing.T) {
	f3a2ResetFeedDurable(t)
	s := f3a2SwapOverrides(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")

	// A and B load the same revision (the empty-set sentinel).
	revA := overridesRevision(t)
	if revA != "none" {
		t.Fatalf("empty-set revision = %q, want the sentinel", revA)
	}

	// A replaces the set (fenced) — succeeds and returns the new revision.
	w := dispatchOverridesURL(RoleAdmin, http.MethodPut, "/api/saas-feed/overrides?ifRevision="+url.QueryEscape(revA),
		`{"added":{"work.example.com":"business"}}`)
	if w.Code != http.StatusOK {
		t.Fatalf("A's fenced PUT = %d (%s)", w.Code, w.Body.String())
	}
	var aResp struct {
		Revision string `json:"revision"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &aResp)
	if aResp.Revision == "" || aResp.Revision == revA {
		t.Fatalf("fenced PUT must return the NEW revision, got %q", aResp.Revision)
	}

	// B's stale full-set replacement (would clear A's set) → structured 409,
	// A's set survives.
	w = dispatchOverridesURL(RoleAdmin, http.MethodPut, "/api/saas-feed/overrides?ifRevision="+url.QueryEscape(revA), `{}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("B's stale PUT = %d, want 409", w.Code)
	}
	var conflict struct {
		Error           string `json:"error"`
		CurrentRevision string `json:"currentRevision"`
		YourRevision    string `json:"yourRevision"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &conflict); err != nil {
		t.Fatalf("conflict decode: %v (%s)", err, w.Body.String())
	}
	if conflict.CurrentRevision != aResp.Revision || conflict.YourRevision != revA {
		t.Fatalf("structured conflict = %+v", conflict)
	}
	if got := s.Get(); got.Added["work.example.com"] != "business" {
		t.Fatalf("A's set must survive B's stale replacement: %+v", got)
	}

	// B refetches and clears with the CURRENT revision — legitimate clear-all.
	w = dispatchOverridesURL(RoleAdmin, http.MethodPut, "/api/saas-feed/overrides?ifRevision="+url.QueryEscape(aResp.Revision), `{}`)
	if w.Code != http.StatusOK {
		t.Fatalf("current-revision clear = %d (%s)", w.Code, w.Body.String())
	}
	if got := s.Get(); len(got.Added) != 0 {
		t.Fatalf("clear-all did not apply: %+v", got)
	}
	if overridesRevision(t) != "none" {
		t.Fatal("cleared set must serve the sentinel revision")
	}
}

func TestOverridesFence_LegacyPutWithoutRevisionUnchanged(t *testing.T) {
	f3a2ResetFeedDurable(t)
	s := f3a2SwapOverrides(t)
	swapAdminSettingsPath(t, filepath.Join(t.TempDir(), "admin_settings.json"))
	f3a2IsolateConfigWriters(t)
	f3a2SwapRole(t, "standalone")

	// Legacy PUT (no ifRevision) keeps last-write-wins compatibility.
	if w := dispatchOverridesURL(RoleAdmin, http.MethodPut, "/api/saas-feed/overrides", `{"tombstones":["ads.example.com"]}`); w.Code != http.StatusOK {
		t.Fatalf("legacy PUT = %d", w.Code)
	}
	if got := s.Get(); len(got.Tombstones) != 1 {
		t.Fatalf("legacy PUT did not apply: %+v", got)
	}
}
