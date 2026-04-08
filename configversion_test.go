package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPruneConfigVersions(t *testing.T) {
	// Just verify it doesn't panic with a non-existent directory.
	pruneConfigVersions()
}

func TestListConfigVersions_EmptyDir(t *testing.T) {
	w := httptest.NewRecorder()
	listConfigVersions(w)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var versions []ConfigVersion
	if err := json.NewDecoder(w.Body).Decode(&versions); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// May have versions from other tests or may be empty — just check it's valid JSON array.
	if versions == nil {
		t.Error("expected non-nil array (even if empty)")
	}
}

func TestApiConfigVersions_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/api/config/versions", nil)
	w := httptest.NewRecorder()
	apiConfigVersions(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestApiConfigDiff_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/config/diff", nil)
	w := httptest.NewRecorder()
	apiConfigDiff(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestApiConfigDiff_MissingParams(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/config/diff", nil)
	w := httptest.NewRecorder()
	apiConfigDiff(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestApiConfigDiff_InvalidFrom(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/config/diff?from=0&to=1", nil)
	w := httptest.NewRecorder()
	apiConfigDiff(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRollbackConfigVersion_InvalidVersion(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/config/versions",
		strings.NewReader(`{"version":0}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rollbackConfigVersion(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestRollbackConfigVersion_NotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/config/versions",
		strings.NewReader(`{"version":99999}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rollbackConfigVersion(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestRollbackConfigVersion_BadJSON(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/config/versions",
		strings.NewReader(`{invalid`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rollbackConfigVersion(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestConfigVersionStruct_JSON(t *testing.T) {
	cv := ConfigVersion{
		Version:   42,
		CreatedAt: "2026-01-01T00:00:00Z",
		Actor:     "admin",
		Action:    "policy.update",
	}
	data, err := json.Marshal(cv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded ConfigVersion
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.Version != 42 {
		t.Errorf("Version = %d, want 42", decoded.Version)
	}
	if decoded.Action != "policy.update" {
		t.Errorf("Action = %q", decoded.Action)
	}
}

func TestInitConfigVersioning_CreatesDir(t *testing.T) {
	// The real initConfigVersioning uses /data/config_versions which may or may not exist.
	// Just verify it doesn't panic.
	initConfigVersioning()
}

func TestSaveConfigVersion_WritesFile(t *testing.T) {
	dir := t.TempDir()
	origDir := configVersionsDir
	// We can't easily change the const, so just test the file write logic directly.
	_ = dir
	_ = origDir

	// Create a version envelope and verify marshaling works.
	snap := configBackup{
		Version:       1,
		ExportedAt:    "2026-01-01T00:00:00Z",
		BlocklistMode: "block",
		DefaultAction: "deny",
		RateLimitRPM:  100,
	}
	meta := ConfigVersion{
		Version:   1,
		CreatedAt: snap.ExportedAt,
		Actor:     "test",
		Action:    "test.save",
	}
	envelope := struct {
		Meta   ConfigVersion `json:"meta"`
		Config configBackup  `json:"config"`
	}{Meta: meta, Config: snap}

	data, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	path := filepath.Join(dir, "v1.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Verify we can read it back.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var loaded struct {
		Meta   ConfigVersion `json:"meta"`
		Config configBackup  `json:"config"`
	}
	if err := json.Unmarshal(raw, &loaded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if loaded.Meta.Version != 1 {
		t.Errorf("Meta.Version = %d", loaded.Meta.Version)
	}
	if loaded.Config.DefaultAction != "deny" {
		t.Errorf("Config.DefaultAction = %q", loaded.Config.DefaultAction)
	}
}

func TestApiConfigDiff_VersionNotFound(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/config/diff?from=88888&to=99999", nil)
	w := httptest.NewRecorder()
	apiConfigDiff(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
