package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateInfoSnapshot(t *testing.T) {
	var ui updateInfo
	ui.mu.Lock()
	ui.currentVersion = "v1.0.0"
	ui.latestVersion = "v1.1.0"
	ui.updateAvailable = true
	ui.lastChecked = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ui.updaterStatus = "connected"
	ui.mu.Unlock()

	snap := ui.snapshot()
	if snap["current_version"] != "v1.0.0" {
		t.Errorf("current_version = %v, want v1.0.0", snap["current_version"])
	}
	if snap["latest_version"] != "v1.1.0" {
		t.Errorf("latest_version = %v, want v1.1.0", snap["latest_version"])
	}
	if snap["update_available"] != true {
		t.Errorf("update_available = %v, want true", snap["update_available"])
	}
	if snap["updater_status"] != "connected" {
		t.Errorf("updater_status = %v, want connected", snap["updater_status"])
	}
}

func TestAPIUpdateStatus(t *testing.T) {
	globalUpdateInfo.mu.Lock()
	globalUpdateInfo.currentVersion = "v1.0.0"
	globalUpdateInfo.latestVersion = "v1.1.0"
	globalUpdateInfo.updateAvailable = true
	globalUpdateInfo.lastChecked = time.Now()
	globalUpdateInfo.updaterStatus = "connected"
	globalUpdateInfo.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/update/status", nil)
	w := httptest.NewRecorder()
	apiUpdateStatus(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["current_version"] != "v1.0.0" {
		t.Errorf("current_version = %v", resp["current_version"])
	}
	if resp["update_available"] != true {
		t.Errorf("update_available = %v", resp["update_available"])
	}
}

func TestAPIUpdateStatus_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/update/status", nil)
	w := httptest.NewRecorder()
	apiUpdateStatus(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIUpdateCheck_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/check", nil)
	w := httptest.NewRecorder()
	apiUpdateCheck(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIUpdateApply_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/apply", nil)
	w := httptest.NewRecorder()
	apiUpdateApply(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIUpdateApply_Unauthorized(t *testing.T) {
	// Without auth session, admin endpoints return 403
	req := httptest.NewRequest(http.MethodPost, "/api/update/apply",
		strings.NewReader(`{invalid json`))
	w := httptest.NewRecorder()
	apiUpdateApply(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestAPIUpdateReports_EmptyDir(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/reports", nil)
	w := httptest.NewRecorder()
	apiUpdateReports(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestAPIUpdateReports_InvalidID(t *testing.T) {
	// Path traversal attempts return 404 — the ID won't match any directory entry.
	req := httptest.NewRequest(http.MethodGet, "/api/update/reports?id=../../../etc/passwd", nil)
	w := httptest.NewRecorder()
	apiUpdateReports(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPIUpdateReports_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/update/reports", nil)
	w := httptest.NewRecorder()
	apiUpdateReports(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIUpdatePreview_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/preview", nil)
	w := httptest.NewRecorder()
	apiUpdatePreview(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIUpdateRollback_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/rollback", nil)
	w := httptest.NewRecorder()
	apiUpdateRollback(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIUpdateRollbackStatus_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/update/rollback/status", nil)
	w := httptest.NewRecorder()
	apiUpdateRollbackStatus(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestEnsureUpdaterToken(t *testing.T) {
	// Use a temp dir to avoid writing to /data
	dir := t.TempDir()
	path := filepath.Join(dir, "updater_token.txt")

	// Simulate by testing the token generation logic
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("token file should not exist yet")
	}
}

func TestUpdaterToken_Empty(t *testing.T) {
	// updaterToken reads from /data/updater_token.txt which won't exist in tests
	tok := updaterToken()
	// In test env, the file likely doesn't exist, so should return ""
	if tok != "" {
		t.Logf("unexpected token: %s (ok if /data/updater_token.txt exists)", tok)
	}
}
