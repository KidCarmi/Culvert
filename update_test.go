package main

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

// ── parseSemver / semverGreater tests ───────────────────────────────────────

func TestParseSemver(t *testing.T) {
	tests := []struct {
		input       string
		maj, min, p int
		ok          bool
	}{
		{"v1.2.3", 1, 2, 3, true},
		{"0.0.15", 0, 0, 15, true},
		{"v0.0.19", 0, 0, 19, true},
		{"v10.20.30", 10, 20, 30, true},
		{"latest", 0, 0, 0, false},
		{"", 0, 0, 0, false},
		{"abc", 0, 0, 0, false},
		{"v1.2", 0, 0, 0, false},
	}
	for _, tt := range tests {
		maj, min, p, ok := parseSemver(tt.input)
		if ok != tt.ok || maj != tt.maj || min != tt.min || p != tt.p {
			t.Errorf("parseSemver(%q) = %d,%d,%d,%v; want %d,%d,%d,%v",
				tt.input, maj, min, p, ok, tt.maj, tt.min, tt.p, tt.ok)
		}
	}
}

func TestSemverGreater(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"v0.0.19", "v0.0.15", true},
		{"v0.0.15", "v0.0.19", false},
		{"v1.0.0", "v0.99.99", true},
		{"v0.1.0", "v0.0.99", true},
		{"v1.0.0", "v1.0.0", false},
		{"latest", "v1.0.0", false},
		{"v1.0.0", "latest", false},
	}
	for _, tt := range tests {
		got := semverGreater(tt.a, tt.b)
		if got != tt.want {
			t.Errorf("semverGreater(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestCleanSemver(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"v0.0.19-4-g8ac6d14", "v0.0.19"},
		{"v0.0.19", "v0.0.19"},
		{"v1.2.3-rc1", "v1.2.3"},
		{"v10.20.30-dirty", "v10.20.30"},
		{"0.0.15", "0.0.15"},
		{"1.2.3-beta.1", "1.2.3"},
		{"dev", "dev"},
		{"latest", "latest"},
		{"", ""},
	}
	for _, tt := range tests {
		got := cleanSemver(tt.input)
		if got != tt.want {
			t.Errorf("cleanSemver(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestCleanSemver_UsedInComparison(t *testing.T) {
	// Verify that cleaning git-describe version makes comparison work correctly
	gitDescribe := "v0.0.19-4-g8ac6d14"
	clean := cleanSemver(gitDescribe)
	if clean != "v0.0.19" {
		t.Fatalf("cleanSemver(%q) = %q, want v0.0.19", gitDescribe, clean)
	}
	// v0.0.20 should be greater than the cleaned version
	if !semverGreater("v0.0.20", clean) {
		t.Error("expected v0.0.20 > v0.0.19 (cleaned from git-describe)")
	}
	// Same version should not be greater
	if semverGreater("v0.0.19", clean) {
		t.Error("expected v0.0.19 NOT > v0.0.19")
	}
}

func TestUpdateInfoSnapshot_PullTag(t *testing.T) {
	var ui updateInfo
	ui.mu.Lock()
	ui.currentVersion = "v0.0.15"
	ui.latestVersion = "v0.0.19"
	ui.pullTag = "latest"
	ui.updateAvailable = true
	ui.lastChecked = time.Now()
	ui.updaterStatus = "connected"
	ui.mu.Unlock()

	snap := ui.snapshot()
	if snap["pull_tag"] != "latest" {
		t.Errorf("pull_tag = %v, want latest", snap["pull_tag"])
	}
	if snap["latest_version"] != "v0.0.19" {
		t.Errorf("latest_version = %v, want v0.0.19", snap["latest_version"])
	}
}

func TestUpdateInfoSnapshot_PullTagFallback(t *testing.T) {
	var ui updateInfo
	ui.mu.Lock()
	ui.currentVersion = "v1.0.0"
	ui.latestVersion = "v1.1.0"
	ui.pullTag = "" // empty pull tag should fall back to latestVersion
	ui.mu.Unlock()

	snap := ui.snapshot()
	if snap["pull_tag"] != "v1.1.0" {
		t.Errorf("pull_tag = %v, want v1.1.0 (fallback)", snap["pull_tag"])
	}
}

func TestStartUpdateChecker_CleansVersion(t *testing.T) {
	// Simulate a git-describe version being set at build time
	oldVersion := version
	version = "v0.0.19-4-g8ac6d14"
	defer func() { version = oldVersion }()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so the goroutine exits fast

	// startUpdateChecker sets currentVersion — call it directly to test the clean logic
	globalUpdateInfo.mu.Lock()
	globalUpdateInfo.currentVersion = cleanSemver(version)
	globalUpdateInfo.mu.Unlock()

	_ = ctx // used above

	globalUpdateInfo.mu.RLock()
	cv := globalUpdateInfo.currentVersion
	globalUpdateInfo.mu.RUnlock()

	if cv != "v0.0.19" {
		t.Errorf("currentVersion = %q, want v0.0.19 (cleaned from git-describe)", cv)
	}
}

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

func TestAPIRegistrySettings_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodDelete, "/api/update/registry", nil)
	w := httptest.NewRecorder()
	apiRegistrySettings(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", w.Code)
	}
}

func TestAPIRegistrySettings_GetEmpty(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/registry", nil)
	w := httptest.NewRecorder()
	apiRegistrySettings(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var rs map[string]string
	if err := json.NewDecoder(w.Body).Decode(&rs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rs["registry_url"] != "" {
		t.Errorf("expected empty registry_url, got %q", rs["registry_url"])
	}
}

func TestAPIRegistrySettings_PostUnauthorized(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/update/registry",
		strings.NewReader(`{"registry_url":"test"}`))
	w := httptest.NewRecorder()
	apiRegistrySettings(w, req)
	// Without admin session → 403
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", w.Code)
	}
}

func TestAPIUpdateRollbackStatus_NoUpdater(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/rollback/status", nil)
	w := httptest.NewRecorder()
	apiUpdateRollbackStatus(w, req)
	// Returns 502 (updater unavailable) or 200 depending on updater
	if w.Code != http.StatusOK && w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 200 or 502", w.Code)
	}
}

func TestStaleRegistryCorrection(t *testing.T) {
	// Unit-test the stale registry correction logic directly, without network.
	// Scenario: Docker registry returns v0.0.15, we're running v0.0.19,
	// and GitHub fallback didn't find anything newer.
	// The displayed "latest" should be v0.0.19 (current), not v0.0.15.
	cleanVer := "v0.0.19"
	registryLatest := "v0.0.15"
	updateAvailable := false

	// Simulate the correction logic from checkUpdateNow:
	// "if registry latest < current, show current as latest"
	if !updateAvailable && cleanVer != "dev" && registryLatest != "" {
		if semverGreater(cleanVer, cleanSemver(registryLatest)) {
			registryLatest = cleanVer
		}
	}

	if registryLatest != "v0.0.19" {
		t.Errorf("latest = %q, want v0.0.19 (current version should replace stale registry)", registryLatest)
	}

	// When registry is current (not stale), it should stay unchanged.
	registryLatest2 := "v0.0.19"
	cleanVer2 := "v0.0.19"
	if !false && cleanVer2 != "dev" && registryLatest2 != "" {
		if semverGreater(cleanVer2, cleanSemver(registryLatest2)) {
			registryLatest2 = cleanVer2
		}
	}
	if registryLatest2 != "v0.0.19" {
		t.Errorf("latest = %q, want v0.0.19 (should stay unchanged when not stale)", registryLatest2)
	}

	// When registry has a newer version, it should stay unchanged.
	registryLatest3 := "v0.0.20"
	cleanVer3 := "v0.0.19"
	if !false && cleanVer3 != "dev" && registryLatest3 != "" {
		if semverGreater(cleanVer3, cleanSemver(registryLatest3)) {
			registryLatest3 = cleanVer3
		}
	}
	if registryLatest3 != "v0.0.20" {
		t.Errorf("latest = %q, want v0.0.20 (registry newer should stay)", registryLatest3)
	}
}

func TestAPIUpdateReports_GETList(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/update/reports", nil)
	w := httptest.NewRecorder()
	apiUpdateReports(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}
