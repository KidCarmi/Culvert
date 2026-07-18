package main

// CHAOS-10 — API/config regression tests for the scan-orchestrator on-error
// posture (/api/security-scan/settings + admin_settings.json persistence).
// Mirrors yara_settings_test.go: role context injected directly, global
// posture saved/restored per test.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// resetScanSettings pins the process-global posture back at cleanup.
func resetScanSettings(t *testing.T) {
	t.Helper()
	prev := secscanGetOnScanError()
	t.Cleanup(func() { secscanSetOnScanError(prev) })
}

func TestScanSettings_DefaultSecure(t *testing.T) {
	resetScanSettings(t)
	secscanSetOnScanError(scanFailClosed)

	w := httptest.NewRecorder()
	apiSecScanSettings(w, newViewerRequest("/api/security-scan/settings"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status %d; body=%s", w.Code, w.Body.String())
	}
	var s struct {
		OnError string `json:"on_error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if s.OnError != scanFailClosed {
		t.Errorf("default on_error = %q, want %q", s.OnError, scanFailClosed)
	}
}

func TestScanSettings_PutRequiresAdmin(t *testing.T) {
	resetScanSettings(t)
	validBody := []byte(`{"on_error":"fail_open_with_alert"}`)

	// Viewer PUT must be forbidden and must not change the posture.
	secscanSetOnScanError(scanFailClosed)
	r := httptest.NewRequestWithContext(
		context.WithValue(context.Background(), uiRoleKey{}, RoleViewer),
		http.MethodPut, "/api/security-scan/settings", bytes.NewReader(validBody))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	apiSecScanSettings(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer PUT: want 403, got %d", w.Code)
	}
	if secscanGetOnScanError() != scanFailClosed {
		t.Error("viewer PUT must not change the posture")
	}

	// Admin PUT must succeed and apply.
	w = httptest.NewRecorder()
	apiSecScanSettings(w, newAdminRequest(http.MethodPut, "/api/security-scan/settings", validBody))
	if w.Code != http.StatusOK {
		t.Fatalf("admin PUT: status %d; body=%s", w.Code, w.Body.String())
	}
	if secscanGetOnScanError() != scanFailOpenWithAlert {
		t.Errorf("posture after admin PUT = %q, want %q", secscanGetOnScanError(), scanFailOpenWithAlert)
	}
}

func TestScanSettings_RejectsUnknownPosture(t *testing.T) {
	resetScanSettings(t)
	secscanSetOnScanError(scanFailClosed)

	for _, body := range []string{`{"on_error":"allow"}`, `{"on_error":""}`, `{}`} {
		w := httptest.NewRecorder()
		apiSecScanSettings(w, newAdminRequest(http.MethodPut, "/api/security-scan/settings", []byte(body)))
		if w.Code != http.StatusBadRequest {
			t.Errorf("body %s: want 400, got %d", body, w.Code)
		}
	}
	if secscanGetOnScanError() != scanFailClosed {
		t.Error("rejected PUTs must not change the posture")
	}
}

// TestScanSettings_PersistsAndReloads mirrors TestYARASettings_PersistsAndReloads:
// a settings file carrying scan_on_error restores it on load; a pre-feature file
// (field absent) leaves the fail-closed default untouched; an invalid persisted
// value (hand-edited file) is refused, keeping the default.
func TestScanSettings_PersistsAndReloads(t *testing.T) {
	resetScanSettings(t)

	adminSettingsMu.Lock()
	origPath := adminSettingsPath
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsMu.Lock()
		adminSettingsPath = origPath
		adminSettingsMu.Unlock()
	})

	writeSettings := func(t *testing.T, cfg AdminSettings) string {
		t.Helper()
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		tmp := filepath.Join(t.TempDir(), "admin_settings.json")
		if err := os.WriteFile(tmp, data, 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		return tmp
	}

	// Saved fail_open posture survives a restart.
	secscanSetOnScanError(scanFailClosed)
	LoadAdminSettings(writeSettings(t, AdminSettings{ScanOnError: scanFailOpenWithAlert}))
	if secscanGetOnScanError() != scanFailOpenWithAlert {
		t.Errorf("after reload: posture = %q, want %q", secscanGetOnScanError(), scanFailOpenWithAlert)
	}

	// Pre-feature file (field absent) keeps the engine default.
	secscanSetOnScanError(scanFailClosed)
	LoadAdminSettings(writeSettings(t, AdminSettings{}))
	if secscanGetOnScanError() != scanFailClosed {
		t.Errorf("pre-feature file must keep default; got %q", secscanGetOnScanError())
	}

	// Invalid persisted value (hand-edited file) is refused — fail-closed
	// default kept rather than landing on an unintended posture.
	secscanSetOnScanError(scanFailClosed)
	LoadAdminSettings(writeSettings(t, AdminSettings{ScanOnError: "allow_everything"}))
	if secscanGetOnScanError() != scanFailClosed {
		t.Errorf("invalid persisted value must be refused; got %q", secscanGetOnScanError())
	}
}
