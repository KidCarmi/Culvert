package main

// API/config regression tests for the YARA engine settings feature (PR-02).
//
// Auth is bypassed by injecting role context keys directly, using the same
// pattern as cdr_ui_test.go and diagnostics_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// resetYARASettings saves all current YARA engine runtime settings and
// restores them at t.Cleanup, keeping tests hermetic against global state.
func resetYARASettings(t *testing.T) {
	t.Helper()
	prevEnabled := yaraGetEnabled()
	prevTimeout := yaraGetTimeoutSecs()
	prevMax := yaraGetMaxInflight()
	prevOnTimeout := yaraGetOnTimeout()
	prevOnSat := yaraGetOnSaturation()
	prevAlert := yaraGetAlertDegraded()
	t.Cleanup(func() {
		yaraSetEnabled(prevEnabled)
		yaraSetTimeoutSecs(prevTimeout)
		yaraSetMaxInflight(prevMax)
		yaraSetOnTimeout(prevOnTimeout)
		yaraSetOnSaturation(prevOnSat)
		yaraSetAlertDegraded(prevAlert)
	})
}

// loadTestYARARule loads a single in-memory rule into globalYARA from a temp
// directory and arranges cleanup that unloads it by pointing at a fresh
// empty dir (no .yar files → rules=[]).
func loadTestYARARule(t *testing.T, ruleSrc string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "test.yar"), []byte(ruleSrc), 0o600); err != nil {
		t.Fatalf("loadTestYARARule: write: %v", err)
	}
	if err := globalYARA.LoadDir(dir); err != nil {
		t.Fatalf("loadTestYARARule: LoadDir: %v", err)
	}
	t.Cleanup(func() {
		empty := t.TempDir()
		_ = globalYARA.LoadDir(empty) // unload: no .yar files → rules=[]
	})
}

// yaraSettingsResponse decodes the body of an apiSecYARASettings response.
type yaraSettingsResponse struct {
	Enabled       bool    `json:"enabled"`
	TimeoutSecs   float64 `json:"timeout_secs"`
	MaxInflight   float64 `json:"max_inflight"`
	OnTimeout     string  `json:"on_timeout"`
	OnSaturation  string  `json:"on_saturation"`
	AlertDegraded bool    `json:"alert_degraded"`
}

func decodeYARASettings(t *testing.T, w *httptest.ResponseRecorder) yaraSettingsResponse {
	t.Helper()
	var s yaraSettingsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatalf("decodeYARASettings: %v; body=%s", err, w.Body.String())
	}
	return s
}

// ── Tests ──────────────────────────────────────────────────────────────────

// TestYARASettings_DefaultsSecure verifies that the GET endpoint returns
// secure fail-closed values when no admin override has been applied.
func TestYARASettings_DefaultsSecure(t *testing.T) {
	resetYARASettings(t)
	// Force init() defaults explicitly so the test is order-independent.
	yaraSetEnabled(true)
	yaraSetTimeoutSecs(5)
	yaraSetMaxInflight(50)
	yaraSetOnTimeout(yaraFailClosed)
	yaraSetOnSaturation(yaraFailClosed)
	yaraSetAlertDegraded(true)

	w := httptest.NewRecorder()
	apiSecYARASettings(w, newViewerRequest("/api/security-scan/yara/settings"))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status %d; body=%s", w.Code, w.Body.String())
	}
	s := decodeYARASettings(t, w)

	if !s.Enabled {
		t.Error("default enabled must be true")
	}
	if s.OnTimeout != yaraFailClosed {
		t.Errorf("default on_timeout = %q, want %q", s.OnTimeout, yaraFailClosed)
	}
	if s.OnSaturation != yaraFailClosed {
		t.Errorf("default on_saturation = %q, want %q", s.OnSaturation, yaraFailClosed)
	}
	if !s.AlertDegraded {
		t.Error("default alert_degraded must be true")
	}
	if s.TimeoutSecs < 1 {
		t.Errorf("default timeout_secs = %v, want >= 1", s.TimeoutSecs)
	}
	if s.MaxInflight < 1 {
		t.Errorf("default max_inflight = %v, want >= 1", s.MaxInflight)
	}
}

// TestYARASettings_PutRequiresAdmin verifies that GET is accessible to
// viewers but PUT is restricted to admins (returns 403 for viewer role).
func TestYARASettings_PutRequiresAdmin(t *testing.T) {
	resetYARASettings(t)
	validBody := []byte(`{"enabled":true,"timeout_secs":10,"max_inflight":20,` +
		`"on_timeout":"fail_closed","on_saturation":"fail_closed","alert_degraded":true}`)

	// Viewer GET must succeed.
	w := httptest.NewRecorder()
	apiSecYARASettings(w, newViewerRequest("/api/security-scan/yara/settings"))
	if w.Code != http.StatusOK {
		t.Fatalf("viewer GET: status %d", w.Code)
	}

	// Viewer PUT must be forbidden.
	r := httptest.NewRequestWithContext(
		context.WithValue(context.Background(), uiRoleKey{}, RoleViewer),
		http.MethodPut, "/api/security-scan/yara/settings", bytes.NewReader(validBody))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	apiSecYARASettings(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer PUT: want 403, got %d", w.Code)
	}

	// Admin PUT must succeed.
	w = httptest.NewRecorder()
	apiSecYARASettings(w, newAdminRequest(http.MethodPut, "/api/security-scan/yara/settings", validBody))
	if w.Code != http.StatusOK {
		t.Fatalf("admin PUT: status %d; body=%s", w.Code, w.Body.String())
	}
}

// TestYARASettings_RejectsInvalidRanges verifies that the PUT handler
// returns 400 for out-of-range or unknown policy values.
func TestYARASettings_RejectsInvalidRanges(t *testing.T) {
	resetYARASettings(t)

	cases := []struct {
		name string
		body string
	}{
		{
			"timeout_zero",
			`{"enabled":true,"timeout_secs":0,"max_inflight":50,"on_timeout":"fail_closed","on_saturation":"fail_closed","alert_degraded":true}`,
		},
		{
			"timeout_over_limit",
			`{"enabled":true,"timeout_secs":61,"max_inflight":50,"on_timeout":"fail_closed","on_saturation":"fail_closed","alert_degraded":true}`,
		},
		{
			"max_inflight_zero",
			`{"enabled":true,"timeout_secs":5,"max_inflight":0,"on_timeout":"fail_closed","on_saturation":"fail_closed","alert_degraded":true}`,
		},
		{
			"max_inflight_over_limit",
			`{"enabled":true,"timeout_secs":5,"max_inflight":501,"on_timeout":"fail_closed","on_saturation":"fail_closed","alert_degraded":true}`,
		},
		{
			"on_timeout_unknown",
			`{"enabled":true,"timeout_secs":5,"max_inflight":50,"on_timeout":"allow_all","on_saturation":"fail_closed","alert_degraded":true}`,
		},
		{
			"on_saturation_unknown",
			`{"enabled":true,"timeout_secs":5,"max_inflight":50,"on_timeout":"fail_closed","on_saturation":"drop","alert_degraded":true}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			apiSecYARASettings(w, newAdminRequest(http.MethodPut,
				"/api/security-scan/yara/settings", []byte(tc.body)))
			if w.Code != http.StatusBadRequest {
				t.Errorf("want 400, got %d; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// TestYARASettings_PersistsAndReloads verifies two persistence invariants:
//
//  1. An AdminSettings file with YARASettingsSaved=true correctly restores all
//     YARA fields via LoadAdminSettings (simulating a restart).
//  2. An older file without YARASettingsSaved (the sentinel) does NOT override
//     init() defaults — ensuring zero-value bools don't disable YARA on upgrade.
//
// SaveAdminSettings is not called directly because it accesses other unrelated
// singletons (blFeedSyncer, syslog, OTLP) that are not initialised in tests.
// Instead we marshal AdminSettings directly, which tests applyAdminYARA and
// the LoadAdminSettings JSON round-trip without any external dependencies.
func TestYARASettings_PersistsAndReloads(t *testing.T) {
	resetYARASettings(t)

	// Save and restore adminSettingsPath since LoadAdminSettings sets it.
	adminSettingsMu.Lock()
	origPath := adminSettingsPath
	adminSettingsMu.Unlock()
	t.Cleanup(func() {
		adminSettingsMu.Lock()
		adminSettingsPath = origPath
		adminSettingsMu.Unlock()
	})

	// ── Part 1: settings file with sentinel → all YARA fields applied ──

	cfg := AdminSettings{
		YARASettingsSaved: true,
		YARAEnabled:       false,
		YARATimeoutSecs:   15,
		YARAMaxInflight:   25,
		YARAOnTimeout:     yaraFailOpenWithAlert,
		YARAOnSaturation:  yaraFailClosed,
		YARAAlertDegraded: false,
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	tmp := filepath.Join(t.TempDir(), "admin_settings.json")
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Simulate restart: reset to init() defaults before loading.
	yaraSetEnabled(true)
	yaraSetTimeoutSecs(5)
	yaraSetMaxInflight(50)
	yaraSetOnTimeout(yaraFailClosed)
	yaraSetOnSaturation(yaraFailClosed)
	yaraSetAlertDegraded(true)

	LoadAdminSettings(tmp)

	if yaraGetEnabled() {
		t.Error("enabled: want false after reload")
	}
	if yaraGetTimeoutSecs() != 15 {
		t.Errorf("timeout_secs: want 15, got %d", yaraGetTimeoutSecs())
	}
	if yaraGetMaxInflight() != 25 {
		t.Errorf("max_inflight: want 25, got %d", yaraGetMaxInflight())
	}
	if yaraGetOnTimeout() != yaraFailOpenWithAlert {
		t.Errorf("on_timeout: want %q, got %q", yaraFailOpenWithAlert, yaraGetOnTimeout())
	}
	if yaraGetOnSaturation() != yaraFailClosed {
		t.Errorf("on_saturation: want %q, got %q", yaraFailClosed, yaraGetOnSaturation())
	}
	if yaraGetAlertDegraded() {
		t.Error("alert_degraded: want false after reload")
	}

	// ── Part 2: pre-feature file (no sentinel) → defaults preserved ──
	// Without YARASettingsSaved=true, zero-value bools (enabled=false) must NOT
	// be applied — this prevents silent YARA disable on first upgrade.

	oldCfg := AdminSettings{} // YARASettingsSaved defaults to false
	oldData, _ := json.Marshal(oldCfg)
	oldTmp := filepath.Join(t.TempDir(), "old_admin_settings.json")
	if err := os.WriteFile(oldTmp, oldData, 0o600); err != nil {
		t.Fatalf("WriteFile old: %v", err)
	}

	yaraSetEnabled(true)
	yaraSetOnTimeout(yaraFailClosed)

	LoadAdminSettings(oldTmp)

	if !yaraGetEnabled() {
		t.Error("sentinel: YARA must remain enabled when YARASettingsSaved=false (upgrade safety)")
	}
	if yaraGetOnTimeout() != yaraFailClosed {
		t.Errorf("sentinel: on_timeout should not change; got %q", yaraGetOnTimeout())
	}
}

// TestYARASettings_FailOpenShowsDiagnosticsWarn verifies that
// checkYARAEnginePosture returns diagWarn whenever on_timeout or
// on_saturation is fail_open_with_alert, and diagOK when both are
// fail_closed.
func TestYARASettings_FailOpenShowsDiagnosticsWarn(t *testing.T) {
	resetYARASettings(t)

	// Baseline: both fail_closed → OK.
	yaraSetEnabled(true)
	yaraSetOnTimeout(yaraFailClosed)
	yaraSetOnSaturation(yaraFailClosed)
	ck := checkYARAEnginePosture()
	if ck.Status != diagOK {
		t.Errorf("both fail_closed: status = %q, want ok", ck.Status)
	}

	// on_timeout = fail_open_with_alert → WARN.
	yaraSetOnTimeout(yaraFailOpenWithAlert)
	ck = checkYARAEnginePosture()
	if ck.Status != diagWarn {
		t.Errorf("on_timeout=fail_open: status = %q, want warn", ck.Status)
	}
	if ck.OperatorAction == "" {
		t.Error("on_timeout=fail_open warn must include operator_action")
	}
	if !strings.Contains(ck.Message, "on_timeout") {
		t.Errorf("warn message should mention on_timeout; got: %s", ck.Message)
	}
	yaraSetOnTimeout(yaraFailClosed)

	// on_saturation = fail_open_with_alert → WARN.
	yaraSetOnSaturation(yaraFailOpenWithAlert)
	ck = checkYARAEnginePosture()
	if ck.Status != diagWarn {
		t.Errorf("on_saturation=fail_open: status = %q, want warn", ck.Status)
	}
	if !strings.Contains(ck.Message, "on_saturation") {
		t.Errorf("warn message should mention on_saturation; got: %s", ck.Message)
	}
	yaraSetOnSaturation(yaraFailClosed)

	// Both fail_open → WARN; message must name both policies.
	yaraSetOnTimeout(yaraFailOpenWithAlert)
	yaraSetOnSaturation(yaraFailOpenWithAlert)
	ck = checkYARAEnginePosture()
	if ck.Status != diagWarn {
		t.Errorf("both fail_open: status = %q, want warn", ck.Status)
	}
	if !strings.Contains(ck.Message, "on_timeout") || !strings.Contains(ck.Message, "on_saturation") {
		t.Errorf("both fail_open warn should name both policies; got: %s", ck.Message)
	}
}

// TestYARA_DisabledSkipsScanAndDiagnosticsWarn verifies two invariants when
// the admin toggle (yara.enabled) is false:
//  1. checkYARAEnginePosture returns diagWarn.
//  2. scanBodyInner does not invoke the YARA engine — content that would
//     otherwise match an active rule passes through unblocked.
func TestYARA_DisabledSkipsScanAndDiagnosticsWarn(t *testing.T) {
	resetYARASettings(t)
	yaraSetEnabled(true)
	yaraSetOnTimeout(yaraFailClosed)
	yaraSetOnSaturation(yaraFailClosed)

	// ── 1. Diagnostics check ────────────────────────────────────────────

	// Enabled → OK.
	ck := checkYARAEnginePosture()
	if ck.Status != diagOK {
		t.Errorf("enabled posture: status = %q, want ok", ck.Status)
	}

	// Disabled → WARN.
	yaraSetEnabled(false)
	ck = checkYARAEnginePosture()
	if ck.Status != diagWarn {
		t.Errorf("disabled posture: status = %q, want warn", ck.Status)
	}
	if ck.OperatorAction == "" {
		t.Error("disabled posture warn must include operator_action")
	}

	// ── 2. Scan skip ────────────────────────────────────────────────────

	// Load an EICAR-matching rule. The parser requires '{' on its own line;
	// yaraRule() produces the correct multi-line layout.
	loadTestYARARule(t, yaraRule("EICAR_disabled_test", `        $a = "EICAR"`, "any of them"))

	if !globalYARA.Enabled() {
		t.Fatal("setup: expected globalYARA to be enabled after LoadDir")
	}
	// Verify the rule matches before testing the admin toggle (isolates failures).
	if m := globalYARA.Match([]byte("EICAR")); len(m) == 0 {
		t.Fatal("setup: YARA rule did not match EICAR — check rule format")
	}

	// With admin toggle off: scanBodyInner must return nil (not blocked)
	// even for content that would match the loaded rule.
	result := globalSecScanner.scanBodyInner(
		[]byte("EICAR"), t.Name()+"-disabled")
	if result != nil {
		t.Errorf("YARA disabled: scanBodyInner returned blocked=%v, want nil", result)
	}

	// Re-enable: the same content must now be blocked by YARA.
	yaraSetEnabled(true)
	globalSecScanner.cache.Clear()
	result = globalSecScanner.scanBodyInner(
		[]byte("EICAR"), t.Name()+"-enabled")
	if result == nil {
		t.Error("YARA enabled: scanBodyInner should block EICAR-matching content")
	}
	if result != nil && result.Source != "yara" {
		t.Errorf("block source = %q, want yara", result.Source)
	}
}
