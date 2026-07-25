package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withTempUploadDir points the global dataDir at a fresh temp dir for the test
// (mirrors the support-bundle tests) so upload config persistence is isolated.
func withTempUploadDir(t *testing.T) {
	t.Helper()
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })
}

// TestUploadConfig_DefaultOffNotEnabled — the default posture is not_enabled and
// no egress is possible without explicit configuration.
func TestUploadConfig_DefaultOffNotEnabled(t *testing.T) {
	withTempUploadDir(t)
	if uploadEnabled() {
		t.Fatal("upload must be disabled by default")
	}
	st := uploadStatus()
	if st["state"] != "not_enabled" {
		t.Fatalf("default state = %v, want not_enabled", st["state"])
	}
	if st["enabled"] != false {
		t.Fatalf("default enabled = %v, want false", st["enabled"])
	}
}

// TestUploadConfig_PersistRoundTripAndFailClosed — config round-trips, and a
// corrupt config fails CLOSED (disabled), never enabling egress.
func TestUploadConfig_PersistRoundTripAndFailClosed(t *testing.T) {
	withTempUploadDir(t)
	uploadConfigMu.Lock()
	err := saveUploadConfigLocked(uploadConfig{Enabled: true, Origin: "https://tac.example.com"})
	uploadConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if got := uploadConfigGet(); !got.Enabled || got.Origin != "https://tac.example.com" {
		t.Fatalf("round-trip = %+v", got)
	}
	if !uploadEnabled() {
		t.Fatal("uploadEnabled should be true after enabling with an origin")
	}
	// Corrupt the file → fail closed to disabled.
	if err := os.WriteFile(uploadConfigPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt write: %v", err)
	}
	if uploadEnabled() {
		t.Fatal("a corrupt upload config must fail closed (disabled)")
	}
}

// TestValidateUploadOrigin — https-only, real host, and private/internal literal
// IPs refused (the config-time half of the SSRF posture; hostnames resolve at
// dial time in a later PR).
func TestValidateUploadOrigin(t *testing.T) {
	ok := []string{
		"https://tac.example.com",
		"https://tac.example.com:8443/v1",
		"https://portal.culvertlabs.com",
	}
	for _, o := range ok {
		if err := validateUploadOrigin(o); err != nil {
			t.Errorf("origin %q should be valid: %v", o, err)
		}
	}
	bad := []string{
		"http://tac.example.com",        // not https
		"ftp://tac.example.com",         // wrong scheme
		"https://",                      // no host
		"https://10.0.0.5",              // private literal IP (RFC1918)
		"https://192.168.1.1:8443",      // private literal IP
		"https://169.254.169.254",       // link-local metadata (IPv4)
		"https://[::1]",                 // IPv6 loopback literal
		"https://[fc00::1]",             // IPv6 ULA literal
		"https://[fe80::1]",             // IPv6 link-local literal
		"https://[fe80::1%25eth0]",      // scoped IPv6 link-local (zone id) — Codex P2
		"https://[fe80::1%25eth0]:8443", // scoped IPv6 with port
	}
	for _, o := range bad {
		if err := validateUploadOrigin(o); err == nil {
			t.Errorf("origin %q should be rejected", o)
		}
	}
}

// TestAPISupportUploadConfig_RBACValidationAudit — method/RBAC gates, validation,
// persistence, and the audit emission on a valid admin PUT.
func TestAPISupportUploadConfig_RBACValidationAudit(t *testing.T) {
	withTempUploadDir(t)

	// GET viewer → 200.
	gRec := httptest.NewRecorder()
	apiSupportUploadConfig(gRec, roleReq(RoleViewer, http.MethodGet, "/api/support/upload/config", nil))
	if gRec.Code != http.StatusOK {
		t.Fatalf("GET viewer code=%d want 200", gRec.Code)
	}

	// PUT viewer → 403.
	vRec := httptest.NewRecorder()
	apiSupportUploadConfig(vRec, roleReq(RoleViewer, http.MethodPut, "/api/support/upload/config", map[string]any{"enabled": false}))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("PUT viewer code=%d want 403", vRec.Code)
	}

	// PUT admin, non-https origin → 400.
	bRec := httptest.NewRecorder()
	apiSupportUploadConfig(bRec, roleReq(RoleAdmin, http.MethodPut, "/api/support/upload/config", map[string]any{"enabled": true, "origin": "http://tac.example.com"}))
	if bRec.Code != http.StatusBadRequest {
		t.Fatalf("PUT admin bad-origin code=%d want 400", bRec.Code)
	}

	// PUT admin, enable with no origin → 400.
	eRec := httptest.NewRecorder()
	apiSupportUploadConfig(eRec, roleReq(RoleAdmin, http.MethodPut, "/api/support/upload/config", map[string]any{"enabled": true}))
	if eRec.Code != http.StatusBadRequest {
		t.Fatalf("PUT admin enable-no-origin code=%d want 400", eRec.Code)
	}

	// PUT admin, valid → 200, persisted, audited.
	baseline := time.Now().UnixMilli()
	req := roleReq(RoleAdmin, http.MethodPut, "/api/support/upload/config", map[string]any{"enabled": true, "origin": "https://tac.example.com"})
	req.RemoteAddr = "198.51.100.61:0" // unique TEST-NET-2 actor IP
	okRec := httptest.NewRecorder()
	apiSupportUploadConfig(okRec, req)
	if okRec.Code != http.StatusOK {
		t.Fatalf("PUT admin valid code=%d want 200 (body=%q)", okRec.Code, okRec.Body.String())
	}
	if !uploadEnabled() {
		t.Fatal("valid PUT should have enabled upload")
	}
	if !hasMatchingAuditEntry(auditGet(), "198.51.100.61", "support.upload.config", "upload", baseline) {
		t.Error("expected a support.upload.config audit entry with the test actor IP")
	}
}

// TestNoAutoUpload — no code path uploads without explicit configuration. PR-1
// form: (1) the gate defaults off, and (2) no startup/background source consumes
// the upload gate/config, so nothing auto-initiates an upload. When the explicit
// per-bundle consent handler lands it is request-driven, not startup/background,
// so this wall stays valid.
func TestNoAutoUpload(t *testing.T) {
	withTempUploadDir(t)
	if uploadEnabled() {
		t.Fatal("upload gate must default to off")
	}

	dir := pkgSourceDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read pkg dir: %v", err)
	}
	forbidden := []string{"uploadEnabled(", "uploadConfigGet("}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "support_upload.go" {
			continue
		}
		startupOrMain := name == "main.go" || strings.HasSuffix(name, "_startup.go") || strings.HasPrefix(name, "background_services")
		if !startupOrMain {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		src := string(b)
		for _, tok := range forbidden {
			if strings.Contains(src, tok) {
				t.Errorf("%s references %q — upload must not be wired into any startup/background (auto) path", name, tok)
			}
		}
	}
}

// TestConsentSeparation — the upload switch is independent (ADR-0011/P6):
// enabling upload writes ONLY its own node-local file and touches no other
// consent/posture surface. Extended for M7 Slice 2 (§14/§15): enabling
// telemetry afterward writes ONLY its own node-local file too, leaves
// upload_config.json byte-identical, and touches no admin_settings.json —
// all FOUR independent switches (support-bundle upload, OTLP, Prometheus/
// alerts, telemetry) stay consent-separated.
func TestConsentSeparation(t *testing.T) {
	withTempUploadDir(t)
	uploadConfigMu.Lock()
	_ = saveUploadConfigLocked(uploadConfig{Enabled: true, Origin: "https://tac.example.com"})
	uploadConfigMu.Unlock()
	if !uploadEnabled() {
		t.Fatal("upload should be enabled")
	}

	supportDir := filepath.Join(dataDir, "support")
	entries, err := os.ReadDir(supportDir)
	if err != nil {
		t.Fatalf("read support dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != "upload_config.json" {
			t.Errorf("enabling upload also wrote %q — the upload switch must be independent (no consent conflation)", e.Name())
		}
	}
	if _, err := os.Stat(filepath.Join(dataDir, "admin_settings.json")); err == nil {
		t.Error("enabling upload wrote admin_settings.json — upload is node-local and independent")
	}

	// M7 Slice 2: enabling telemetry must touch ONLY telemetry_config.json —
	// upload_config.json must stay byte-identical, and no admin_settings.json.
	uploadConfigBefore, err := os.ReadFile(uploadConfigPath())
	if err != nil {
		t.Fatalf("read upload config baseline: %v", err)
	}
	telemetryConfigMu.Lock()
	_ = saveTelemetryConfigLocked(telemetryConfig{Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: "tok"})
	telemetryConfigMu.Unlock()
	if !telemetryEnabled() {
		t.Fatal("telemetry should be enabled")
	}
	entries, err = os.ReadDir(supportDir)
	if err != nil {
		t.Fatalf("read support dir after telemetry enable: %v", err)
	}
	allowed := map[string]bool{"upload_config.json": true, "telemetry_config.json": true}
	for _, e := range entries {
		if !allowed[e.Name()] {
			t.Errorf("enabling telemetry also wrote %q — telemetry consent must be independent (no consent conflation)", e.Name())
		}
	}
	uploadConfigAfter, err := os.ReadFile(uploadConfigPath())
	if err != nil {
		t.Fatalf("read upload config after telemetry enable: %v", err)
	}
	if !bytes.Equal(uploadConfigBefore, uploadConfigAfter) {
		t.Error("enabling telemetry modified upload_config.json — consent switches must be fully independent")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "admin_settings.json")); err == nil {
		t.Error("enabling telemetry wrote admin_settings.json — telemetry is node-local and independent")
	}
}
