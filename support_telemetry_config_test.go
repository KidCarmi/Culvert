package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// withTempTelemetryDir points the global dataDir at a fresh temp dir for the
// test (mirrors withTempUploadDir) so telemetry config persistence is
// isolated per test.
func withTempTelemetryDir(t *testing.T) {
	t.Helper()
	prev := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { dataDir = prev })
}

// ── §9 endpoint canonicalization ─────────────────────────────────────────────

// TestTelemetryRejectsHTTP — https is mandatory; plain http is refused.
func TestTelemetryRejectsHTTP(t *testing.T) {
	if _, err := validateTelemetryEndpoint("http://tac.culvertlabs.com"); err == nil {
		t.Error("http:// origin should be rejected")
	}
}

// TestTelemetryRejectsURLUserinfo — embedded credentials in the origin are refused.
func TestTelemetryRejectsURLUserinfo(t *testing.T) {
	if _, err := validateTelemetryEndpoint("https://user:pass@tac.culvertlabs.com"); err == nil {
		t.Error("origin with userinfo should be rejected")
	}
}

// TestTelemetryRejectsFragment — a fragment component is refused.
func TestTelemetryRejectsFragment(t *testing.T) {
	if _, err := validateTelemetryEndpoint("https://tac.culvertlabs.com/#fragment"); err == nil {
		t.Error("origin with a fragment should be rejected")
	}
}

// TestTelemetryRejectsQuery — a query string is refused.
func TestTelemetryRejectsQuery(t *testing.T) {
	if _, err := validateTelemetryEndpoint("https://tac.culvertlabs.com?tenant=x"); err == nil {
		t.Error("origin with a query should be rejected")
	}
}

// TestTelemetryRejectsCustomPath — an operator-provided path beyond a bare "/"
// is refused; only the fixed future /v1/telemetry/samples path is ever used,
// and it is never user-configurable.
func TestTelemetryRejectsCustomPath(t *testing.T) {
	if _, err := validateTelemetryEndpoint("https://tac.culvertlabs.com/custom/path"); err == nil {
		t.Error("origin with a custom path should be rejected")
	}
}

// TestTelemetryRejectsPrivateOrigin — literal private/internal IPv4 and IPv6
// addresses are refused (config-time SSRF posture; no DNS resolution here).
func TestTelemetryRejectsPrivateOrigin(t *testing.T) {
	bad := []string{
		"https://127.0.0.1",
		"https://10.0.0.1",
		"https://169.254.169.254",
		"https://[::1]",
		"https://[fc00::1]",
	}
	for _, o := range bad {
		if _, err := validateTelemetryEndpoint(o); err == nil {
			t.Errorf("origin %q should be rejected (private/internal)", o)
		}
	}
}

// TestTelemetryRejectsInvalidPort — an explicitly supplied port outside the
// valid TCP range (1-65535) is refused; url.Parse/Port() would otherwise
// accept it as a plain numeric string with no range check, persisting an
// endpoint that could never be dialed.
func TestTelemetryRejectsInvalidPort(t *testing.T) {
	bad := []string{
		"https://tac.culvertlabs.com:99999",
		"https://tac.culvertlabs.com:0",
		"https://tac.culvertlabs.com:65536",
		"https://tac.culvertlabs.com:-1",
	}
	for _, o := range bad {
		if _, err := validateTelemetryEndpoint(o); err == nil {
			t.Errorf("origin %q should be rejected (invalid port)", o)
		}
	}
	if _, err := validateTelemetryEndpoint("https://tac.culvertlabs.com:8443"); err != nil {
		t.Errorf("origin with a valid port should be accepted: %v", err)
	}
}

// TestTelemetryCanonicalizesOrigin — a trailing "/" is normalized away and the
// scheme+host is lower-cased; the canonical form is what gets stored/returned.
func TestTelemetryCanonicalizesOrigin(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://tac.culvertlabs.com", "https://tac.culvertlabs.com"},
		{"https://tac.culvertlabs.com/", "https://tac.culvertlabs.com"},
		{"https://TAC.CulvertLabs.COM", "https://tac.culvertlabs.com"},
		{"https://tac.culvertlabs.com:8443", "https://tac.culvertlabs.com:8443"},
	}
	for _, c := range cases {
		got, err := validateTelemetryEndpoint(c.in)
		if err != nil {
			t.Fatalf("validateTelemetryEndpoint(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("validateTelemetryEndpoint(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ── §4 bearer-mandatory gate ─────────────────────────────────────────────────

// TestTelemetryRequiresBearerAuth — an endpoint-only config (no credential) is
// refused at PUT (400) and the effective gate stays false.
func TestTelemetryRequiresBearerAuth(t *testing.T) {
	withTempTelemetryDir(t)

	rec := httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com"}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT enabled+origin, no credential: code=%d, want 400 (body=%q)", rec.Code, rec.Body.String())
	}
	if telemetryEnabled() {
		t.Fatal("telemetryEnabled() must stay false — the PUT should have been rejected, not partially applied")
	}
	if got := telemetryConfigGet(); got.Enabled || got.Origin != "" {
		t.Fatalf("a rejected PUT must not persist anything, got %+v", got)
	}
}

// TestTelemetryCredentialMissingFailsClosed — a persisted config that somehow
// has Enabled=true, a valid Origin, but an empty Credential (e.g. a
// hand-edited or partially-migrated file — bypassing the API's own guard)
// must fail CLOSED: telemetryEnabled() is false and status is
// "credential_missing".
func TestTelemetryCredentialMissingFailsClosed(t *testing.T) {
	withTempTelemetryDir(t)
	telemetryConfigMu.Lock()
	err := saveTelemetryConfigLocked(telemetryConfig{Enabled: true, Origin: "https://tac.culvertlabs.com"})
	telemetryConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if telemetryEnabled() {
		t.Fatal("a config with no credential must never read as enabled")
	}
	if got := telemetryStatus(); got.Status != "credential_missing" || got.EffectiveEnabled {
		t.Fatalf("status = %+v, want status=credential_missing effective_enabled=false", got)
	}
}

// ── credential preserve/replace/clear ────────────────────────────────────────

// TestTelemetryCredentialPreserveReplaceClear exercises all three credential
// update semantics through the real API handler with no ambiguous combination.
func TestTelemetryCredentialPreserveReplaceClear(t *testing.T) {
	withTempTelemetryDir(t)

	// Initial enable with a credential.
	rec := httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "credential": "first-token"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("initial enable: code=%d, body=%q", rec.Code, rec.Body.String())
	}
	if got := telemetryConfigGet(); got.Credential != "first-token" {
		t.Fatalf("credential = %q, want first-token", got.Credential)
	}

	// Preserve: a PUT with a blank credential and no clear flag keeps it.
	rec = httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("preserve PUT: code=%d, body=%q", rec.Code, rec.Body.String())
	}
	if got := telemetryConfigGet(); got.Credential != "first-token" {
		t.Fatalf("credential after preserve = %q, want unchanged first-token", got.Credential)
	}

	// Replace: a non-empty credential in the body atomically replaces it.
	rec = httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "credential": "second-token"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("replace PUT: code=%d, body=%q", rec.Code, rec.Body.String())
	}
	if got := telemetryConfigGet(); got.Credential != "second-token" {
		t.Fatalf("credential after replace = %q, want second-token", got.Credential)
	}

	// No ambiguous combination: replace + clear together is rejected.
	rec = httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "credential": "third-token", "clear_credential": true}))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replace+clear combo: code=%d, want 400", rec.Code)
	}
	if got := telemetryConfigGet(); got.Credential != "second-token" {
		t.Fatalf("an invalid combo must not mutate anything; credential = %q, want unchanged second-token", got.Credential)
	}

	// Clear: the explicit clear action removes the stored credential.
	rec = httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "clear_credential": true}))
	if rec.Code != http.StatusOK {
		t.Fatalf("clear PUT: code=%d, body=%q", rec.Code, rec.Body.String())
	}
	if got := telemetryConfigGet(); got.Credential != "" {
		t.Fatalf("credential after clear = %q, want empty", got.Credential)
	}
}

// TestTelemetryClearCredentialDisablesEffectivePosture — clearing the
// credential on a fully-configured ("ready") posture immediately forces the
// EFFECTIVE posture unavailable (effective_enabled=false, status
// credential_missing) even though the persisted Enabled intent is
// unchanged, and this survives a reload from disk.
func TestTelemetryClearCredentialDisablesEffectivePosture(t *testing.T) {
	withTempTelemetryDir(t)
	telemetryConfigMu.Lock()
	_ = saveTelemetryConfigLocked(telemetryConfig{Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: "tok"})
	telemetryConfigMu.Unlock()
	if !telemetryEnabled() {
		t.Fatal("setup: expected a ready/enabled posture before clearing")
	}

	rec := httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "clear_credential": true}))
	if rec.Code != http.StatusOK {
		t.Fatalf("clear PUT: code=%d, body=%q", rec.Code, rec.Body.String())
	}
	var view telemetryStatusView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if view.EffectiveEnabled {
		t.Fatal("effective_enabled must be false immediately after clearing the credential")
	}
	if view.Status != "credential_missing" {
		t.Fatalf("status = %q, want credential_missing", view.Status)
	}
	if telemetryEnabled() {
		t.Fatal("telemetryEnabled() must be false after the credential is cleared")
	}

	// Restart persistence: a fresh read from disk still shows it cleared.
	if got := telemetryConfigGet(); got.Credential != "" {
		t.Fatalf("credential persisted as %q, want empty after clear survives reload", got.Credential)
	}
}

// ── redaction / never-echoed ─────────────────────────────────────────────────

// TestTelemetryCredentialNeverEchoed — no read model (GET, or the PUT
// response) ever contains the raw credential value, on the wire or in the Go
// struct's own JSON encoding.
func TestTelemetryCredentialNeverEchoed(t *testing.T) {
	withTempTelemetryDir(t)
	const secretValue = "super-secret-bearer-credential-value"

	putRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(putRec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "credential": secretValue}))
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: code=%d, body=%q", putRec.Code, putRec.Body.String())
	}
	if strings.Contains(putRec.Body.String(), secretValue) {
		t.Fatalf("PUT response leaked the credential: %s", putRec.Body.String())
	}

	getRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(getRec, roleReq(RoleAdmin, http.MethodGet, "/api/support/telemetry/config", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET: code=%d, body=%q", getRec.Code, getRec.Body.String())
	}
	if strings.Contains(getRec.Body.String(), secretValue) {
		t.Fatalf("GET response leaked the credential: %s", getRec.Body.String())
	}

	// The typed view itself has no field that could carry it.
	view := telemetryStatusFor(telemetryConfigGet())
	b, err := json.Marshal(view)
	if err != nil {
		t.Fatalf("marshal view: %v", err)
	}
	if strings.Contains(string(b), secretValue) {
		t.Fatalf("telemetryStatusView marshaled the credential: %s", b)
	}
	if !view.CredentialSet {
		t.Fatal("credential_set should be true once a credential is configured")
	}
}

// TestTelemetryConfigAuditDoesNotLeakCredential — the audit trail (Detail,
// Before, After) for support.telemetry.config never contains the raw
// credential value.
func TestTelemetryConfigAuditDoesNotLeakCredential(t *testing.T) {
	withTempTelemetryDir(t)
	restoreAudit := audit.SwapRingForTest()
	t.Cleanup(restoreAudit)
	const secretValue = "audit-must-not-see-this-token" // #nosec G101 -- fake test fixture value, not a real credential

	baseline := time.Now().UnixMilli()
	req := roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "credential": secretValue})
	req.RemoteAddr = "198.51.100.77:0" // unique TEST-NET-2 actor IP
	rec := httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT: code=%d, body=%q", rec.Code, rec.Body.String())
	}
	if !hasMatchingAuditEntry(auditGet(), "198.51.100.77", "support.telemetry.config", "telemetry", baseline) {
		t.Fatal("expected a support.telemetry.config audit entry with the test actor IP")
	}
	for _, e := range auditGet() {
		if e.Action != "support.telemetry.config" {
			continue
		}
		if strings.Contains(e.Detail, secretValue) || strings.Contains(e.Before, secretValue) || strings.Contains(e.After, secretValue) {
			t.Fatalf("audit entry leaked the credential: %+v", e)
		}
	}

	// Clear it too, and check that round as well.
	rec = httptest.NewRecorder()
	req2 := roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "clear_credential": true})
	req2.RemoteAddr = "198.51.100.77:0"
	apiSupportTelemetryConfig(rec, req2)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear PUT: code=%d, body=%q", rec.Code, rec.Body.String())
	}
	for _, e := range auditGet() {
		if e.Action != "support.telemetry.config" {
			continue
		}
		if strings.Contains(e.Detail, secretValue) || strings.Contains(e.Before, secretValue) || strings.Contains(e.After, secretValue) {
			t.Fatalf("audit entry leaked the credential after clear: %+v", e)
		}
	}
}

// ── P1: a persisted-but-unsafe origin is never reflected outward ─────────────

// TestTelemetryPersistedUnsafeOriginNeverEchoed proves the read model NEVER
// echoes a raw persisted origin. The PUT handler canonicalizes before
// storing, but the on-disk config is not a trusted input — it can be
// hand-edited, restored from a foreign backup, or corrupted. Every unsafe
// shape (userinfo, query, fragment, path, bad port, private IP, plain http)
// written directly to disk must come back as status=origin_invalid with the
// origin field OMITTED, and the raw value must be absent from the GET
// response, the PUT response, and every audit entry.
func TestTelemetryPersistedUnsafeOriginNeverEchoed(t *testing.T) {
	unsafeOrigins := []struct{ name, origin, marker string }{
		{"userinfo", "https://user:s3cr3t-in-origin@tac.culvertlabs.com", "s3cr3t-in-origin"},
		{"query", "https://tac.culvertlabs.com?tenant=leaky-tenant-id", "leaky-tenant-id"},
		{"fragment", "https://tac.culvertlabs.com/#leaky-fragment", "leaky-fragment"},
		{"path", "https://tac.culvertlabs.com/leaky/path/segment", "leaky/path/segment"},
		{"invalid port", "https://tac.culvertlabs.com:99999", ":99999"},
		{"private ip", "https://10.1.2.3", "10.1.2.3"},
		{"plain http", "http://tac.culvertlabs.com", "http://"},
	}
	for _, tc := range unsafeOrigins {
		t.Run(tc.name, func(t *testing.T) {
			withTempTelemetryDir(t)
			restoreAudit := audit.SwapRingForTest()
			t.Cleanup(restoreAudit)

			// Write the unsafe origin DIRECTLY to disk, bypassing the API.
			telemetryConfigMu.Lock()
			err := saveTelemetryConfigLocked(telemetryConfig{
				Enabled: true, Origin: tc.origin, Credential: "tok",
			})
			telemetryConfigMu.Unlock()
			if err != nil {
				t.Fatalf("save: %v", err)
			}
			assertUnsafeOriginNotExposed(t, tc.marker)
		})
	}
}

// assertUnsafeOriginNotExposed checks every outward surface — the typed
// view, GET, a subsequent PUT's response, and the audit trail — for the raw
// unsafe origin marker.
func assertUnsafeOriginNotExposed(t *testing.T, marker string) {
	t.Helper()

	view := telemetryStatus()
	if view.Origin != "" {
		t.Errorf("read model exposed origin %q for an invalid persisted origin — it must be omitted", view.Origin)
	}
	if view.Status != "origin_invalid" {
		t.Errorf("status = %q, want origin_invalid", view.Status)
	}
	if view.EffectiveEnabled {
		t.Error("effective_enabled must be false for an invalid origin")
	}
	if telemetryEnabled() {
		t.Error("telemetryEnabled() must be false for an invalid origin")
	}

	getRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(getRec, roleReq(RoleAdmin, http.MethodGet, "/api/support/telemetry/config", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET: code=%d body=%q", getRec.Code, getRec.Body.String())
	}
	if strings.Contains(getRec.Body.String(), marker) {
		t.Errorf("GET response leaked the unsafe persisted origin (%q): %s", marker, getRec.Body.String())
	}

	// A subsequent PUT must not leak it via the response or the audit
	// before-snapshot either.
	putRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(putRec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": false}))
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT: code=%d body=%q", putRec.Code, putRec.Body.String())
	}
	if strings.Contains(putRec.Body.String(), marker) {
		t.Errorf("PUT response leaked the unsafe persisted origin (%q): %s", marker, putRec.Body.String())
	}
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.Action != "support.telemetry.config" {
			continue
		}
		for field, val := range map[string]string{"detail": e.Detail, "before": e.Before, "after": e.After} {
			if strings.Contains(val, marker) {
				t.Errorf("audit %s leaked the unsafe persisted origin (%q): %s", field, marker, val)
			}
		}
	}
}

// TestTelemetryPersistedNonCanonicalOriginIsCanonicalized proves a persisted
// origin that is VALID but not canonical (trailing slash, upper-case host)
// is returned in canonical form, not verbatim — the read model is the single
// canonicalization point regardless of how the value reached disk.
func TestTelemetryPersistedNonCanonicalOriginIsCanonicalized(t *testing.T) {
	withTempTelemetryDir(t)
	telemetryConfigMu.Lock()
	err := saveTelemetryConfigLocked(telemetryConfig{
		Enabled: true, Origin: "https://TAC.CulvertLabs.COM/", Credential: "tok",
	})
	telemetryConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	view := telemetryStatus()
	if view.Origin != "https://tac.culvertlabs.com" {
		t.Errorf("origin = %q, want the canonical https://tac.culvertlabs.com", view.Origin)
	}
	if view.Status != "ready" || !view.EffectiveEnabled {
		t.Errorf("a valid non-canonical origin should still be ready/effective: %+v", view)
	}
}

// ── P1: unsafe config-file permissions / type ───────────────────────────────

// TestTelemetryConfigRejectsUnsafeFileMode proves a group/other-readable
// config is either self-healed to 0600 or rejected — never trusted as-is
// while another local account can read the bearer credential.
func TestTelemetryConfigRejectsUnsafeFileMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o644, 0o666, 0o604, 0o640} {
		t.Run(mode.String(), func(t *testing.T) {
			withTempTelemetryDir(t)
			telemetryConfigMu.Lock()
			err := saveTelemetryConfigLocked(telemetryConfig{
				Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: "tok",
			})
			telemetryConfigMu.Unlock()
			if err != nil {
				t.Fatalf("save: %v", err)
			}
			if err := os.Chmod(telemetryConfigPath(), mode); err != nil {
				t.Fatalf("chmod: %v", err)
			}

			// Load self-heals the mode back to 0600 and then trusts the file.
			_ = telemetryConfigGet()
			fi, err := os.Stat(telemetryConfigPath())
			if err != nil {
				t.Fatalf("stat: %v", err)
			}
			if got := fi.Mode().Perm(); got&0o077 != 0 {
				t.Errorf("after load, mode = %04o — group/other bits must be cleared or the config refused", got)
			}
		})
	}
}

// TestTelemetryConfigRejectsSymlink proves a symlinked config is refused
// outright (never followed), so an attacker who can create a symlink in the
// support dir cannot redirect the credential read — or have the appliance
// chmod an arbitrary target.
func TestTelemetryConfigRejectsSymlink(t *testing.T) {
	withTempTelemetryDir(t)
	if err := os.MkdirAll(filepath.Dir(telemetryConfigPath()), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(dataDir, "elsewhere.json")
	body := `{"enabled":true,"origin":"https://tac.culvertlabs.com","credential":"tok"}`
	if err := os.WriteFile(target, []byte(body), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, telemetryConfigPath()); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}
	if got := telemetryConfigGet(); got.Enabled || got.Credential != "" {
		t.Fatalf("a symlinked config must be refused (fail closed), got %+v", got)
	}
	if telemetryEnabled() {
		t.Fatal("a symlinked config must never produce an enabled posture")
	}
}

// TestTelemetryConfigRejectsNonRegularFile proves a directory (or any other
// non-regular file) at the config path fails closed rather than erroring
// into a trusted state.
func TestTelemetryConfigRejectsNonRegularFile(t *testing.T) {
	withTempTelemetryDir(t)
	if err := os.MkdirAll(telemetryConfigPath(), 0o700); err != nil {
		t.Fatalf("mkdir at config path: %v", err)
	}
	if got := telemetryConfigGet(); got.Enabled || got.Credential != "" {
		t.Fatalf("a directory at the config path must fail closed, got %+v", got)
	}
	if telemetryEnabled() {
		t.Fatal("a non-regular config must never produce an enabled posture")
	}
}

// TestTelemetryConfigUnsafeFileDoesNotLogCredential proves the refusal path
// reports the POSTURE without ever logging the credential value.
func TestTelemetryConfigUnsafeFileDoesNotLogCredential(t *testing.T) {
	withTempTelemetryDir(t)
	const secretValue = "must-not-reach-the-log-token" // #nosec G101 -- fake test fixture value
	if err := os.MkdirAll(filepath.Dir(telemetryConfigPath()), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(dataDir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"credential":"`+secretValue+`"}`), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	if err := os.Symlink(target, telemetryConfigPath()); err != nil {
		t.Skipf("symlink unsupported here: %v", err)
	}

	var buf bytes.Buffer
	prev := logger
	logger = log.New(&buf, "", 0)
	t.Cleanup(func() { logger = prev })

	_ = telemetryConfigGet()
	if strings.Contains(buf.String(), secretValue) {
		t.Fatalf("the unsafe-config log line leaked the credential: %s", buf.String())
	}
	if buf.Len() == 0 {
		t.Error("expected a log line reporting the refused config")
	}
}

// ── P2: credential input validation ─────────────────────────────────────────

// TestTelemetryRejectsMalformedCredential proves control characters (a
// header-injection primitive for the future Bearer header) and over-length
// values are refused, and that the rejection never echoes the value.
func TestTelemetryRejectsMalformedCredential(t *testing.T) {
	cases := []struct{ name, cred string }{
		{"CRLF injection", "tok\r\nX-Injected: 1"},
		{"bare LF", "tok\nmore"},
		{"NUL byte", "tok\x00more"},
		{"DEL byte", "tok\x7fmore"},
		{"blank", "   "},
		{"too long", strings.Repeat("a", maxTelemetryCredentialLen+1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTempTelemetryDir(t)
			rec := httptest.NewRecorder()
			apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
				map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "credential": tc.cred}))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code=%d, want 400 for a malformed credential", rec.Code)
			}
			if strings.Contains(rec.Body.String(), tc.cred) {
				t.Errorf("the rejection echoed the credential value: %s", rec.Body.String())
			}
			if got := telemetryConfigGet(); got.Credential != "" {
				t.Errorf("a rejected credential must not persist, got %q", got.Credential)
			}
		})
	}
	// A credential exactly at the cap is accepted.
	withTempTelemetryDir(t)
	rec := httptest.NewRecorder()
	apiSupportTelemetryConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com",
			"credential": strings.Repeat("a", maxTelemetryCredentialLen)}))
	if rec.Code != http.StatusOK {
		t.Fatalf("a max-length credential should be accepted, code=%d body=%q", rec.Code, rec.Body.String())
	}
}

// ── persistence ───────────────────────────────────────────────────────────────

// TestTelemetryConfigPersists0600 — the on-disk config file is 0600.
func TestTelemetryConfigPersists0600(t *testing.T) {
	withTempTelemetryDir(t)
	telemetryConfigMu.Lock()
	err := saveTelemetryConfigLocked(telemetryConfig{Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: "tok"})
	telemetryConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	fi, err := os.Stat(telemetryConfigPath())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("telemetry_config.json mode = %o, want 0600", perm)
	}
}

// TestTelemetryConfigRestartPersistence — config round-trips across a
// simulated restart (a fresh disk read), for enabled, disabled, and
// credential-cleared states.
func TestTelemetryConfigRestartPersistence(t *testing.T) {
	withTempTelemetryDir(t)

	telemetryConfigMu.Lock()
	err := saveTelemetryConfigLocked(telemetryConfig{Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: "tok"})
	telemetryConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	// Simulate restart: read fresh from disk (no in-memory cache exists to
	// smuggle state across — loadTelemetryConfigLocked always re-reads).
	telemetryConfigMu.Lock()
	got := loadTelemetryConfigLocked()
	telemetryConfigMu.Unlock()
	if !got.Enabled || got.Origin != "https://tac.culvertlabs.com" || got.Credential != "tok" {
		t.Fatalf("round-trip = %+v", got)
	}
	if !telemetryEnabled() {
		t.Fatal("telemetryEnabled() should be true after a fresh reload")
	}

	// Disable — durable across "restart".
	telemetryConfigMu.Lock()
	err = saveTelemetryConfigLocked(telemetryConfig{Enabled: false, Origin: "https://tac.culvertlabs.com", Credential: "tok"})
	telemetryConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save disabled: %v", err)
	}
	if telemetryEnabled() {
		t.Fatal("disabling must be durable across a fresh reload")
	}

	// Clear the credential — durable across "restart".
	telemetryConfigMu.Lock()
	err = saveTelemetryConfigLocked(telemetryConfig{Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: ""})
	telemetryConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save cleared: %v", err)
	}
	if telemetryEnabled() {
		t.Fatal("a cleared credential must stay cleared across a fresh reload")
	}
	if got := loadTelemetryConfigLocked(); got.Credential != "" {
		t.Fatalf("credential = %q after reload, want empty", got.Credential)
	}
}

// TestTelemetryMalformedConfigFailsClosed — a corrupt/empty on-disk file
// fails CLOSED to disabled, never enabling telemetry.
func TestTelemetryMalformedConfigFailsClosed(t *testing.T) {
	withTempTelemetryDir(t)
	telemetryConfigMu.Lock()
	err := saveTelemetryConfigLocked(telemetryConfig{Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: "tok"})
	telemetryConfigMu.Unlock()
	if err != nil {
		t.Fatalf("save: %v", err)
	}
	if !telemetryEnabled() {
		t.Fatal("setup: expected enabled before corruption")
	}

	if err := os.WriteFile(telemetryConfigPath(), []byte("{not json"), 0o600); err != nil {
		t.Fatalf("corrupt write: %v", err)
	}
	if telemetryEnabled() {
		t.Fatal("a corrupt telemetry config must fail closed (disabled)")
	}
	if got := telemetryStatus(); got.Status != "disabled" {
		t.Fatalf("status after corruption = %q, want disabled", got.Status)
	}

	// An empty file must also fail closed.
	if err := os.WriteFile(telemetryConfigPath(), []byte(""), 0o600); err != nil {
		t.Fatalf("empty write: %v", err)
	}
	if telemetryEnabled() {
		t.Fatal("an empty telemetry config must fail closed (disabled)")
	}
}

// ── RBAC / classification / OpenAPI ──────────────────────────────────────────

// TestTelemetryRoutesRBACAndClassification — GET is viewer+, PUT is
// admin-only+audited, and the uiRoutes metadata matches the handler's actual
// RBAC contract exactly.
func TestTelemetryRoutesRBACAndClassification(t *testing.T) {
	withTempTelemetryDir(t)

	var entry *uiRouteMetadata
	for i := range uiRoutes {
		if uiRoutes[i].Path == "/api/support/telemetry/config" {
			entry = &uiRoutes[i]
			break
		}
	}
	if entry == nil {
		t.Fatal("uiRoutes has no entry for /api/support/telemetry/config")
	}
	var getMeta, putMeta *uiRouteMethod
	for i := range entry.Methods {
		switch entry.Methods[i].Method {
		case "GET":
			getMeta = &entry.Methods[i]
		case "PUT":
			putMeta = &entry.Methods[i]
		}
	}
	// BOTH methods are admin-only: the posture reveals the TAC origin and
	// whether a credential is configured — consent configuration, not
	// general operational status.
	if getMeta == nil || getMeta.MinRole != RoleAdmin || getMeta.Mutating {
		t.Fatalf("GET metadata = %+v, want MinRole=admin Mutating=false", getMeta)
	}
	if putMeta == nil || putMeta.MinRole != RoleAdmin || !putMeta.Mutating || !putMeta.AuditExpected {
		t.Fatalf("PUT metadata = %+v, want MinRole=admin Mutating=true AuditExpected=true", putMeta)
	}

	// GET admin → 200.
	gRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(gRec, roleReq(RoleAdmin, http.MethodGet, "/api/support/telemetry/config", nil))
	if gRec.Code != http.StatusOK {
		t.Fatalf("GET admin code=%d want 200", gRec.Code)
	}

	// GET viewer → 403 (the whole config surface is admin-gated).
	gvRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(gvRec, roleReq(RoleViewer, http.MethodGet, "/api/support/telemetry/config", nil))
	if gvRec.Code != http.StatusForbidden {
		t.Fatalf("GET viewer code=%d want 403 — a viewer must not read the telemetry consent posture", gvRec.Code)
	}
	// GET operator → 403 as well (admin is strictly above operator).
	goRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(goRec, roleReq(RoleOperator, http.MethodGet, "/api/support/telemetry/config", nil))
	if goRec.Code != http.StatusForbidden {
		t.Fatalf("GET operator code=%d want 403", goRec.Code)
	}

	// PUT viewer → 403.
	vRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(vRec, roleReq(RoleViewer, http.MethodPut, "/api/support/telemetry/config", map[string]any{"enabled": false}))
	if vRec.Code != http.StatusForbidden {
		t.Fatalf("PUT viewer code=%d want 403", vRec.Code)
	}

	// PUT admin, valid → 200.
	aRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(aRec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config",
		map[string]any{"enabled": false}))
	if aRec.Code != http.StatusOK {
		t.Fatalf("PUT admin code=%d want 200 (body=%q)", aRec.Code, aRec.Body.String())
	}

	// Unsupported method → 405.
	mRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(mRec, roleReq(RoleAdmin, http.MethodDelete, "/api/support/telemetry/config", nil))
	if mRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE code=%d want 405", mRec.Code)
	}
}

// TestTelemetryOpenAPIContract — the real GET/PUT responses (and a
// representative PUT request body) validate against the committed OpenAPI
// contract for /api/support/telemetry/config.
func TestTelemetryOpenAPIContract(t *testing.T) {
	withTempTelemetryDir(t)
	spec := loadContract(t)

	putBody := map[string]any{"enabled": true, "origin": "https://tac.culvertlabs.com", "credential": "contract-test-token"}
	putBodyBytes, err := json.Marshal(putBody)
	if err != nil {
		t.Fatalf("marshal put body: %v", err)
	}
	if err := spec.ValidateJSONRequest(http.MethodPut, "/api/support/telemetry/config", putBodyBytes); err != nil {
		t.Fatalf("PUT request body violates contract: %v", err)
	}

	putRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(putRec, roleReq(RoleAdmin, http.MethodPut, "/api/support/telemetry/config", putBody))
	if putRec.Code != http.StatusOK {
		t.Fatalf("PUT status = %d, want 200; body=%s", putRec.Code, putRec.Body.String())
	}
	if err := spec.ValidateJSONResponse(http.MethodPut, "/api/support/telemetry/config", http.StatusOK, putRec.Body.Bytes()); err != nil {
		t.Fatalf("PUT response violates contract: %v\nbody: %s", err, putRec.Body.String())
	}

	getRec := httptest.NewRecorder()
	apiSupportTelemetryConfig(getRec, roleReq(RoleAdmin, http.MethodGet, "/api/support/telemetry/config", nil))
	if getRec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200; body=%s", getRec.Code, getRec.Body.String())
	}
	if err := spec.ValidateJSONResponse(http.MethodGet, "/api/support/telemetry/config", http.StatusOK, getRec.Body.Bytes()); err != nil {
		t.Fatalf("GET response violates contract: %v\nbody: %s", err, getRec.Body.String())
	}
}

// ── consent independence ─────────────────────────────────────────────────────

// TestTelemetryConsentIndependentFromUpload — enabling telemetry never
// touches the upload config (content or existence), and vice versa; the two
// consent switches are fully independent (ADR-0011/P6).
func TestTelemetryConsentIndependentFromUpload(t *testing.T) {
	withTempTelemetryDir(t)

	telemetryConfigMu.Lock()
	_ = saveTelemetryConfigLocked(telemetryConfig{Enabled: true, Origin: "https://tac.culvertlabs.com", Credential: "tok"})
	telemetryConfigMu.Unlock()
	if !telemetryEnabled() {
		t.Fatal("telemetry should be enabled")
	}
	if uploadEnabled() {
		t.Fatal("enabling telemetry must not enable upload")
	}
	if _, err := os.Stat(uploadConfigPath()); err == nil {
		t.Error("enabling telemetry wrote upload_config.json — consent switches must be independent")
	}

	uploadConfigMu.Lock()
	_ = saveUploadConfigLocked(uploadConfig{Enabled: true, Origin: "https://tac.example.com"})
	uploadConfigMu.Unlock()
	if !uploadEnabled() {
		t.Fatal("upload should be enabled")
	}
	if !telemetryEnabled() {
		t.Fatal("enabling upload must not disable telemetry")
	}
	got := telemetryConfigGet()
	if !got.Enabled || got.Origin != "https://tac.culvertlabs.com" || got.Credential != "tok" {
		t.Fatalf("telemetry config mutated by enabling upload: %+v", got)
	}
}

// TestTelemetryConfigNoEgressStatic guards against forgetting the intended
// storage location — telemetry_config.json under <dataDir>/support, same
// directory as every other node-local support consent file.
func TestTelemetryConfigNoEgressStatic(t *testing.T) {
	withTempTelemetryDir(t)
	telemetryConfigMu.Lock()
	_ = saveTelemetryConfigLocked(telemetryConfig{Enabled: false})
	telemetryConfigMu.Unlock()
	want := filepath.Join(dataDir, "support", "telemetry_config.json")
	if telemetryConfigPath() != want {
		t.Fatalf("telemetryConfigPath() = %q, want %q", telemetryConfigPath(), want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("expected config file at %q: %v", want, err)
	}
}
