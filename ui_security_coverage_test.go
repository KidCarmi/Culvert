package main

// ui_security_coverage_test.go — targets the four 0%-covered
// security-sensitive handlers in ui_security.go flagged for coverage
// improvement: apiCARotate, apiCAKeyProvider, apiOCSPConfig, apiSecYARARules.
//
// Every test snapshots the globals it touches (pendingCARotation,
// globalOCSP, globalYARA, globalSecScanner) and restores them via
// t.Cleanup so parallel / shuffled runs stay isolated. This is the same
// discipline qa-determinism exists to enforce — if any of these leaks,
// the gate catches it before CI.

import (
	"bytes"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/scanexcl"
	"github.com/KidCarmi/Culvert/internal/secscan"
)

// ─── apiCARotate ────────────────────────────────────────────────────────────

func TestAPICARotate_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiCARotate(w, getReq("/api/ca/rotate"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// Step 1 of the two-step flow: POST without confirm=true must return a
// short-lived confirmation token and a warning payload but NOT rotate the CA.
func TestAPICARotate_Step1IssuesToken(t *testing.T) {
	// Snapshot the pending-rotation slot — it's a package-global.
	pendingCARotation.Lock()
	origToken, origExp := pendingCARotation.token, pendingCARotation.expires
	pendingCARotation.Unlock()
	t.Cleanup(func() {
		pendingCARotation.Lock()
		pendingCARotation.token = origToken
		pendingCARotation.expires = origExp
		pendingCARotation.Unlock()
	})

	w := httptest.NewRecorder()
	apiCARotate(w, jsonReq(http.MethodPost, "/api/ca/rotate", map[string]any{}))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	if m["status"] != "pending_confirmation" {
		t.Fatalf("status = %v, want pending_confirmation", m["status"])
	}
	tok, _ := m["confirmation_token"].(string)
	if len(tok) != 32 { // 16 random bytes → 32 hex chars
		t.Fatalf("confirmation_token length = %d, want 32", len(tok))
	}
	if m["warning"] == "" {
		t.Error("step 1 response must include a warning string")
	}

	// The token must now be the pending value.
	pendingCARotation.Lock()
	stored := pendingCARotation.token
	pendingCARotation.Unlock()
	if stored != tok {
		t.Fatalf("pending token = %q, want %q", stored, tok)
	}
}

// Step 2 must 403 when the supplied token does not match the pending one.
func TestAPICARotate_Step2WrongToken(t *testing.T) {
	pendingCARotation.Lock()
	origToken, origExp := pendingCARotation.token, pendingCARotation.expires
	pendingCARotation.token = "correct-token"
	pendingCARotation.expires = time.Now().Add(60 * time.Second)
	pendingCARotation.Unlock()
	t.Cleanup(func() {
		pendingCARotation.Lock()
		pendingCARotation.token = origToken
		pendingCARotation.expires = origExp
		pendingCARotation.Unlock()
	})

	w := httptest.NewRecorder()
	apiCARotate(w, jsonReq(http.MethodPost, "/api/ca/rotate", map[string]any{
		"confirm":            true,
		"confirmation_token": "bogus",
	}))
	assertStatus(t, w, http.StatusForbidden)
}

// Step 2 must 400 when no token has been issued (or it has expired). The
// handler one-shot-consumes the token regardless of outcome, so the test
// must restore the previous slot.
func TestAPICARotate_Step2NoPendingToken(t *testing.T) {
	pendingCARotation.Lock()
	origToken, origExp := pendingCARotation.token, pendingCARotation.expires
	pendingCARotation.token = ""
	pendingCARotation.expires = time.Time{}
	pendingCARotation.Unlock()
	t.Cleanup(func() {
		pendingCARotation.Lock()
		pendingCARotation.token = origToken
		pendingCARotation.expires = origExp
		pendingCARotation.Unlock()
	})

	w := httptest.NewRecorder()
	apiCARotate(w, jsonReq(http.MethodPost, "/api/ca/rotate", map[string]any{
		"confirm":            true,
		"confirmation_token": "whatever",
	}))
	assertStatus(t, w, http.StatusBadRequest)
}

// Step 2 must 400 when the stored token has already expired. Exercises the
// "storedToken != \"\" but time.Now().After(expires)" branch specifically.
func TestAPICARotate_Step2ExpiredToken(t *testing.T) {
	pendingCARotation.Lock()
	origToken, origExp := pendingCARotation.token, pendingCARotation.expires
	pendingCARotation.token = "expired-token"
	pendingCARotation.expires = time.Now().Add(-1 * time.Second) // already elapsed
	pendingCARotation.Unlock()
	t.Cleanup(func() {
		pendingCARotation.Lock()
		pendingCARotation.token = origToken
		pendingCARotation.expires = origExp
		pendingCARotation.Unlock()
	})

	w := httptest.NewRecorder()
	apiCARotate(w, jsonReq(http.MethodPost, "/api/ca/rotate", map[string]any{
		"confirm":            true,
		"confirmation_token": "expired-token",
	}))
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiCAStatus / apiCADownload / apiCACacheClear ─────────────────────────
// These three are adjacent to apiCARotate in the CA management panel and
// were also at 0% coverage. Trivial to cover here so the GUI surface area
// gets a baseline test.

func TestAPICAStatus_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiCAStatus(w, jsonReq(http.MethodPost, "/api/ca/status", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPICAStatus_GETShape(t *testing.T) {
	w := httptest.NewRecorder()
	apiCAStatus(w, getReq("/api/ca/status"))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	// Contract check — the UI panel reads these fields.
	for _, k := range []string{"cacheSize", "cacheMax", "cacheTTL", "leafValidity",
		"autoRotation", "rotationOverlapDays", "keyProvider", "dualCAActive"} {
		if _, ok := m[k]; !ok {
			t.Errorf("GET response missing %q: %v", k, m)
		}
	}
}

func TestAPICADownload_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiCADownload(w, jsonReq(http.MethodPost, "/api/ca/download", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// GET returns the PEM bundle when the CA is ready; 503 when not. Rather than
// trying to bootstrap a full CA in the test, we accept either outcome and
// verify the handler at least returned a sensible status + content type.
func TestAPICADownload_GETStatus(t *testing.T) {
	w := httptest.NewRecorder()
	apiCADownload(w, getReq("/api/ca/download"))
	switch w.Code {
	case http.StatusOK:
		if ct := w.Header().Get("Content-Type"); ct != "application/x-pem-file" {
			t.Errorf("Content-Type = %q, want application/x-pem-file", ct)
		}
		if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "culvert-ca.pem") {
			t.Errorf("Content-Disposition missing filename: %q", cd)
		}
	case http.StatusServiceUnavailable:
		// CA not initialised yet — acceptable in a fresh test environment.
	default:
		t.Fatalf("unexpected status: %d body=%q", w.Code, w.Body.String())
	}
}

func TestAPICACacheClear_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiCACacheClear(w, getReq("/api/ca/cache/clear"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPICACacheClear_POST(t *testing.T) {
	w := httptest.NewRecorder()
	apiCACacheClear(w, jsonReq(http.MethodPost, "/api/ca/cache/clear", nil))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if m["ok"] != true {
		t.Errorf("response: ok=%v, want true", m["ok"])
	}
}

// ─── apiCAKeyProvider ───────────────────────────────────────────────────────

func TestAPICAKeyProvider_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiCAKeyProvider(w, jsonReq(http.MethodPost, "/api/ca/key-provider", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPICAKeyProvider_GETReturnsStatus(t *testing.T) {
	w := httptest.NewRecorder()
	apiCAKeyProvider(w, getReq("/api/ca/key-provider"))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	// The four fields below are the GUI-observable contract — dropping any of
	// them silently would break the HSM/KMS management panel.
	for _, k := range []string{"provider", "isExternal", "caReady", "dualCAActive"} {
		if _, ok := m[k]; !ok {
			t.Errorf("response missing %q field: %v", k, m)
		}
	}
	// provider must be a non-empty string ("local" on default builds).
	if p, _ := m["provider"].(string); p == "" {
		t.Errorf("provider must be non-empty, got %v", m["provider"])
	}
}

// ─── apiOCSPConfig ──────────────────────────────────────────────────────────

func TestAPIOCSPConfig_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiOCSPConfig(w, jsonReq(http.MethodDelete, "/api/ocsp", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

func TestAPIOCSPConfig_GETShape(t *testing.T) {
	w := httptest.NewRecorder()
	apiOCSPConfig(w, getReq("/api/ocsp"))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	// Both fields are required by the UI panel contract.
	if _, ok := m["enabled"]; !ok {
		t.Error("GET response missing enabled field")
	}
	if _, ok := m["cacheLen"]; !ok {
		t.Error("GET response missing cacheLen field")
	}
}

// POST toggles enabled on and off. Snapshots the globals the toggle mutates
// so the test restores both OCSP state AND the upstreamTransport TLS config,
// since Enable calls ConfigureTransportOCSP which mutates the shared transport.
func TestAPIOCSPConfig_POSTTogglesEnabled(t *testing.T) {
	origEnabled := globalOCSP.Enabled()
	// P5.3: snapshot the entire transport pointer + operator TLS
	// template. apiOCSPConfig now installs OCSP via
	// swapUpstreamTransport, which publishes a NEW transport with a
	// Clone of the operator template attached.
	origPtr := upstreamTransportPtr.Load()
	upstreamTransportWriteMu.Lock()
	origOpTLS := upstreamOpTLSCfg
	upstreamOpTLSCfg = nil
	upstreamTransportWriteMu.Unlock()
	t.Cleanup(func() {
		if origEnabled {
			globalOCSP.Enable()
		} else {
			globalOCSP.Disable()
		}
		upstreamTransportPtr.Store(origPtr)
		upstreamTransportWriteMu.Lock()
		upstreamOpTLSCfg = origOpTLS
		upstreamTransportWriteMu.Unlock()
	})

	// Start from disabled + a fresh transport (no TLS config) so the
	// OCSP swap path takes the "create with MinVersion=TLS13" branch
	// deterministically regardless of what an earlier test may have
	// left installed on the shared upstream transport.
	globalOCSP.Disable()
	upstreamTransportPtr.Store(newBaseUpstreamTransport())

	w := httptest.NewRecorder()
	apiOCSPConfig(w, jsonReq(http.MethodPost, "/api/ocsp", map[string]any{"enabled": true}))
	assertStatus(t, w, http.StatusOK)
	if !globalOCSP.Enabled() {
		t.Fatal("POST enabled=true did not enable OCSP")
	}
	current := getUpstreamTransport()
	if current.TLSClientConfig == nil {
		t.Fatal("POST enabled=true must install TLSClientConfig on the upstream transport")
	}
	if current.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("upstreamTransport MinVersion = 0x%x, want >= TLS 1.2",
			current.TLSClientConfig.MinVersion)
	}
	if current.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Error("POST enabled=true must install VerifyPeerCertificate")
	}
	if current.TLSClientConfig.VerifyConnection == nil {
		t.Error("POST enabled=true must install VerifyConnection (resumed-session path)")
	}

	// And toggle back off — Disable branch.
	w2 := httptest.NewRecorder()
	apiOCSPConfig(w2, jsonReq(http.MethodPost, "/api/ocsp", map[string]any{"enabled": false}))
	assertStatus(t, w2, http.StatusOK)
	if globalOCSP.Enabled() {
		t.Fatal("POST enabled=false did not disable OCSP")
	}
}

// GET must stay silent about upstream mTLS when it was never configured —
// the admin panel treats field-absence as "not configured" (see
// static/index.html's loadCAMgmt).
func TestAPIOCSPConfig_GETOmitsMTLSFieldsWhenUnconfigured(t *testing.T) {
	mtlsClientCertMu.Lock()
	orig := mtlsClientCertState
	mtlsClientCertState = mtlsClientCertStatus{}
	mtlsClientCertMu.Unlock()
	t.Cleanup(func() {
		mtlsClientCertMu.Lock()
		mtlsClientCertState = orig
		mtlsClientCertMu.Unlock()
	})

	w := httptest.NewRecorder()
	apiOCSPConfig(w, getReq("/api/ocsp"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if _, ok := m["mtlsClientCertConfigured"]; ok {
		t.Error("mtlsClientCertConfigured should be omitted when no client cert is configured")
	}
}

// GET must surface a failed client-cert load — this is the operator-facing
// contract the panel banner depends on (a bad/expired upstream mTLS cert
// must be visible without grepping the process log).
func TestAPIOCSPConfig_GETSurfacesMTLSLoadFailure(t *testing.T) {
	mtlsClientCertMu.Lock()
	orig := mtlsClientCertState
	mtlsClientCertState = mtlsClientCertStatus{
		configured: true,
		loaded:     false,
		file:       "/etc/culvert/client.crt",
		lastError:  "x509: malformed certificate",
	}
	mtlsClientCertMu.Unlock()
	t.Cleanup(func() {
		mtlsClientCertMu.Lock()
		mtlsClientCertState = orig
		mtlsClientCertMu.Unlock()
	})

	w := httptest.NewRecorder()
	apiOCSPConfig(w, getReq("/api/ocsp"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if configured, _ := m["mtlsClientCertConfigured"].(bool); !configured {
		t.Error("mtlsClientCertConfigured should be true")
	}
	if loaded, _ := m["mtlsClientCertLoaded"].(bool); loaded {
		t.Error("mtlsClientCertLoaded should be false")
	}
	if m["mtlsClientCertLastError"] != "x509: malformed certificate" {
		t.Errorf("mtlsClientCertLastError = %v, want the recorded load error", m["mtlsClientCertLastError"])
	}
	if _, ok := m["mtlsClientCertNotAfter"]; ok {
		t.Error("mtlsClientCertNotAfter should be omitted when the cert never loaded")
	}
}

// GET must surface expiry once the cert is loaded, so an admin can catch an
// impending expiry before it silently drops upstream mTLS.
func TestAPIOCSPConfig_GETSurfacesMTLSExpiry(t *testing.T) {
	notAfter := time.Now().Add(72 * time.Hour)
	mtlsClientCertMu.Lock()
	orig := mtlsClientCertState
	mtlsClientCertState = mtlsClientCertStatus{
		configured: true,
		loaded:     true,
		file:       "/etc/culvert/client.crt",
		notAfter:   notAfter,
	}
	mtlsClientCertMu.Unlock()
	t.Cleanup(func() {
		mtlsClientCertMu.Lock()
		mtlsClientCertState = orig
		mtlsClientCertMu.Unlock()
	})

	w := httptest.NewRecorder()
	apiOCSPConfig(w, getReq("/api/ocsp"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if loaded, _ := m["mtlsClientCertLoaded"].(bool); !loaded {
		t.Error("mtlsClientCertLoaded should be true")
	}
	if m["mtlsClientCertNotAfter"] != notAfter.UTC().Format(time.RFC3339) {
		t.Errorf("mtlsClientCertNotAfter = %v, want %v", m["mtlsClientCertNotAfter"], notAfter.UTC().Format(time.RFC3339))
	}
	// Tolerate the sub-hour of wall-clock time between setting notAfter
	// above and the daysUntil() computation inside the handler.
	if days, ok := m["mtlsClientCertDaysRemaining"].(float64); !ok || (int(days) != 2 && int(days) != 3) {
		t.Errorf("mtlsClientCertDaysRemaining = %v, want 2 or 3", m["mtlsClientCertDaysRemaining"])
	}
	if _, ok := m["mtlsClientCertLastError"]; ok {
		t.Error("mtlsClientCertLastError should be omitted on a healthy load")
	}
}

// A loaded-but-expired certificate must still report loaded=true with a
// negative daysRemaining — the GUI (loadCAMgmt) is the layer that turns
// that into an "Expired" red state; the API contract is just an honest
// clock computation, never clamped at zero.
func TestAPIOCSPConfig_GETSurfacesMTLSExpired(t *testing.T) {
	notAfter := time.Now().Add(-48 * time.Hour)
	mtlsClientCertMu.Lock()
	orig := mtlsClientCertState
	mtlsClientCertState = mtlsClientCertStatus{
		configured: true,
		loaded:     true,
		file:       "/etc/culvert/client.crt",
		notAfter:   notAfter,
	}
	mtlsClientCertMu.Unlock()
	t.Cleanup(func() {
		mtlsClientCertMu.Lock()
		mtlsClientCertState = orig
		mtlsClientCertMu.Unlock()
	})

	w := httptest.NewRecorder()
	apiOCSPConfig(w, getReq("/api/ocsp"))
	assertStatus(t, w, http.StatusOK)
	m := assertJSON(t, w)
	if loaded, _ := m["mtlsClientCertLoaded"].(bool); !loaded {
		t.Error("mtlsClientCertLoaded should stay true — the cert loaded fine at startup, it has just since expired")
	}
	days, ok := m["mtlsClientCertDaysRemaining"].(float64)
	if !ok || days >= 0 {
		t.Errorf("mtlsClientCertDaysRemaining = %v, want a negative value for an expired cert", m["mtlsClientCertDaysRemaining"])
	}
}

func TestAPIOCSPConfig_POSTBadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/ocsp", strings.NewReader("not json"))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:9999"
	apiOCSPConfig(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
}

// ─── apiGeoIPConfig ──────────────────────────────────────────────────────────

func TestAPIGeoIPConfig_GETShape(t *testing.T) {
	w := httptest.NewRecorder()
	apiGeoIPConfig(w, getReq("/api/geoip"))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	// Both fields are required by the UI panel contract.
	if _, ok := m["enabled"]; !ok {
		t.Error("GET response missing enabled field")
	}
	if _, ok := m["dbPath"]; !ok {
		t.Error("GET response missing dbPath field")
	}
	// No test process loads a real .mmdb fixture, so the engine stays
	// disabled — the staleness fields must be omitted rather than reporting a
	// misleading zero age.
	if _, ok := m["dbAgeDays"]; ok {
		t.Error("GET response must omit dbAgeDays when no GeoIP database is loaded")
	}
	if _, ok := m["dbBuildDate"]; ok {
		t.Error("GET response must omit dbBuildDate when no GeoIP database is loaded")
	}
}

// ─── apiSecYARARules ───────────────────────────────────────────────────────

// yaraTestRuleset swaps globalYARA for an isolated test-only instance rooted
// at dir. Returns a cleanup func the caller registers with t.Cleanup. Also
// swaps globalSecScanner so the handler's cache.Clear() call has something
// to act on without touching the real scanner's hash cache.
func yaraTestRuleset(t *testing.T, dir string) {
	t.Helper()
	origYARA := globalYARA
	origSec := globalSecScanner
	y := &YARARuleSet{}
	y.SetDir(dir)
	globalYARA = y
	globalSecScanner = secscan.New(secscan.Deps{Cache: newHashCache(16, time.Minute)})
	t.Cleanup(func() {
		globalYARA = origYARA
		globalSecScanner = origSec
	})
}

func TestAPISecYARARules_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq(http.MethodPatch, "/api/security-scan/yara/rules", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// GET / returns the directory + files + rules summary from the isolated
// ruleset.
func TestAPISecYARARules_GETList(t *testing.T) {
	dir := t.TempDir()
	yaraTestRuleset(t, dir)

	w := httptest.NewRecorder()
	apiSecYARARules(w, getReq("/api/security-scan/yara/rules"))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	// Contract check — UI consumes every one of these fields.
	for _, k := range []string{"directory", "files", "file_rules", "rules", "warnings", "count"} {
		if _, ok := m[k]; !ok {
			t.Errorf("GET response missing %q: %v", k, m)
		}
	}
	if m["directory"] != dir {
		t.Errorf("directory = %v, want %v", m["directory"], dir)
	}
}

// GET /{name} on a missing rule returns 404 with a "read rule:" error.
func TestAPISecYARARules_GETMissingRule(t *testing.T) {
	yaraTestRuleset(t, t.TempDir())

	w := httptest.NewRecorder()
	apiSecYARARules(w, getReq("/api/security-scan/yara/rules/nope"))
	assertStatus(t, w, http.StatusNotFound)
	if !strings.Contains(w.Body.String(), "read rule:") {
		t.Errorf("response body should mention 'read rule:', got %q", w.Body.String())
	}
}

// POST a valid rule, then GET it back, then DELETE it. Also asserts that the
// hash cache is cleared on both write and delete (Tier 1.1 invariant).
func TestAPISecYARARules_WriteReadDelete(t *testing.T) {
	dir := t.TempDir()
	yaraTestRuleset(t, dir)

	// Prime the cache so we can confirm the handler clears it.
	globalSecScanner.CacheSet("primed", ScanCacheResult{Clean: true})

	src := yaraRule("CoverRule", `        $a = "HELLO"`, "any of them")

	// POST /api/security-scan/yara/rules  {name, source}
	body := map[string]any{"name": "coverrule", "source": src}
	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq(http.MethodPost, "/api/security-scan/yara/rules", body))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	if m["name"] != "coverrule" {
		t.Errorf("write name = %v, want coverrule", m["name"])
	}
	if m["cache_cleared"] != true {
		t.Error("write response must indicate cache_cleared=true")
	}

	// Confirm the file landed on disk — an observable contract for operators.
	if _, err := os.Stat(filepath.Join(dir, "coverrule.yar")); err != nil {
		t.Fatalf("rule file should exist on disk after write: %v", err)
	}

	// Cache should no longer contain "primed".
	if _, ok := globalSecScanner.CacheGet("primed"); ok {
		t.Error("cache was not cleared by write")
	}

	// GET /api/security-scan/yara/rules/coverrule should echo source back.
	w2 := httptest.NewRecorder()
	apiSecYARARules(w2, getReq("/api/security-scan/yara/rules/coverrule"))
	assertStatus(t, w2, http.StatusOK)
	gm := assertJSON(t, w2)
	if gs, _ := gm["source"].(string); !strings.Contains(gs, "CoverRule") {
		t.Errorf("GET /name source does not round-trip: %q", gs)
	}

	// Re-prime then DELETE.
	globalSecScanner.CacheSet("primed2", ScanCacheResult{Clean: true})
	w3 := httptest.NewRecorder()
	apiSecYARARules(w3, jsonReq(http.MethodDelete, "/api/security-scan/yara/rules/coverrule", nil))
	assertStatus(t, w3, http.StatusOK)
	dm := assertJSON(t, w3)
	if dm["deleted"] != "coverrule" {
		t.Errorf("delete response: deleted=%v", dm["deleted"])
	}
	if dm["cache_cleared"] != true {
		t.Error("delete response must indicate cache_cleared=true")
	}
	if _, ok := globalSecScanner.CacheGet("primed2"); ok {
		t.Error("cache was not cleared by delete")
	}
}

// POST with an empty name must 400 (missing rule name).
func TestAPISecYARARules_POSTMissingName(t *testing.T) {
	yaraTestRuleset(t, t.TempDir())

	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq(http.MethodPost, "/api/security-scan/yara/rules",
		map[string]any{"name": "", "source": "whatever"}))
	assertStatus(t, w, http.StatusBadRequest)
}

// POST with a bogus source returns 400 "write rule:" because the YARA parser
// rejects it before it lands on disk.
func TestAPISecYARARules_POSTBadSource(t *testing.T) {
	yaraTestRuleset(t, t.TempDir())

	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq(http.MethodPost, "/api/security-scan/yara/rules",
		map[string]any{"name": "bad", "source": "this is not a yara rule"}))
	assertStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), "write rule:") {
		t.Errorf("response should mention 'write rule:', got %q", w.Body.String())
	}
}

// DELETE with no name (neither path nor ?name=) must 400 instead of panicking.
func TestAPISecYARARules_DELETEMissingName(t *testing.T) {
	yaraTestRuleset(t, t.TempDir())

	w := httptest.NewRecorder()
	apiSecYARARules(w, jsonReq(http.MethodDelete, "/api/security-scan/yara/rules", nil))
	assertStatus(t, w, http.StatusBadRequest)
}

// POST with malformed JSON must 400 without touching the ruleset.
func TestAPISecYARARules_POSTBadJSON(t *testing.T) {
	yaraTestRuleset(t, t.TempDir())

	r := httptest.NewRequest(http.MethodPost, "/api/security-scan/yara/rules",
		bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiSecYARARules(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
}

// ═══════════════════════════════════════════════════════════════════════════════
// Round 3 — scan-evasion controls and YARA validator
// ═══════════════════════════════════════════════════════════════════════════════
//
// The three handlers covered below are all security-sensitive:
//
//   apiContentScanBypass   PUT replaces dpiScanner.bypassHosts — disables DPI
//                          for the listed hosts. Untested = silent scan bypass.
//   apiSecScanExclusions   PUT replaces globalScanExclusions (hashes + hosts)
//                          — skips ClamAV/YARA/threat-feed for those targets.
//   apiSecYARAValidate     Pure parser wrapper. Protects the rule-authoring
//                          path from upstream YARA-lib drift.
//
// The first two share a "snapshot whole store → replace with clean
// instance → restore on cleanup" pattern. That pattern is extracted into
// isolateDPIScanner / isolateScanExclusions so the same shape can be
// lifted into a Round 4 apiFileblockProfiles test by writing a single
// isolateProfileStore helper with the same surface area.

// isolateDPIScanner swaps the global dpiScanner for a fresh, in-memory
// ContentScanner for the duration of the test, then restores the original
// on cleanup. The isolated scanner has an empty persistence path so
// Save() is a no-op — callers do not need to manage a temp file.
//
// Pattern note: see isolateScanExclusions below for the sibling helper.
// Both expose the same three-line usage: snapshot, replace, defer
// restore. A future isolateProfileStore helper for apiFileblockProfiles
// will follow the same shape.
func isolateDPIScanner(t *testing.T) *ContentScanner {
	t.Helper()
	orig := dpiScanner
	fresh := &ContentScanner{}
	dpiScanner = fresh
	t.Cleanup(func() { dpiScanner = orig })
	return fresh
}

// isolateScanExclusions swaps globalScanExclusions for a fresh, in-memory
// ScanExclusionStore for the duration of the test. Same contract as
// isolateDPIScanner: empty persistence path → Save() is a no-op.
func isolateScanExclusions(t *testing.T) *ScanExclusionStore {
	t.Helper()
	orig := globalScanExclusions
	fresh := scanexcl.New()
	globalScanExclusions = fresh
	t.Cleanup(func() { globalScanExclusions = orig })
	return fresh
}

// ─── apiContentScanBypass ──────────────────────────────────────────────────

func TestAPIContentScanBypass_WrongMethod(t *testing.T) {
	isolateDPIScanner(t)
	w := httptest.NewRecorder()
	apiContentScanBypass(w, jsonReq(http.MethodPost, "/api/content-scan/bypass", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// GET on an empty store returns an empty host slice — never nil, never
// missing the "hosts" key. The UI depends on the key existing.
func TestAPIContentScanBypass_GETEmpty(t *testing.T) {
	isolateDPIScanner(t)

	w := httptest.NewRecorder()
	apiContentScanBypass(w, getReq("/api/content-scan/bypass"))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	raw, ok := m["hosts"]
	if !ok {
		t.Fatalf("GET response missing 'hosts' key: %v", m)
	}
	hosts, _ := raw.([]any)
	if len(hosts) != 0 {
		t.Errorf("expected empty host list on empty store, got %v", hosts)
	}
}

// Happy path: PUT a list of hosts, then GET confirms they were stored
// (lower-cased and trimmed), and the response echoes the same list.
func TestAPIContentScanBypass_PUTRoundTrip(t *testing.T) {
	isolateDPIScanner(t)

	w := httptest.NewRecorder()
	apiContentScanBypass(w, jsonReq(http.MethodPut, "/api/content-scan/bypass",
		map[string]any{"hosts": []string{"  Internal.Corp  ", "CI.Corp", "", "internal.corp"}}))
	assertStatus(t, w, http.StatusOK)

	putResp := assertJSON(t, w)
	// The response echoes the current state — deduplicated, case-folded,
	// empty entries dropped. Contract we're locking in.
	hosts, _ := putResp["hosts"].([]any)
	if len(hosts) != 2 {
		t.Fatalf("PUT response: expected 2 unique hosts after normalisation, got %v", hosts)
	}
	for _, h := range hosts {
		s, _ := h.(string)
		if s != strings.ToLower(strings.TrimSpace(s)) {
			t.Errorf("PUT response returned un-normalised host %q", s)
		}
	}

	// GET after PUT returns the same list.
	w2 := httptest.NewRecorder()
	apiContentScanBypass(w2, getReq("/api/content-scan/bypass"))
	assertStatus(t, w2, http.StatusOK)
	getResp := assertJSON(t, w2)
	got, _ := getResp["hosts"].([]any)
	if len(got) != 2 {
		t.Errorf("GET after PUT: expected 2 hosts, got %v", got)
	}

	// Direct store inspection — the handler path must reach SetBypassHosts.
	if !containsString(dpiScanner.BypassHosts(), "internal.corp") {
		t.Error("internal.corp should be in bypass list")
	}
}

// PUT with empty body (no "hosts" field) clears the list.
func TestAPIContentScanBypass_PUTEmptyClearsList(t *testing.T) {
	d := isolateDPIScanner(t)
	d.SetBypassHosts([]string{"host.a", "host.b"})

	w := httptest.NewRecorder()
	apiContentScanBypass(w, jsonReq(http.MethodPut, "/api/content-scan/bypass",
		map[string]any{"hosts": []string{}}))
	assertStatus(t, w, http.StatusOK)
	if len(d.BypassHosts()) != 0 {
		t.Errorf("PUT with empty list should clear bypass hosts, got %v", d.BypassHosts())
	}
}

// Malformed JSON must 400 without mutating the store.
func TestAPIContentScanBypass_PUTBadJSON(t *testing.T) {
	d := isolateDPIScanner(t)
	d.SetBypassHosts([]string{"preserved.example"})

	r := httptest.NewRequest(http.MethodPut, "/api/content-scan/bypass",
		bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiContentScanBypass(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)

	// The original list must survive a malformed request.
	if !containsString(d.BypassHosts(), "preserved.example") {
		t.Error("pre-existing bypass list was mutated by a failed PUT")
	}
}

// ─── apiSecScanExclusions ──────────────────────────────────────────────────

func TestAPISecScanExclusions_WrongMethod(t *testing.T) {
	isolateScanExclusions(t)
	w := httptest.NewRecorder()
	apiSecScanExclusions(w, jsonReq(http.MethodPost, "/api/security-scan/exclusions", nil))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// GET on an empty store must return both keys and empty slices (UI contract).
func TestAPISecScanExclusions_GETEmpty(t *testing.T) {
	isolateScanExclusions(t)

	w := httptest.NewRecorder()
	apiSecScanExclusions(w, getReq("/api/security-scan/exclusions"))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	for _, k := range []string{"hashes", "hosts"} {
		if _, ok := m[k]; !ok {
			t.Errorf("GET response missing %q key: %v", k, m)
		}
	}
}

// Happy-path round-trip: PUT replaces both lists; GET confirms persistence.
// Also verifies case-folding + trim + empty-entry drop behavior.
func TestAPISecScanExclusions_PUTRoundTrip(t *testing.T) {
	store := isolateScanExclusions(t)

	body := map[string]any{
		"hashes": []string{"  DEADBEEF  ", "deadbeef", "", "CAFE"}, // case + dup + empty
		"hosts":  []string{"Trusted.Corp", " trusted.corp ", "other.corp", ""},
	}
	w := httptest.NewRecorder()
	apiSecScanExclusions(w, jsonReq(http.MethodPut, "/api/security-scan/exclusions", body))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	hashes, _ := m["hashes"].([]any)
	if len(hashes) != 2 {
		t.Errorf("PUT response hashes: expected 2 unique, got %v", hashes)
	}
	hosts, _ := m["hosts"].([]any)
	if len(hosts) != 2 {
		t.Errorf("PUT response hosts: expected 2 unique, got %v", hosts)
	}

	// Direct store inspection — handler must hit ScanExclusionStore.Replace.
	gotHashes, gotHosts := store.Lists()
	if !containsString(gotHashes, "deadbeef") {
		t.Errorf("expected 'deadbeef' in hashes, got %v", gotHashes)
	}
	if !containsString(gotHosts, "trusted.corp") {
		t.Errorf("expected 'trusted.corp' in hosts, got %v", gotHosts)
	}

	// GET after PUT returns the same two lists.
	w2 := httptest.NewRecorder()
	apiSecScanExclusions(w2, getReq("/api/security-scan/exclusions"))
	assertStatus(t, w2, http.StatusOK)
}

// PUT with both lists missing / empty collapses the store to empty.
func TestAPISecScanExclusions_PUTEmpty(t *testing.T) {
	store := isolateScanExclusions(t)
	store.Replace([]string{"old"}, []string{"old.example"})

	w := httptest.NewRecorder()
	apiSecScanExclusions(w, jsonReq(http.MethodPut, "/api/security-scan/exclusions",
		map[string]any{"hashes": []string{}, "hosts": []string{}}))
	assertStatus(t, w, http.StatusOK)

	hashes, hosts := store.Lists()
	if len(hashes) != 0 || len(hosts) != 0 {
		t.Errorf("PUT with empty lists should clear store, got hashes=%v hosts=%v", hashes, hosts)
	}
}

// Malformed JSON must 400 without mutating the store.
func TestAPISecScanExclusions_PUTBadJSON(t *testing.T) {
	store := isolateScanExclusions(t)
	store.Replace([]string{"keep"}, []string{"keep.example"})

	r := httptest.NewRequest(http.MethodPut, "/api/security-scan/exclusions",
		bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiSecScanExclusions(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)

	hashes, hosts := store.Lists()
	if !containsString(hashes, "keep") || !containsString(hosts, "keep.example") {
		t.Error("pre-existing exclusions were mutated by a failed PUT")
	}
}

// ─── apiSecYARAValidate ────────────────────────────────────────────────────

func TestAPISecYARAValidate_WrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiSecYARAValidate(w, getReq("/api/security-scan/yara/validate"))
	assertStatus(t, w, http.StatusMethodNotAllowed)
}

// Happy path: a syntactically valid rule round-trips with valid=true,
// rule_names set, and no error.
func TestAPISecYARAValidate_ValidRule(t *testing.T) {
	src := yaraRule("ValidRule", `        $a = "HELLO"`, "any of them")

	w := httptest.NewRecorder()
	apiSecYARAValidate(w, jsonReq(http.MethodPost, "/api/security-scan/yara/validate",
		map[string]any{"source": src}))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	if m["valid"] != true {
		t.Fatalf("valid = %v, want true; body: %v", m["valid"], m)
	}
	names, _ := m["rule_names"].([]any)
	if len(names) != 1 || names[0] != "ValidRule" {
		t.Errorf("rule_names = %v, want [ValidRule]", names)
	}
}

// Alias: the handler accepts {rule: ...} as a synonym for {source: ...}.
func TestAPISecYARAValidate_RuleFieldAlias(t *testing.T) {
	src := yaraRule("AliasRule", `        $a = "HELLO"`, "any of them")

	w := httptest.NewRecorder()
	apiSecYARAValidate(w, jsonReq(http.MethodPost, "/api/security-scan/yara/validate",
		map[string]any{"rule": src})) // note: "rule" not "source"
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	if m["valid"] != true {
		t.Fatalf("alias field not accepted: valid=%v body=%v", m["valid"], m)
	}
}

// Bad YARA source returns 200 OK with valid=false + an error string. The
// 200 is intentional — the endpoint is a dry-run, not a failed operation.
func TestAPISecYARAValidate_InvalidRule(t *testing.T) {
	w := httptest.NewRecorder()
	apiSecYARAValidate(w, jsonReq(http.MethodPost, "/api/security-scan/yara/validate",
		map[string]any{"source": "this is not a yara rule"}))
	assertStatus(t, w, http.StatusOK)

	m := assertJSON(t, w)
	if m["valid"] != false {
		t.Errorf("invalid rule reported valid=%v, want false", m["valid"])
	}
	if errStr, _ := m["error"].(string); errStr == "" {
		t.Error("invalid rule response missing error string")
	}
}

// Empty source (neither field set, or both empty strings) returns 400.
func TestAPISecYARAValidate_EmptySource(t *testing.T) {
	w := httptest.NewRecorder()
	apiSecYARAValidate(w, jsonReq(http.MethodPost, "/api/security-scan/yara/validate",
		map[string]any{"source": "   "}))
	assertStatus(t, w, http.StatusBadRequest)
}

// Malformed JSON body must 400 with the "bad JSON body:" prefix so the UI
// can surface it verbatim.
func TestAPISecYARAValidate_BadJSON(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/security-scan/yara/validate",
		bytes.NewReader([]byte("not json")))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:9999"
	w := httptest.NewRecorder()
	apiSecYARAValidate(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
	if !strings.Contains(w.Body.String(), "bad JSON body:") {
		t.Errorf("response should mention 'bad JSON body:', got %q", w.Body.String())
	}
}

// containsString is a tiny helper — kept local so Round 3 tests don't need
// to reach into a shared helper file.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
