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
	origTLSConf := upstreamTransport.TLSClientConfig
	t.Cleanup(func() {
		if origEnabled {
			globalOCSP.Enable()
		} else {
			globalOCSP.Disable()
		}
		upstreamTransport.TLSClientConfig = origTLSConf
	})

	// Start from disabled + nil TLS config so ConfigureTransportOCSP takes the
	// "create with MinVersion=TLS13" branch deterministically regardless of
	// what an earlier test (TestConfigureTransportOCSP in ocsp_test.go) may
	// have left installed on the shared upstreamTransport.
	globalOCSP.Disable()
	upstreamTransport.TLSClientConfig = nil

	w := httptest.NewRecorder()
	apiOCSPConfig(w, jsonReq(http.MethodPost, "/api/ocsp", map[string]any{"enabled": true}))
	assertStatus(t, w, http.StatusOK)
	if !globalOCSP.Enabled() {
		t.Fatal("POST enabled=true did not enable OCSP")
	}
	if upstreamTransport.TLSClientConfig == nil {
		t.Fatal("POST enabled=true must install TLSClientConfig on upstreamTransport")
	}
	if upstreamTransport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Errorf("upstreamTransport MinVersion = 0x%x, want >= TLS 1.2",
			upstreamTransport.TLSClientConfig.MinVersion)
	}
	if upstreamTransport.TLSClientConfig.VerifyPeerCertificate == nil {
		t.Error("POST enabled=true must install VerifyPeerCertificate")
	}
	if upstreamTransport.TLSClientConfig.VerifyConnection == nil {
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

func TestAPIOCSPConfig_POSTBadJSON(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/ocsp", strings.NewReader("not json"))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "127.0.0.1:9999"
	apiOCSPConfig(w, adminCtx(r))
	assertStatus(t, w, http.StatusBadRequest)
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
	globalSecScanner = &SecurityScanner{cache: newHashCache(16, time.Minute)}
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
	globalSecScanner.cache.Set("primed", ScanCacheResult{Clean: true})

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
	if _, ok := globalSecScanner.cache.Get("primed"); ok {
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
	globalSecScanner.cache.Set("primed2", ScanCacheResult{Clean: true})
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
	if _, ok := globalSecScanner.cache.Get("primed2"); ok {
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

