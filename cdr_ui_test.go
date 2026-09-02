package main

// Phase 2c — tests for /api/cdr/* admin API handlers.
//
// Auth is bypassed by injecting the RoleAdmin/RoleViewer context key
// directly on the test request — this is the same pattern used elsewhere
// in the test suite (see edge_audit_test.go).

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ─── Helpers ───────────────────────────────────────────────────────────────

// newAdminRequest builds an *http.Request with RoleAdmin injected into the
// context — matches what uiAuthMiddleware does for an authenticated admin.
// Uses NewRequestWithContext per noctx lint (propagates cancellation).
func newAdminRequest(method, target string, body []byte) *http.Request {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	var bodyReader *bytes.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	var r *http.Request
	if bodyReader != nil {
		r = httptest.NewRequestWithContext(ctx, method, target, bodyReader)
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequestWithContext(ctx, method, target, nil)
	}
	return r
}

// newViewerRequest mirrors newAdminRequest for RoleViewer.  Only used
// with GET today; parameterised on method for future read-style ops.
func newViewerRequest(target string) *http.Request {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	return httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
}

// resetCDRState wipes process-wide CDR singletons between tests.
func resetCDRState(t *testing.T) {
	t.Helper()
	shutdownCDRClient()
	cdrPool.shutdown()
	cdrInstances = &CDRInstanceRegistry{}
	cdrPolicyStore = &CDRPolicyStore{}
	cdrEnrollReceipts = &cdrEnrollReceiptStore{}
	t.Cleanup(func() {
		shutdownCDRClient()
		cdrPool.shutdown()
		cdrInstances = &CDRInstanceRegistry{}
		cdrPolicyStore = &CDRPolicyStore{}
		cdrEnrollReceipts = &cdrEnrollReceiptStore{}
	})
}

// ─── /api/cdr/config ───────────────────────────────────────────────────────

func TestApiCDRConfig_ReturnsRuntimeState(t *testing.T) {
	resetCDRState(t)
	// Wire a config as though initCDRClient had been called with it.
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{
		Enabled: true, Endpoint: "sluice:8443",
		FailMode: "open", DefaultProfile: "default", DefaultMode: "ENFORCE",
		MaxFileSizeMB: 50,
	}
	cdrClientMu.Unlock()

	w := httptest.NewRecorder()
	apiCDRConfig(w, newViewerRequest("/api/cdr/config"))

	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["enabled"] != true || got["endpoint"] != "sluice:8443" {
		t.Fatalf("unexpected body: %+v", got)
	}
	if got["failOpen"] != true {
		t.Fatalf("failOpen expected true for fail-mode=open, got %v", got["failOpen"])
	}
}

func TestApiCDRConfig_RejectsWrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiCDRConfig(w, newAdminRequest(http.MethodPost, "/api/cdr/config", []byte(`{}`)))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", w.Code)
	}
}

// redirectSentinelToTempDir points cdrRuntimeEnabledPath at a
// test-owned tmp file so the suite doesn't require root or /data to
// exist.  Restores the original path on cleanup.
func redirectSentinelToTempDir(t *testing.T) {
	t.Helper()
	orig := cdrRuntimeEnabledPath
	cdrRuntimeEnabledPath = filepath.Join(t.TempDir(), "cdr_enabled")
	t.Cleanup(func() { cdrRuntimeEnabledPath = orig })
}

// TestApiCDRConfigToggle_OnThenOff — PUT flips the runtime-enable
// sentinel, persists to disk, and surfaces in GET.
func TestApiCDRConfigToggle_OnThenOff(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)

	// GET baseline — should be disabled.
	w := httptest.NewRecorder()
	apiCDRConfig(w, newAdminRequest(http.MethodGet, "/api/cdr/config", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET status %d", w.Code)
	}
	var before map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &before)
	if before["enabled"] == true {
		t.Skip("pre-existing runtime sentinel — skipping toggle test")
	}

	// PUT enable.
	w = httptest.NewRecorder()
	apiCDRConfig(w, newAdminRequest(http.MethodPut, "/api/cdr/config", []byte(`{"enabled":true}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT enable status %d; body=%s", w.Code, w.Body.String())
	}
	if !cdrActiveConfig().Enabled {
		t.Fatal("runtime flag did not flip to enabled")
	}

	// PUT disable.
	w = httptest.NewRecorder()
	apiCDRConfig(w, newAdminRequest(http.MethodPut, "/api/cdr/config", []byte(`{"enabled":false}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("PUT disable status %d; body=%s", w.Code, w.Body.String())
	}
	if cdrActiveConfig().Enabled {
		t.Fatal("runtime flag did not flip back to disabled")
	}
}

func TestApiCDRConfigToggle_RequiresAdmin(t *testing.T) {
	w := httptest.NewRecorder()
	apiCDRConfig(w, newViewerRequest("/api/cdr/config"))
	if w.Code != http.StatusOK {
		t.Fatalf("viewer GET should succeed, got %d", w.Code)
	}
	// Viewer PUT should be refused by requireRole (403).  Build a
	// viewer-context PUT manually since newViewerRequest is GET-only.
	r := httptest.NewRequestWithContext(
		context.WithValue(context.Background(), uiRoleKey{}, RoleViewer),
		http.MethodPut, "/api/cdr/config", bytes.NewReader([]byte(`{"enabled":true}`)))
	r.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	apiCDRConfig(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer PUT should be forbidden; got %d", w.Code)
	}
}

func TestApiCDRConfigToggle_InvalidJSON(t *testing.T) {
	w := httptest.NewRecorder()
	apiCDRConfig(w, newAdminRequest(http.MethodPut, "/api/cdr/config", []byte(`{broken`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("broken JSON status %d", w.Code)
	}
}

// TestCDRRuntimeEnabled_SentinelLifecycle — setCDRRuntimeEnabled
// write/remove is idempotent and observable via cdrRuntimeEnabled.
func TestCDRRuntimeEnabled_SentinelLifecycle(t *testing.T) {
	redirectSentinelToTempDir(t)
	if err := setCDRRuntimeEnabled(true); err != nil {
		t.Fatalf("cannot write %s: %v", cdrRuntimeEnabledPath, err)
	}
	t.Cleanup(func() { _ = setCDRRuntimeEnabled(false) })

	if !cdrRuntimeEnabled() {
		t.Fatal("sentinel should exist after setCDRRuntimeEnabled(true)")
	}
	if err := setCDRRuntimeEnabled(false); err != nil {
		t.Fatal(err)
	}
	if cdrRuntimeEnabled() {
		t.Fatal("sentinel should be gone after setCDRRuntimeEnabled(false)")
	}
	// Double-off is a no-op.
	if err := setCDRRuntimeEnabled(false); err != nil {
		t.Fatalf("double-off should be idempotent: %v", err)
	}
}

// ─── /api/cdr/instances ────────────────────────────────────────────────────

func TestApiCDRInstances_List(t *testing.T) {
	resetCDRState(t)
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "a", Endpoint: "sluice:8443"})
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "b", Endpoint: "sluice-2:8443"})

	w := httptest.NewRecorder()
	apiCDRInstances(w, newViewerRequest("/api/cdr/instances"))

	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["count"].(float64) != 2 {
		t.Fatalf("count = %v", got["count"])
	}
}

// TestApiCDRInstances_ExposesBreakerState verifies the GUI's "CB state"
// column (previously hard-coded to "-") gets real circuit-breaker data:
// an admin should see WHY the proxy is routing around a misbehaving
// Sluice instance without needing Prometheus or SSH.
func TestApiCDRInstances_ExposesBreakerState(t *testing.T) {
	resetCDRState(t)
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "tripped", Endpoint: "sluice:8443"})
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "unpooled", Endpoint: "sluice-2:8443"})

	breaker := newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 2})
	breaker.OnFailure()
	breaker.OnFailure()
	cdrPool.replace([]*cdrPooledClient{{Name: "tripped", Breaker: breaker}})

	w := httptest.NewRecorder()
	apiCDRInstances(w, newViewerRequest("/api/cdr/instances"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Instances []map[string]any `json:"instances"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var tripped, unpooled map[string]any
	for _, inst := range got.Instances {
		switch inst["name"] {
		case "tripped":
			tripped = inst
		case "unpooled":
			unpooled = inst
		}
	}
	if tripped == nil || unpooled == nil {
		t.Fatalf("missing expected instances: %+v", got.Instances)
	}
	if tripped["cbState"] != "open" {
		t.Fatalf("cbState = %v, want open", tripped["cbState"])
	}
	if tripped["cbConsecFails"].(float64) != 2 {
		t.Fatalf("cbConsecFails = %v, want 2", tripped["cbConsecFails"])
	}
	if tripped["cbTotalOpens"].(float64) != 1 {
		t.Fatalf("cbTotalOpens = %v, want 1", tripped["cbTotalOpens"])
	}
	// An instance not (yet) in the live pool must not fabricate breaker
	// state — the UI treats a missing cbState as "-".
	if _, ok := unpooled["cbState"]; ok {
		t.Fatalf("unpooled instance should not have cbState: %v", unpooled["cbState"])
	}
}

func TestApiCDRInstances_DeleteRemovesRegistryEntry(t *testing.T) {
	resetCDRState(t)
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "live", Endpoint: "sluice:8443"})

	w := httptest.NewRecorder()
	apiCDRInstances(w, newAdminRequest(http.MethodDelete, "/api/cdr/instances?name=live", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	if len(cdrInstances.List()) != 0 {
		t.Fatalf("instance not removed")
	}
}

func TestApiCDRInstances_DeleteMissingReturns404(t *testing.T) {
	resetCDRState(t)
	w := httptest.NewRecorder()
	apiCDRInstances(w, newAdminRequest(http.MethodDelete, "/api/cdr/instances?name=ghost", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
}

func TestApiCDRInstances_DeleteRequiresName(t *testing.T) {
	w := httptest.NewRecorder()
	apiCDRInstances(w, newAdminRequest(http.MethodDelete, "/api/cdr/instances", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
}

// ─── /api/cdr/instances/enroll ─────────────────────────────────────────────

func TestApiCDREnroll_RejectsInvalidInputs(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"empty", `{}`},
		{"missing endpoint", `{"name":"x","token":"tok","serverFingerprint":"fp"}`},
		{"missing token", `{"name":"x","endpoint":"host:1","serverFingerprint":"fp"}`},
		{"missing fingerprint", `{"name":"x","endpoint":"host:1","token":"tok"}`},
		{"path traversal in name", `{"name":"../evil","endpoint":"host:1","token":"tok","serverFingerprint":"fp"}`},
		{"slash in name", `{"name":"a/b","endpoint":"host:1","token":"tok","serverFingerprint":"fp"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", []byte(c.body)))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestApiCDREnroll_RejectsDuplicateName(t *testing.T) {
	resetCDRState(t)
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "dup", Endpoint: "sluice:8443"})

	body := `{"name":"dup","endpoint":"h:1","token":"t","serverFingerprint":"fp"}`
	w := httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", []byte(body)))
	if w.Code != http.StatusConflict {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
}

func TestApiCDREnroll_RejectsWrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	apiCDREnroll(w, newAdminRequest(http.MethodGet, "/api/cdr/instances/enroll", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", w.Code)
	}
}

// ─── /api/cdr/policies ─────────────────────────────────────────────────────

func TestApiCDRPolicies_ListEmpty(t *testing.T) {
	resetCDRState(t)
	w := httptest.NewRecorder()
	apiCDRPolicies(w, newViewerRequest("/api/cdr/policies"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d", w.Code)
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["count"].(float64) != 0 {
		t.Fatalf("count = %v", got["count"])
	}
}

func TestApiCDRPolicies_AddThenList(t *testing.T) {
	resetCDRState(t)
	body := `{"name":"vip-monitor","priority":100,"sourceGroup":"vip","profileName":"default","mode":"BYPASS_WITH_REPORT"}`
	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", []byte(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("POST status %d; body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	apiCDRPolicies(w, newViewerRequest("/api/cdr/policies"))
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["count"].(float64) != 1 {
		t.Fatalf("count after add = %v", got["count"])
	}
}

func TestApiCDRPolicies_AddRejectsEmptyName(t *testing.T) {
	resetCDRState(t)
	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", []byte(`{"priority":50,"mode":"ENFORCE"}`)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
}

func TestApiCDRPolicies_AddRejectsInvalidMode(t *testing.T) {
	resetCDRState(t)
	body := `{"name":"bad","priority":50,"mode":"AUDIT"}`
	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodPost, "/api/cdr/policies", []byte(body)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
}

func TestApiCDRPolicies_Delete(t *testing.T) {
	resetCDRState(t)
	_, _ = cdrPolicyStore.Add(CDRPolicyRule{Name: "tmp", Priority: 50, Mode: "ENFORCE"})

	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete, "/api/cdr/policies?name=tmp", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	if len(cdrPolicyStore.List()) != 0 {
		t.Fatalf("rule not removed")
	}
}

func TestApiCDRPolicies_DeleteMissingReturns404(t *testing.T) {
	resetCDRState(t)
	w := httptest.NewRecorder()
	apiCDRPolicies(w, newAdminRequest(http.MethodDelete, "/api/cdr/policies?name=ghost", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}

// ─── /api/cdr/health ───────────────────────────────────────────────────────

func TestApiCDRHealth_NoClientReturns503(t *testing.T) {
	resetCDRState(t)
	cdrHealthMu.Lock()
	cdrHealthLast = nil
	cdrHealthMu.Unlock()

	w := httptest.NewRecorder()
	apiCDRHealth(w, newViewerRequest("/api/cdr/health"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
}

func TestApiCDRHealth_CachedSnapshotReturned(t *testing.T) {
	resetCDRState(t)
	cdrHealthMu.Lock()
	cdrHealthLast = &pb.HealthResponse{
		Healthy: true, Version: "v0.1.0",
		Profiles: []*pb.Profile{{Name: "default", Description: "baseline"}},
	}
	cdrHealthMu.Unlock()
	t.Cleanup(clearCDRHealth)

	w := httptest.NewRecorder()
	apiCDRHealth(w, newViewerRequest("/api/cdr/health"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["version"] != "v0.1.0" {
		t.Fatalf("version = %v", got["version"])
	}
	profiles, ok := got["profiles"].([]any)
	if !ok || len(profiles) != 1 {
		t.Fatalf("profiles = %v", got["profiles"])
	}
}

// TestApiCDRHealth_StaleCacheSurfacesConsecutiveFailures pins the GUI
// blind-spot fix: while the poller is failing but hasn't yet cleared the
// cache (< cdrHealthFailStaleAfter), the response must still say so via
// consecutiveFailures/liveHealthy, instead of silently reporting the old
// "healthy: true" snapshot with no sign anything is degraded.
func TestApiCDRHealth_StaleCacheSurfacesConsecutiveFailures(t *testing.T) {
	resetCDRState(t)
	cdrHealthMu.Lock()
	cdrHealthLast = &pb.HealthResponse{Healthy: true, Version: "v0.1.0"}
	cdrHealthMu.Unlock()
	t.Cleanup(clearCDRHealth)

	atomic.StoreInt64(&cdrHealthFailures, 2)
	atomic.StoreInt64(&statCDRInstanceHealthy, 0)
	t.Cleanup(func() {
		atomic.StoreInt64(&cdrHealthFailures, 0)
		atomic.StoreInt64(&statCDRInstanceHealthy, 0)
	})

	w := httptest.NewRecorder()
	apiCDRHealth(w, newViewerRequest("/api/cdr/health"))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["healthy"] != true {
		t.Fatalf("expected stale cached healthy=true, got %v", got["healthy"])
	}
	if cf, ok := got["consecutiveFailures"].(float64); !ok || cf != 2 {
		t.Fatalf("consecutiveFailures = %v", got["consecutiveFailures"])
	}
	if got["liveHealthy"] != false {
		t.Fatalf("liveHealthy = %v; want false", got["liveHealthy"])
	}
}

// ─── /api/cdr/test ─────────────────────────────────────────────────────────

func TestApiCDRTest_NoClientReturns503(t *testing.T) {
	resetCDRState(t)
	w := httptest.NewRecorder()
	apiCDRTest(w, newAdminRequest(http.MethodPost, "/api/cdr/test", []byte("x")))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
}

func TestApiCDRTest_WithFakeSluiceReturnsReportOnly(t *testing.T) {
	resetCDRState(t)
	srv := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:         pb.Status_SANITIZED,
			OriginalSize:   4,
			SanitizedSize:  4,
			ThreatsRemoved: []*pb.Threat{{Type: "macro", Severity: "high"}},
		},
		replyChunks: [][]byte{[]byte("data")},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{Enabled: true, DefaultProfile: "default"}
	cdrClientMu.Unlock()
	cdrPoolInstallSingleForTest(c)
	defer cdrPool.shutdown()

	r := newAdminRequest(http.MethodPost, "/api/cdr/test?filename=sample.docx", []byte("data"))
	r.Header.Set("Content-Type", "application/octet-stream")
	w := httptest.NewRecorder()
	apiCDRTest(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}

	// Sluice saw REPORT_ONLY.
	if srv.lastHeader.GetMode() != pb.Mode_REPORT_ONLY {
		t.Fatalf("apiCDRTest must force REPORT_ONLY mode; got %v", srv.lastHeader.GetMode())
	}

	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["status"] != "SANITIZED" {
		t.Fatalf("status = %v", got["status"])
	}
}

func TestApiCDRTest_RejectsOversize(t *testing.T) {
	resetCDRState(t)
	// Active client needed for the gate check to pass and reach the size gate.
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	cdrClientMu.Lock()
	cdrActiveCfg = CDRConfig{Enabled: true, MaxFileSizeMB: 1}
	cdrClientMu.Unlock()
	cdrPoolInstallSingleForTest(c)
	defer cdrPool.shutdown()

	big := make([]byte, 2<<20)
	w := httptest.NewRecorder()
	apiCDRTest(w, newAdminRequest(http.MethodPost, "/api/cdr/test", big))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
}

// ─── Validation ────────────────────────────────────────────────────────────

func TestValidateEnrollRequest_Valid(t *testing.T) {
	ok := cdrEnrollRequest{Name: "s1", Endpoint: "sluice:8443", Token: "tok", ServerFingerprint: strings.Repeat("ab", 32)}
	if err := validateEnrollRequest(ok); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
}

func TestShortFingerprint(t *testing.T) {
	if got := shortFingerprint("sha256:abcdefghij"); got != "abcdefgh…" {
		t.Fatalf("got %q", got)
	}
	if got := shortFingerprint("ab"); got != "ab" {
		t.Fatalf("short input should pass through, got %q", got)
	}
}

// TestLoadCertExpiry_RejectsPathOutsideRoot is a CodeQL-grade check
// — we only read certs under cdrCertsRoot, even if the registry is
// tampered with to point elsewhere.
func TestLoadCertExpiry_RejectsPathOutsideRoot(t *testing.T) {
	_, err := loadCertExpiry("/etc/passwd")
	if err == nil {
		t.Fatal("expected path-outside-root rejection")
	}
	if !strings.Contains(err.Error(), "outside cdr certs root") {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = loadCertExpiry("")
	if err == nil {
		t.Fatal("empty path should error")
	}
}

func TestDaysUntil(t *testing.T) {
	// Future timestamp — positive days.
	if d := daysUntil(time.Now().Add(5 * 24 * time.Hour)); d < 4 || d > 5 {
		t.Fatalf("days = %d, want ~5", d)
	}
	// Past timestamp — negative days.
	if d := daysUntil(time.Now().Add(-5 * 24 * time.Hour)); d > -4 || d < -5 {
		t.Fatalf("days = %d, want ~-5", d)
	}
}

// TestCDRInstanceToMap verifies the JSON-flattening preserves the
// fields the GUI reads.
func TestCDRInstanceToMap(t *testing.T) {
	enabled := true
	inst := &CDREnrolledInstance{
		Name:              "prod-01",
		Endpoint:          "sluice:8443",
		ServerFingerprint: "aabbccdd",
		EnrolledAt:        time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		Version:           "v0.1.0",
		Enabled:           &enabled,
	}
	got := cdrInstanceToMap(inst)
	if got["name"] != "prod-01" {
		t.Fatalf("name = %v", got["name"])
	}
	if got["enabled"] != true {
		t.Fatalf("enabled = %v", got["enabled"])
	}
	if got["enrolledAt"] != "2025-01-01T00:00:00Z" {
		t.Fatalf("enrolledAt = %v", got["enrolledAt"])
	}
	if _, ok := got["clientCertNotAfter"]; ok {
		t.Fatal("cert-expiry fields must be added by the caller, not by the flattener")
	}
}
