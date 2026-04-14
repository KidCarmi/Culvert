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
	"strings"
	"testing"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
)

// ─── Helpers ───────────────────────────────────────────────────────────────

// newAdminRequest builds an *http.Request with RoleAdmin injected into the
// context — matches what uiAuthMiddleware does for an authenticated admin.
func newAdminRequest(method, target string, body []byte) *http.Request {
	var r *http.Request
	if body != nil {
		r = httptest.NewRequest(method, target, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, target, nil)
	}
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleAdmin))
	return r
}

func newViewerRequest(method, target string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r = r.WithContext(context.WithValue(r.Context(), uiRoleKey{}, RoleViewer))
	return r
}

// resetCDRState wipes process-wide CDR singletons between tests.
func resetCDRState(t *testing.T) {
	t.Helper()
	shutdownCDRClient()
	cdrInstances = &CDRInstanceRegistry{}
	cdrPolicyStore = &CDRPolicyStore{}
	t.Cleanup(func() {
		shutdownCDRClient()
		cdrInstances = &CDRInstanceRegistry{}
		cdrPolicyStore = &CDRPolicyStore{}
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
	apiCDRConfig(w, newViewerRequest(http.MethodGet, "/api/cdr/config"))

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

// ─── /api/cdr/instances ────────────────────────────────────────────────────

func TestApiCDRInstances_List(t *testing.T) {
	resetCDRState(t)
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "a", Endpoint: "sluice:8443"})
	_, _ = cdrInstances.Add(CDREnrolledInstance{Name: "b", Endpoint: "sluice-2:8443"})

	w := httptest.NewRecorder()
	apiCDRInstances(w, newViewerRequest(http.MethodGet, "/api/cdr/instances"))

	if w.Code != http.StatusOK {
		t.Fatalf("status %d; body=%s", w.Code, w.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["count"].(float64) != 2 {
		t.Fatalf("count = %v", got["count"])
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
	apiCDRPolicies(w, newViewerRequest(http.MethodGet, "/api/cdr/policies"))
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
	apiCDRPolicies(w, newViewerRequest(http.MethodGet, "/api/cdr/policies"))
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
	apiCDRHealth(w, newViewerRequest(http.MethodGet, "/api/cdr/health"))
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
	apiCDRHealth(w, newViewerRequest(http.MethodGet, "/api/cdr/health"))
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
	cdrActiveClientV = c
	cdrActiveCfg = CDRConfig{Enabled: true, DefaultProfile: "default"}
	cdrClientMu.Unlock()

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
	cdrActiveClientV = c
	cdrActiveCfg = CDRConfig{Enabled: true, MaxFileSizeMB: 1}
	cdrClientMu.Unlock()

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
