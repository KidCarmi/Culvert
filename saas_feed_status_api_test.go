package main

// saas_feed_status_api_test.go — F3b-4: status API + manual-refresh handler + the
// report-only health/readiness row.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func swapFeedStatus(t *testing.T, now time.Time) *saasFeedStatus {
	t.Helper()
	prev := globalSaaSFeedStatus
	s := newSaaSFeedStatus(func() time.Time { return now })
	globalSaaSFeedStatus = s
	t.Cleanup(func() { globalSaaSFeedStatus = prev })
	return s
}

func dispatchStatus(role UIRole, method string) *httptest.ResponseRecorder {
	ctx := context.WithValue(context.Background(), uiRoleKey{}, role)
	r := httptest.NewRequestWithContext(ctx, method, "/api/saas-feed/status", nil)
	w := httptest.NewRecorder()
	apiSaaSFeedStatus(w, r)
	return w
}

func TestF3b4_API_Status(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s := swapFeedStatus(t, base)
	s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true, Protocol: saasFeedProtocolV1}})
	s.noteActivation(viewFor(sourceDownloaded, 42, "2026-08-01T00:00:00Z", "2026-08-20T00:00:00Z"), saasFeedActivationDelta{HostsAdded: 5})

	// Viewer GET OK.
	w := dispatchStatus(RoleViewer, http.MethodGet)
	if w.Code != http.StatusOK {
		t.Fatalf("GET viewer: %d", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["state"] != "fresh" || body["provenance"] != "downloaded" {
		t.Errorf("state/provenance wrong: %v", body)
	}
	if body["active_feed_version"] != float64(42) {
		t.Errorf("active_feed_version = %v, want 42", body["active_feed_version"])
	}
	if body["expires_in_days"] == nil {
		t.Errorf("expires_in_days should be present when a generation is active")
	}
	if _, ok := body["last_activation_delta"].(map[string]any); !ok {
		t.Errorf("last_activation_delta should be an object after activation: %v", body["last_activation_delta"])
	}

	// Wrong method 405.
	if w := dispatchStatus(RoleViewer, http.MethodPost); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status: %d, want 405", w.Code)
	}
}

func TestF3b4_API_Status_NeverSucceededNullDelta(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s := swapFeedStatus(t, base)
	s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})

	w := dispatchStatus(RoleViewer, http.MethodGet)
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["state"] != "embedded" {
		t.Errorf("state = %v, want embedded", body["state"])
	}
	if body["last_activation_delta"] != nil {
		t.Errorf("never_succeeded must render null delta, got %v", body["last_activation_delta"])
	}
	if body["active_feed_version"] != nil {
		t.Errorf("no active version ⇒ null, got %v", body["active_feed_version"])
	}
	if body["compiled_trusted"] != true {
		t.Errorf("embedded must be compiled_trusted")
	}
}

func TestF3b4_API_Refresh(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "e")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)
	prev := globalSaaSFeedRuntime
	globalSaaSFeedRuntime = rt
	t.Cleanup(func() { globalSaaSFeedRuntime = prev })

	// Viewer POST forbidden.
	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleViewer)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/saas-feed/refresh", nil)
	w := httptest.NewRecorder()
	apiSaaSFeedRefresh(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("viewer refresh: %d, want 403", w.Code)
	}

	// Admin POST triggers an activation.
	ctx = context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	r = httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/saas-feed/refresh", nil)
	w = httptest.NewRecorder()
	apiSaaSFeedRefresh(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("admin refresh: %d (%s)", w.Code, w.Body.String())
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["refreshed"] != true || body["status"] != "activated" {
		t.Errorf("refresh result wrong: %v", body)
	}

	// GET method not allowed.
	r = httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/saas-feed/refresh", nil)
	w = httptest.NewRecorder()
	apiSaaSFeedRefresh(w, r)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET refresh: %d, want 405", w.Code)
	}
}

func TestF3b4_API_Refresh_InProgress(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	rt := f3b4TestRuntime(t, g, &fakeAcquirer{result: committedResult(g, "e")}, f3b3Now)
	prev := globalSaaSFeedRuntime
	globalSaaSFeedRuntime = rt
	t.Cleanup(func() { globalSaaSFeedRuntime = prev })

	// Simulate an in-flight refresh by holding the run mutex.
	rt.runMu.Lock()
	defer rt.runMu.Unlock()

	ctx := context.WithValue(context.Background(), uiRoleKey{}, RoleAdmin)
	r := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/saas-feed/refresh", nil)
	w := httptest.NewRecorder()
	apiSaaSFeedRefresh(w, r)
	if w.Code != http.StatusAccepted {
		t.Fatalf("in-flight refresh: %d, want 202", w.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body["status"] != "in_progress" {
		t.Errorf("expected in_progress, got %v", body)
	}
}

func TestF3b4_Health_ReportOnlyNeverGates(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	s := swapFeedStatus(t, base)
	// Force a critical feed state.
	s.noteConfig(feedAuthorityResolution{Authority: authorityStandalone, Config: SaaSFeedConfig{Managed: true, Enabled: true}})
	s.noteRecovery(recoveryResult{Class: recoveryEquivocation, Critical: true, Detail: "equivocation"})

	checks := map[string]*readinessCheck{}
	appendSaaSFeedHealthCheck(checks)
	row, ok := checks["saas_feed"]
	if !ok {
		t.Fatal("saas_feed health row missing")
	}
	if row.Status != "fail" || row.Detail != "critical" {
		t.Errorf("critical feed row wrong: %+v", row)
	}
	// The row exists but appendSaaSFeedHealthCheck takes only the checks map — it can
	// never set allOK=false, so a critical feed can NEVER shed traffic by default.
}
