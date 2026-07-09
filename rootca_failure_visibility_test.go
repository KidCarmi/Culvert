package main

// rootca_failure_visibility_test.go — CHAOS-06 regression coverage.
//
// A Root CA that was configured but failed to load (wrong/missing
// CULVERT_CA_PASSPHRASE, corrupt bundle) turns the gateway into a
// tunnel-only proxy — fail-open on the primary inspection control — and
// used to leave exactly one startup log line behind. These tests pin the
// visibility contract: the failure is recorded, surfaced on /healthz and
// /readyz (report-only — readiness posture unchanged), and a
// ca_load_failed alert is queued until the webhook store loads.

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// captureStartupAlerts isolates the deferred-startup-alert globals and the
// recorded CA failure for one test, capturing delivered alerts through the
// startupAlertFire seam.
func captureStartupAlerts(t *testing.T) *[]queuedStartupAlert {
	t.Helper()
	startupAlertMu.Lock()
	oldQueue, oldFlushed := startupAlertQueue, startupAlertFlushed
	startupAlertQueue, startupAlertFlushed = nil, false
	startupAlertMu.Unlock()
	oldFire := startupAlertFire
	oldErr := sslInspectionLoadFailure()

	captured := &[]queuedStartupAlert{}
	startupAlertFire = func(event string, p AlertPayload) {
		*captured = append(*captured, queuedStartupAlert{event, p})
	}
	t.Cleanup(func() {
		startupAlertMu.Lock()
		startupAlertQueue, startupAlertFlushed = oldQueue, oldFlushed
		startupAlertMu.Unlock()
		startupAlertFire = oldFire
		sslInspectionLoadError.Store(oldErr)
	})
	return captured
}

// TestCALoadFailure_AlertQueuedUntilWebhooksLoad pins the deferred-delivery
// contract: the alert fired by the Root-CA slice (which runs BEFORE the
// webhook store loads) must survive until flushStartupAlerts and then fire;
// post-flush alerts pass straight through.
func TestCALoadFailure_AlertQueuedUntilWebhooksLoad(t *testing.T) {
	captured := captureStartupAlerts(t)

	noteSSLInspectionUnavailable("/data/ca.bundle", errors.New("bundle decrypt failed"))

	if len(*captured) != 0 {
		t.Fatalf("alert fired before webhook store loaded — it would fan out to an empty list and vanish (got %d)", len(*captured))
	}
	if got := sslInspectionLoadFailure(); !strings.Contains(got, "/data/ca.bundle") || !strings.Contains(got, "bundle decrypt failed") {
		t.Fatalf("recorded failure missing path/cause: %q", got)
	}

	flushStartupAlerts()
	if len(*captured) != 1 {
		t.Fatalf("flush delivered %d alerts, want 1", len(*captured))
	}
	if a := (*captured)[0]; a.event != "ca_load_failed" || a.payload.Source != "ca" {
		t.Fatalf("unexpected alert %q source %q, want ca_load_failed/ca", a.event, a.payload.Source)
	}

	// After the flush the queue degrades to a passthrough.
	deferStartupAlert("ca_load_failed", AlertPayload{Detail: "again", Source: "ca"})
	if len(*captured) != 2 {
		t.Fatalf("post-flush deferStartupAlert should fire immediately (got %d)", len(*captured))
	}
}

// TestHandleReady_SurfacesCALoadFailure pins that /readyz shows a failing
// (but non-gating) ca check when the CA was configured and failed to load,
// instead of the row silently disappearing.
func TestHandleReady_SurfacesCALoadFailure(t *testing.T) {
	captureStartupAlerts(t)
	prevMgr := certMgr
	certMgr = ca.New() // fresh manager: not ready
	t.Cleanup(func() { certMgr = prevMgr })

	type readyResp struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	ready := func() (readyResp, int) {
		rr := httptest.NewRecorder()
		handleReady(rr, nil)
		var r readyResp
		if err := json.NewDecoder(rr.Body).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r, rr.Code
	}

	// Baseline: CA not ready, no recorded failure → no ca row (unchanged
	// pre-CHAOS-06 behavior for a CA that is simply not configured yet).
	sslInspectionLoadError.Store("")
	base, baseCode := ready()
	if _, ok := base.Checks["ca"]; ok {
		t.Fatal("no failure recorded: ca row should be absent (baseline behavior)")
	}

	// Failure recorded → visible fail row with the detail…
	sslInspectionLoadError.Store("Root CA load/init failed for /data/ca.bundle: bad passphrase")
	got, gotCode := ready()
	caCheck, ok := got.Checks["ca"]
	if !ok {
		t.Fatal("ca row missing from /readyz after a configured CA failed to load (CHAOS-06)")
	}
	if caCheck.Status != "fail" || !strings.Contains(caCheck.Detail, "bad passphrase") {
		t.Fatalf("ca check = %+v, want fail with the load error detail", caCheck)
	}
	// …and it is report-only: the ca row alone must not change the
	// readiness verdict (documented posture — the proxy still serves as a
	// plain forward proxy).
	if gotCode != baseCode || got.Status != base.Status {
		t.Fatalf("ca fail row changed readiness (%s/%d → %s/%d) — must be report-only", base.Status, baseCode, got.Status, gotCode)
	}
}

// TestHandleHealth_SurfacesSSLInspectionState pins the /healthz
// ssl_inspection field: load_failed when a configured CA failed,
// unavailable when the CA simply is not ready.
func TestHandleHealth_SurfacesSSLInspectionState(t *testing.T) {
	captureStartupAlerts(t)
	prevMgr := certMgr
	certMgr = ca.New()
	t.Cleanup(func() { certMgr = prevMgr })

	health := func() string {
		rr := httptest.NewRecorder()
		handleHealth(rr, nil)
		var r struct {
			SSLInspection string `json:"ssl_inspection"`
		}
		if err := json.NewDecoder(rr.Body).Decode(&r); err != nil {
			t.Fatal(err)
		}
		return r.SSLInspection
	}

	sslInspectionLoadError.Store("")
	if got := health(); got != "unavailable" {
		t.Fatalf("ssl_inspection = %q, want unavailable (CA not ready, no failure)", got)
	}
	sslInspectionLoadError.Store("Root CA load/init failed: boom")
	if got := health(); got != "load_failed" {
		t.Fatalf("ssl_inspection = %q, want load_failed", got)
	}
}
