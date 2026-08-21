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
	"path/filepath"
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

	// Failure recorded → visible fail row…
	sslInspectionLoadError.Store("Root CA load/init failed for /data/ca.bundle: bad passphrase")
	got, gotCode := ready()
	caCheck, ok := got.Checks["ca"]
	if !ok {
		t.Fatal("ca row missing from /readyz after a configured CA failed to load (CHAOS-06)")
	}
	if caCheck.Status != "fail" {
		t.Fatalf("ca check = %+v, want status fail", caCheck)
	}
	// …carrying a FIXED detail, never the raw cause. /ready is unauthenticated
	// on the proxy port, so the bundle path and the "inspection is off" cause
	// must not be published to every client on the network (see
	// appendCAReadinessCheck). The visibility contract CHAOS-06 established is
	// the failing ROW; the cause belongs to the log and the alert.
	if !strings.Contains(caCheck.Detail, "see server logs") {
		t.Fatalf("ca detail = %q, want the fixed see-server-logs string", caCheck.Detail)
	}
	for _, leak := range []string{"/data/ca.bundle", "bad passphrase"} {
		if strings.Contains(caCheck.Detail, leak) {
			t.Fatalf("ca detail leaks %q to the unauthenticated /ready surface: %q", leak, caCheck.Detail)
		}
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

// TestCALoadFailure_SurfacedEvenWhenReady is the follow-up regression: the
// recorded load failure must win over Ready() on BOTH /healthz and /readyz.
// LoadOrInitCA calls InitCA() (Ready()→true) BEFORE SaveCA(), so a SaveCA
// failure (missing parent dir) leaves initInspectionCA having recorded a
// failure while certMgr.Ready() stays true. Reporting "ready"/"ok" there would
// hide a configured CA bundle that never persisted — the reporting must reflect
// the recorded failure first, without touching the CA manager's Ready()
// semantics or the proxy's degrade-to-tunnel behavior.
func TestCALoadFailure_SurfacedEvenWhenReady(t *testing.T) {
	captureStartupAlerts(t)
	prevMgr := certMgr
	certMgr = ca.New()
	t.Cleanup(func() { certMgr = prevMgr })

	// Drive the real load path: a bundle whose PARENT directory does not exist.
	// LoadOrInitCA sees no file → InitCA() (Ready()→true) → SaveCA() fails.
	sslInspectionLoadError.Store("")
	badPath := filepath.Join(t.TempDir(), "no-such-dir", "ca.bundle")
	initInspectionCA(rootCAStartupConfig{Path: badPath})

	// Preconditions that make this the exact bug window: Ready() true AND a
	// failure recorded.
	if !certMgr.Ready() {
		t.Fatal("precondition: InitCA should leave certMgr Ready() true (the bug only bites when Ready() is true)")
	}
	if sslInspectionLoadFailure() == "" {
		t.Fatal("precondition: a SaveCA failure must record a load failure")
	}

	// /healthz ssl_inspection must be load_failed, not "ready".
	hr := httptest.NewRecorder()
	handleHealth(hr, nil)
	var h struct {
		SSLInspection string `json:"ssl_inspection"`
	}
	if err := json.NewDecoder(hr.Body).Decode(&h); err != nil {
		t.Fatal(err)
	}
	if h.SSLInspection != "load_failed" {
		t.Fatalf("/healthz ssl_inspection = %q, want load_failed (Ready() true but SaveCA failed)", h.SSLInspection)
	}

	// /readyz ca row must be a failing (report-only) row, not "ok".
	rr := httptest.NewRecorder()
	handleReady(rr, nil)
	var r struct {
		Checks map[string]struct {
			Status string `json:"status"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&r); err != nil {
		t.Fatal(err)
	}
	caRow, ok := r.Checks["ca"]
	if !ok {
		t.Fatal("/readyz ca row missing after a configured CA failed to persist despite Ready() true")
	}
	if caRow.Status != "fail" {
		t.Fatalf("/readyz ca row = %+v, want status=fail (recorded failure must win over Ready())", caRow)
	}
}
