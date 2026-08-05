package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// Audit-log durable-write health — package-main wiring + admin surfaces.
//
// internal/audit now counts every entry that never reached the persistent JSONL
// file (see internal/audit/writefail_test.go for the engine contract). These
// tests pin the OTHER half: that package main actually wires the observer into
// the storage-health plane, and that the resulting count is visible on all
// three read surfaces (GET /api/stats, /metrics, /healthz).
//
// Why it matters: the JSONL file is the durable compliance record. The
// in-memory ring the admin UI renders from holds only the newest 500 entries
// and is wiped on restart, so without these surfaces a full or read-only volume
// silently destroys the "who changed what" trail while every dashboard stays
// green (CWE-778, OWASP A09:2021).

// alwaysFailingAuditSink fails every audit persist.
type alwaysFailingAuditSink struct{}

func (alwaysFailingAuditSink) Write([]byte) (int, error) {
	return 0, errors.New("no space left on device")
}

// injectAuditWriteFailures makes n audit persists fail and returns cleanup.
// Both the audit engine state and the storage-health record are restored.
func injectAuditWriteFailures(t *testing.T, n int) {
	t.Helper()
	restoreRing := audit.SwapRingForTest()
	restorePersist := audit.SetPersistForTest(alwaysFailingAuditSink{})
	restoreErrs := audit.ResetWriteErrorsForTest()
	// ResetWriteErrorsForTest clears the observer too, so re-arm the production
	// wiring under test.
	audit.SetWriteFailureObserver(noteStorageWriteFailure)
	t.Cleanup(func() {
		restoreErrs()
		restorePersist()
		restoreRing()
	})
	for i := 0; i < n; i++ {
		auditAdd(AuditEntry{TS: int64(i), Actor: "10.0.0.1", Action: "policy.add", Object: "rule-1"})
	}
}

// TestAuditWriteFailure_ReachesStorageHealthPlane is the wiring regression:
// the audit JSONL is a RotatingFile, not a fileutil.AtomicWrite, so the
// chokepoint observer never saw it. Without the explicit
// audit.SetWriteFailureObserver wiring in storage_health.go's init, an audit
// write failure would degrade nothing and alert nobody.
func TestAuditWriteFailure_ReachesStorageHealthPlane(t *testing.T) {
	withCleanStorageWriteHealth(t)
	alerts := captureStorageWriteAlerts(t)

	injectAuditWriteFailures(t, 1)

	if got := auditWriteErrors(); got < 1 {
		t.Fatalf("auditWriteErrors() = %d after a failed audit persist; want >= 1", got)
	}
	snap := storageWriteFailures()
	if snap.Total < 1 {
		t.Fatalf("storage failure total = %d; want at least the audit failure we injected", snap.Total)
	}
	if !storageDegraded() {
		t.Error("storageDegraded() = false after an audit-log write failure — the operator contract still reports healthy")
	}
	if len(*alerts) != 1 {
		t.Fatalf("fired %d storage_write_failed alerts; want exactly 1", len(*alerts))
	}
	// Path redaction is inherited from noteStorageWriteFailure and must hold
	// for this producer too: the alert detail is a viewer-visible surface.
	if strings.ContainsRune(snap.Path, '/') {
		t.Errorf("recorded path %q is not a bare base name — audit-log failures must not leak the data-directory layout", snap.Path)
	}
}

// TestAuditWriteFailure_HealthyPersistDoesNotDegrade is the negative case: a
// working audit sink must not charge a write error or degrade storage health,
// so the signal stays trustworthy on a healthy node.
func TestAuditWriteFailure_HealthyPersistDoesNotDegrade(t *testing.T) {
	withCleanStorageWriteHealth(t)
	alerts := captureStorageWriteAlerts(t)

	restoreRing := audit.SwapRingForTest()
	restorePersist := audit.SetPersistForTest(&strings.Builder{})
	restoreErrs := audit.ResetWriteErrorsForTest()
	audit.SetWriteFailureObserver(noteStorageWriteFailure)
	t.Cleanup(func() {
		restoreErrs()
		restorePersist()
		restoreRing()
	})

	auditAdd(AuditEntry{TS: 1, Actor: "10.0.0.1", Action: "policy.add", Object: "rule-1"})

	if got := auditWriteErrors(); got != 0 {
		t.Fatalf("auditWriteErrors() = %d on a healthy sink; want 0", got)
	}
	if len(*alerts) != 0 {
		t.Fatalf("fired %d alerts on a healthy sink; want 0", len(*alerts))
	}
}

// TestAPIStats_SurfacesAuditWriteErrors pins the admin-API surface. GET
// /api/stats is what the dashboard polls; without this field the UI has no way
// to learn that audit entries are being lost.
func TestAPIStats_SurfacesAuditWriteErrors(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)
	injectAuditWriteFailures(t, 3)

	w := httptest.NewRecorder()
	r := adminCtx(httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody))
	r.RemoteAddr = "198.51.100.7:9999"
	apiStats(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /api/stats: %v", err)
	}
	raw, ok := body["auditLogWriteErrors"]
	if !ok {
		t.Fatal("/api/stats has no auditLogWriteErrors field — audit-log loss is invisible to the dashboard")
	}
	n, ok := raw.(float64)
	if !ok {
		t.Fatalf("auditLogWriteErrors = %#v; want a number", raw)
	}
	if int64(n) < 3 {
		t.Errorf("auditLogWriteErrors = %v; want >= 3 (the failures we injected)", n)
	}
}

// TestMetrics_ExposesAuditWriteErrors pins the Prometheus surface, so the loss
// is alertable from the operator's existing monitoring rather than only from a
// human looking at the dashboard.
func TestMetrics_ExposesAuditWriteErrors(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)
	injectAuditWriteFailures(t, 2)

	var sb strings.Builder
	liveFeedWritePrometheus(&sb)
	out := sb.String()

	if !strings.Contains(out, "# TYPE culvert_audit_write_errors_total counter") {
		t.Fatal("/metrics does not declare culvert_audit_write_errors_total")
	}
	if !strings.Contains(out, "\nculvert_audit_write_errors_total ") {
		t.Fatal("/metrics does not emit a culvert_audit_write_errors_total sample")
	}
	if strings.Contains(out, "culvert_audit_write_errors_total 0\n") {
		t.Error("culvert_audit_write_errors_total reported 0 after injected failures")
	}
}

// TestHealthz_AnnotatesAuditWriteErrors pins the /healthz surface and its
// two-sided contract: the field appears when entries are being lost, and is
// ABSENT on a healthy node so existing probe consumers see an unchanged body.
// The node must stay "ok" either way — degraded logging must not pull a
// working gateway out of the load balancer.
func TestHealthz_AnnotatesAuditWriteErrors(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)

	// The counter is process-global; zero it explicitly so the "absent on a
	// healthy node" half is asserted against a known-clean baseline rather
	// than against whatever a sibling test left behind.
	t.Cleanup(audit.ResetWriteErrorsForTest())

	healthy := map[string]any{"status": "ok"}
	addRequestLogHealth(healthy)
	if _, present := healthy["auditLogWriteErrors"]; present {
		t.Error("auditLogWriteErrors present on a healthy node — probe bodies must be unchanged in the normal case")
	}

	injectAuditWriteFailures(t, 1)

	degraded := map[string]any{"status": "ok"}
	addRequestLogHealth(degraded)
	n, present := degraded["auditLogWriteErrors"].(int64)
	if !present {
		t.Fatal("/healthz does not annotate auditLogWriteErrors while audit writes are failing")
	}
	if n < 1 {
		t.Errorf("auditLogWriteErrors = %d; want >= 1", n)
	}
	if degraded["status"] != "ok" {
		t.Errorf("status = %v; want \"ok\" — degraded logging must not fail the health probe", degraded["status"])
	}
}
