package main

// Process-log durable-write health — package-main wiring + admin surfaces.
//
// internal/logsink already counts every line that never reached its
// destination writer (Writer.WriteErrors, see internal/logsink/logsink_test.go
// for the engine contract). Unlike its sibling reqlog.WriteErrors() and
// auditWriteErrors(), that count previously had zero callers in package main:
// no /api/stats field, no /metrics sample, no /healthz annotation. These tests
// pin the wiring added to close that gap — the process log carries every
// POLICY_ALLOW/BLOCK/DROP decision, so a silent gap in it is a blind spot for
// exactly the audience this counter exists to serve.

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/logsink"
)

// failingSink fails every write.
type failingSink struct{}

func (failingSink) Write([]byte) (int, error) { return 0, errors.New("no space left on device") }

// installFailingLogSink swaps the process-wide async sink for one whose
// destination always fails, writes n lines through it, and drains
// synchronously so WriteErrors() reflects them before returning. Restores the
// previous sink on cleanup (mirrors restoreLogSink in logger_async_test.go).
func installFailingLogSink(t *testing.T, n int) {
	t.Helper()
	restoreLogSink(t)
	w := logsink.New(failingSink{})
	t.Cleanup(func() { _ = w.Close() })
	logSink.Store(w)
	for i := 0; i < n; i++ {
		_, _ = w.Write([]byte("POLICY_ALLOW test line\n"))
	}
	w.Sync()
}

func TestLogSinkWriteErrors_Delegates(t *testing.T) {
	restoreLogSink(t)
	logSink.Store(nil)
	if n := logSinkWriteErrors(); n != 0 {
		t.Fatalf("logSinkWriteErrors() with no sink installed = %d, want 0", n)
	}
	installFailingLogSink(t, 3)
	if n := logSinkWriteErrors(); n < 3 {
		t.Fatalf("logSinkWriteErrors() = %d, want >= 3", n)
	}
}

func TestAPIStats_SurfacesProcessLogWriteErrors(t *testing.T) {
	installFailingLogSink(t, 2)

	w := httptest.NewRecorder()
	r := adminCtx(httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/stats", http.NoBody))
	r.RemoteAddr = "198.51.100.7:9999"
	apiStats(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", w.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode /api/stats: %v", err)
	}
	raw, ok := body["processLogWriteErrors"]
	if !ok {
		t.Fatal("/api/stats has no processLogWriteErrors field — process-log loss is invisible to the dashboard")
	}
	n, ok := raw.(float64)
	if !ok {
		t.Fatalf("processLogWriteErrors = %#v; want a number", raw)
	}
	if n < 2 {
		t.Errorf("processLogWriteErrors = %v; want >= 2 (the failures we injected)", n)
	}
}

// TestMetrics_ExposesLogSinkWriteErrors pins the Prometheus surface, so the
// loss is alertable from the operator's existing monitoring rather than only
// from a human looking at the dashboard.
func TestMetrics_ExposesLogSinkWriteErrors(t *testing.T) {
	installFailingLogSink(t, 1)

	var sb strings.Builder
	liveFeedWritePrometheus(&sb)
	out := sb.String()

	if !strings.Contains(out, "# TYPE culvert_logsink_write_errors_total counter") {
		t.Fatal("/metrics does not declare culvert_logsink_write_errors_total")
	}
	if !strings.Contains(out, "\nculvert_logsink_write_errors_total ") {
		t.Fatal("/metrics does not emit a culvert_logsink_write_errors_total sample")
	}
	if strings.Contains(out, "culvert_logsink_write_errors_total 0\n") {
		t.Error("culvert_logsink_write_errors_total reported 0 after an injected failure")
	}
}

// TestAPIHealthz_Standby_AnnotatesProcessLogWriteErrors exercises the real
// /healthz endpoint (not just the addRequestLogHealth helper) on the standby
// response path, which builds its body separately from the leader/standalone
// path and previously never called addRequestLogHealth at all — so this
// whole field family (including the pre-existing requestLogWriteErrors/
// auditLogWriteErrors/requestLogBackpressure) was invisible on a standby
// node's health probe.
func TestAPIHealthz_Standby_AnnotatesProcessLogWriteErrors(t *testing.T) {
	defer swapGlobalHA(t)()
	globalHA.mu.Lock()
	globalHA.role = "standby"
	globalHA.since = time.Now()
	globalHA.mu.Unlock()
	installFailingLogSink(t, 1)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	apiHealthz(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode /healthz: %v", err)
	}
	n, present := resp["processLogWriteErrors"].(float64)
	if !present {
		t.Fatal("standby /healthz does not annotate processLogWriteErrors while process-log writes are failing")
	}
	if n < 1 {
		t.Errorf("processLogWriteErrors = %v; want >= 1", n)
	}
}

func TestHealthz_AnnotatesProcessLogWriteErrors(t *testing.T) {
	healthy := map[string]any{}
	addRequestLogHealth(healthy)
	if _, present := healthy["processLogWriteErrors"]; present {
		t.Error("processLogWriteErrors present with a healthy sink — probe bodies must be unchanged in the normal case")
	}

	installFailingLogSink(t, 1)
	degraded := map[string]any{}
	addRequestLogHealth(degraded)
	n, present := degraded["processLogWriteErrors"].(int64)
	if !present {
		t.Fatal("/healthz does not annotate processLogWriteErrors while process-log writes are failing")
	}
	if n < 1 {
		t.Errorf("processLogWriteErrors = %d; want >= 1", n)
	}
}
