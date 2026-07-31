package main

// config_persist_test.go — CHAOS-27 / F-12 regression coverage.
//
// Before this change every config store discarded its durable-write error
// (`_ = fileutil.AtomicWrite(...)`), so a full / read-only / permission-broken
// data directory produced a perfectly silent failure: the admin's change was
// accepted (HTTP 200), enforced in memory, shown in the UI — and reverted by
// the next restart, with nothing in the logs, no counter, no alert, no probe
// signal. Config-version rollback was the worst case: it reported
// `{"status":"rolled_back"}` after persisting none of it.
//
// These tests pin the response on all four surfaces: alert (transition edge
// only), /readyz row (report-only, path-free), /metrics series, and the
// rollback API's partial-durability verdict.
//
// Failures are forced by writing under a directory that does not exist, so
// os.CreateTemp fails with ENOENT. That is uid-independent — a chmod-based
// unwritable directory does not fail for a root test runner.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// capturedPersistAlert is one alert observed through the configPersistAlert seam.
type capturedPersistAlert struct {
	event   string
	payload AlertPayload
}

// isolatePersistTracking gives one test a clean durable-write registry and a
// synchronous alert recorder, then restores the production wiring. The recorder
// is a local seam swap rather than a listener on the process-global alerts sink
// — the determinism lesson from the CHAOS-11 run (a straggler alert goroutine
// from a sibling test makes shuffled `-count=2` runs flaky).
func isolatePersistTracking(t *testing.T) *[]capturedPersistAlert {
	t.Helper()
	fileutil.ResetPersistTrackingForTest()
	origAlert := configPersistAlert
	captured := &[]capturedPersistAlert{}
	configPersistAlert = func(event string, p AlertPayload) {
		*captured = append(*captured, capturedPersistAlert{event, p})
	}
	// ResetPersistTrackingForTest also clears the reporter, so re-install the
	// production one for the duration of the test and again on cleanup.
	fileutil.SetPersistFailureReporter(reportConfigPersist)
	t.Cleanup(func() {
		fileutil.ResetPersistTrackingForTest()
		fileutil.SetPersistFailureReporter(reportConfigPersist)
		configPersistAlert = origAlert
	})
	return captured
}

// unwritablePath returns a path whose parent directory does not exist.
func unwritablePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "no-such-dir", "state.json")
}

func eventsOf(alerts []capturedPersistAlert) []string {
	out := make([]string, 0, len(alerts))
	for _, a := range alerts {
		out = append(out, a.event)
	}
	return out
}

// ── Alerting ────────────────────────────────────────────────────────────────

func TestConfigPersist_AlertsOnTransitionEdgeOnlyThenRecovers(t *testing.T) {
	captured := isolatePersistTracking(t)

	bad := unwritablePath(t)
	for i := 0; i < 3; i++ {
		if err := atomicWriteFileTracked("policy_rules", bad, []byte("x")); err == nil {
			t.Fatalf("write %d unexpectedly succeeded", i)
		}
	}

	if got := eventsOf(*captured); len(got) != 1 || got[0] != "config_persist_failed" {
		t.Fatalf("alerts = %v, want exactly one config_persist_failed (transition edge)", got)
	}
	a := (*captured)[0]
	if a.payload.Source != "storage" {
		t.Errorf("alert Source = %q, want storage", a.payload.Source)
	}
	if !strings.Contains(a.payload.Detail, "policy_rules") {
		t.Errorf("alert detail does not name the store: %q", a.payload.Detail)
	}
	if !strings.Contains(a.payload.Detail, "LOST on restart") {
		t.Errorf("alert detail does not state the consequence: %q", a.payload.Detail)
	}

	// Recovery fires exactly once, and re-arms the failure edge.
	good := filepath.Join(t.TempDir(), "rules.json")
	if err := atomicWriteFileTracked("policy_rules", good, []byte("ok")); err != nil {
		t.Fatalf("recovery write: %v", err)
	}
	if got := eventsOf(*captured); len(got) != 2 || got[1] != "config_persist_recovered" {
		t.Fatalf("alerts = %v, want a trailing config_persist_recovered", got)
	}
	if err := atomicWriteFileTracked("policy_rules", good, []byte("ok")); err != nil {
		t.Fatalf("second healthy write: %v", err)
	}
	if got := eventsOf(*captured); len(got) != 2 {
		t.Fatalf("a healthy write emitted an alert: %v", got)
	}
	if err := atomicWriteFileTracked("policy_rules", bad, []byte("x")); err == nil {
		t.Fatal("want a failure")
	}
	if got := eventsOf(*captured); len(got) != 3 || got[2] != "config_persist_failed" {
		t.Fatalf("alerts = %v, want the failure edge re-armed after recovery", got)
	}
}

func TestConfigPersist_HealthyWritesAreSilent(t *testing.T) {
	captured := isolatePersistTracking(t)

	good := filepath.Join(t.TempDir(), "state.json")
	for i := 0; i < 5; i++ {
		if err := atomicWriteFileTracked("blocklist", good, []byte("x")); err != nil {
			t.Fatalf("healthy write %d: %v", i, err)
		}
	}
	if len(*captured) != 0 {
		t.Fatalf("healthy writes produced alerts: %v", eventsOf(*captured))
	}
	checks := map[string]*readinessCheck{}
	appendConfigPersistChecks(checks)
	if len(checks) != 0 {
		t.Fatalf("healthy writes produced readiness rows: %v", checks)
	}
}

// ── /readyz ─────────────────────────────────────────────────────────────────

func TestConfigPersist_ReadinessRowIsReportOnlyAndPathFree(t *testing.T) {
	isolatePersistTracking(t)

	bad := unwritablePath(t)
	if err := atomicWriteFileTracked("blocklist_mode", bad, []byte("allow")); err == nil {
		t.Fatal("want a failure")
	}

	checks := map[string]*readinessCheck{}
	appendConfigPersistChecks(checks)
	row, ok := checks["config_persist_blocklist_mode"]
	if !ok {
		t.Fatalf("no config_persist_blocklist_mode row; got %v", checks)
	}
	if row.Status != "fail" {
		t.Errorf("row status = %q, want fail", row.Status)
	}
	// /readyz is unauthenticated on the proxy port — the row must not leak the
	// data-directory layout or the raw syscall error (appendStateFileChecks
	// posture).
	if strings.Contains(row.Detail, bad) || strings.Contains(row.Detail, filepath.Dir(bad)) {
		t.Errorf("readiness detail leaks the state-file path: %q", row.Detail)
	}

	// Report-only: the row must not flip the DEFAULT readiness verdict on its
	// own. Compare the verdict with and without the failure recorded.
	_, codeWithFailure := computeReadiness()
	fileutil.ResetPersistTrackingForTest()
	fileutil.SetPersistFailureReporter(reportConfigPersist)
	_, codeClean := computeReadiness()
	if codeWithFailure != codeClean {
		t.Errorf("readiness code changed %d → %d; the config_persist row must be report-only", codeClean, codeWithFailure)
	}
}

// ── /metrics ────────────────────────────────────────────────────────────────

func TestConfigPersist_MetricsExposition(t *testing.T) {
	isolatePersistTracking(t)

	// The aggregate gauge is emitted even when everything is healthy, so an
	// alerting rule never depends on a series that only appears once broken.
	var clean bytes.Buffer
	writeConfigPersistMetrics(&clean)
	if !strings.Contains(clean.String(), "culvert_config_persist_failing_stores 0") {
		t.Fatalf("healthy exposition missing the zero gauge:\n%s", clean.String())
	}
	if strings.Contains(clean.String(), "culvert_config_persist_failures_total{") {
		t.Errorf("healthy exposition emitted labelled series:\n%s", clean.String())
	}

	bad := unwritablePath(t)
	if err := atomicWriteFileTracked("content_scan", bad, []byte("x")); err == nil {
		t.Fatal("want a failure")
	}
	var broken bytes.Buffer
	writeConfigPersistMetrics(&broken)
	out := broken.String()
	for _, want := range []string{
		"culvert_config_persist_failing_stores 1",
		`culvert_config_persist_failures_total{store="content_scan"} 1`,
		`culvert_config_persist_failing{store="content_scan"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q:\n%s", want, out)
		}
	}

	// After recovery the gauge drops to 0 but the counter stays monotonic.
	good := filepath.Join(t.TempDir(), "cs.json")
	if err := atomicWriteFileTracked("content_scan", good, []byte("ok")); err != nil {
		t.Fatalf("recovery write: %v", err)
	}
	var recovered bytes.Buffer
	writeConfigPersistMetrics(&recovered)
	out = recovered.String()
	if !strings.Contains(out, `culvert_config_persist_failing{store="content_scan"} 0`) {
		t.Errorf("gauge did not clear on recovery:\n%s", out)
	}
	if !strings.Contains(out, `culvert_config_persist_failures_total{store="content_scan"} 1`) {
		t.Errorf("counter regressed on recovery:\n%s", out)
	}
}

// ── Config-version rollback (the CHAOS-27 headline) ─────────────────────────

// TestRollback_PartialDurabilityIsReported is the regression that names the
// original defect: a rollback whose stores could not be written reported
// HTTP 200 {"status":"rolled_back"} and left the operator believing the change
// was durable. The rollback target is a snapshot of the CURRENT live state, so
// applying it is semantically a no-op — the only thing under test is what the
// caller is told about durability.
func TestRollback_PartialDurabilityIsReported(t *testing.T) {
	isolatePersistTracking(t)

	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })

	origPolicyPath := policyStore.path
	t.Cleanup(func() { policyStore.path = origPolicyPath })

	// Snapshot the live config as the rollback target.
	saveConfigVersion("chaos-27-test", "test.baseline")
	ver := configVersions.Seq()

	// Break policy persistence only — one store failing is enough to make the
	// whole rollback non-durable.
	policyStore.path = unwritablePath(t)

	req := httptest.NewRequest(http.MethodPost, "/api/config/versions",
		strings.NewReader(`{"version":`+strconv.Itoa(ver)+`}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rollbackConfigVersion(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for a rollback that did not reach disk\nbody: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status         string   `json:"status"`
		Applied        bool     `json:"applied"`
		PersistDurable bool     `json:"persist_durable"`
		PersistErrors  []string `json:"persist_errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, w.Body.String())
	}
	if resp.Status != "rolled_back_not_durable" {
		t.Errorf("status = %q, want rolled_back_not_durable", resp.Status)
	}
	if resp.PersistDurable {
		t.Error("persist_durable = true after a failed store write")
	}
	if !resp.Applied {
		t.Error("applied = false; the in-memory rollback DID happen and must be reported")
	}
	if !persistStoreListed(resp.PersistErrors, "policy_rules") {
		t.Errorf("persist_errors = %v, want it to name policy_rules", resp.PersistErrors)
	}
}

// TestRollback_DurableRollbackStillReportsSuccess pins the healthy path: the
// new verdict must not turn every rollback into a 500.
func TestRollback_DurableRollbackStillReportsSuccess(t *testing.T) {
	isolatePersistTracking(t)

	origDir := configVersions.Dir()
	configVersions.SetDirForTest(t.TempDir())
	t.Cleanup(func() { configVersions.SetDirForTest(origDir) })

	origPolicyPath := policyStore.path
	policyStore.path = filepath.Join(t.TempDir(), "rules.json")
	t.Cleanup(func() { policyStore.path = origPolicyPath })

	saveConfigVersion("chaos-27-test", "test.baseline")
	ver := configVersions.Seq()

	req := httptest.NewRequest(http.MethodPost, "/api/config/versions",
		strings.NewReader(`{"version":`+strconv.Itoa(ver)+`}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	rollbackConfigVersion(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a durable rollback\nbody: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status         string   `json:"status"`
		PersistDurable bool     `json:"persist_durable"`
		PersistErrors  []string `json:"persist_errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "rolled_back" || !resp.PersistDurable || len(resp.PersistErrors) != 0 {
		t.Errorf("healthy rollback reported %+v, want rolled_back/durable/no errors", resp)
	}
}

// TestApplyConfigBackup_ReportsFailingStores checks the attribution primitive
// directly: applyConfigBackup names every store that failed inside its window.
func TestApplyConfigBackup_ReportsFailingStores(t *testing.T) {
	isolatePersistTracking(t)

	origPolicyPath := policyStore.path
	policyStore.path = unwritablePath(t)
	t.Cleanup(func() { policyStore.path = origPolicyPath })

	target := captureConfigBackup()
	failures := applyConfigBackup(target)
	if !persistStoreListed(failures, "policy_rules") {
		t.Fatalf("applyConfigBackup returned %v, want it to name policy_rules", failures)
	}

	// A pre-existing failure from BEFORE the apply window is not attributed to
	// this rollback (the window is bounded by the failure sequence).
	policyStore.path = filepath.Join(t.TempDir(), "rules.json")
	if failures := applyConfigBackup(target); len(failures) != 0 {
		t.Fatalf("healthy apply reported %v, want none", failures)
	}
}

func persistStoreListed(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
