package main

// storage_health_test.go — CHAOS-45: a data directory that goes read-only or
// full AFTER boot must be loud, not silent.
//
// Pre-fix behaviour these tests would have caught:
//   - every durable write failed with no counter, no log, no alert
//   - checkStorage() kept reporting "writable (verified once at startup)"
//     because the probe is one-shot and its verdict is cached forever
//   - /metrics carried no persistence-health series at all

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// renderMetrics scrapes /metrics through the real handler.
func renderMetrics(t *testing.T) string {
	t.Helper()
	rec := httptest.NewRecorder()
	handleMetrics(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/metrics", http.NoBody))
	if rec.Code != http.StatusOK {
		t.Fatalf("handleMetrics status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

// failingWrite provokes a real AtomicWrite failure through the production
// observer. A missing parent directory is used rather than a chmod'd one
// because root bypasses mode bits and CI runs as root.
func failingWrite(t *testing.T, name string) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), "missing-subdir", name)
	if err := fileutil.AtomicWrite(target, []byte("{}"), 0o600); err == nil {
		t.Fatalf("AtomicWrite into a missing directory unexpectedly succeeded (%s)", target)
	}
	return target
}

// withCleanStorageWriteHealth isolates the process-global failure record.
func withCleanStorageWriteHealth(t *testing.T) {
	t.Helper()
	resetStorageWriteHealthForTest()
	t.Cleanup(resetStorageWriteHealthForTest)
}

// captureStorageWriteAlerts swaps the alert seam for a SYNCHRONOUS recorder.
// The production seam fires `go fireAlert(...)`; letting that goroutine run in
// the test binary is the -count/-shuffle determinism class the CI gate keeps
// catching (a straggler alert landing in a sibling test's sink).
func captureStorageWriteAlerts(t *testing.T) *[]string {
	t.Helper()
	var got []string
	prev := fireStorageWriteAlert
	fireStorageWriteAlert = func(detail string) { got = append(got, detail) }
	t.Cleanup(func() { fireStorageWriteAlert = prev })
	return &got
}

func TestStorageWriteFailure_CountedAlertedAndSurfaced(t *testing.T) {
	withCleanStorageWriteHealth(t)
	alerts := captureStorageWriteAlerts(t)

	failingWrite(t, "policy.json")

	snap := storageWriteFailures()
	if snap.Total != 1 {
		t.Fatalf("failure total = %d, want 1", snap.Total)
	}
	if snap.Path != "policy.json" {
		t.Errorf("last path = %q, want the base name policy.json", snap.Path)
	}
	if snap.Err == "" {
		t.Error("last error is empty — the operator gets no cause")
	}
	if snap.Last.IsZero() {
		t.Error("last-failure timestamp not recorded")
	}
	if !storageDegraded() {
		t.Error("storageDegraded() = false immediately after a failure")
	}
	if len(*alerts) != 1 {
		t.Fatalf("fired %d alerts, want exactly 1", len(*alerts))
	}
	if !strings.Contains((*alerts)[0], "policy.json") {
		t.Errorf("alert detail %q does not name the file that failed", (*alerts)[0])
	}
}

// TestCheckStorage_RuntimeFailureOutranksBootProbe is the core regression: the
// boot probe says "writable" (it ran when the disk was fine) and the operator
// contract must NOT keep reporting ok once writes start failing.
func TestCheckStorage_RuntimeFailureOutranksBootProbe(t *testing.T) {
	withCachedStorageState(t) // also resets the write-failure record
	captureStorageWriteAlerts(t)

	dataDir = t.TempDir()
	probeStorageWritability()
	if got := storageWritability(); got != storageStateWritable {
		t.Fatalf("setup: boot probe = %q, want writable", got)
	}
	if ck := checkStorage(); ck.Status != diagOK {
		t.Fatalf("setup: checkStorage = %q, want ok before any failure", ck.Status)
	}

	failingWrite(t, "admin_settings.json")

	ck := checkStorage()
	if ck.Status != diagFail {
		t.Fatalf("checkStorage = %q, want fail — the cached boot probe masked a live persistence failure", ck.Status)
	}
	if !strings.Contains(ck.Message, "admin_settings.json") {
		t.Errorf("message %q does not name the failing file", ck.Message)
	}
	if ck.OperatorAction == "" {
		t.Error("fail verdict with no operator action")
	}
	// The boot probe itself is untouched — the two signals stay distinct.
	if got := storageWritability(); got != storageStateWritable {
		t.Errorf("boot-probe cache = %q, want it left at writable (checkStorage must not re-probe)", got)
	}
}

// TestCheckStorage_HealedFailureDegradesToWarn: once writes land again the
// contract must stop crying fail, but must not pretend nothing happened —
// configuration edited during the window never reached disk.
func TestCheckStorage_HealedFailureDegradesToWarn(t *testing.T) {
	withCachedStorageState(t)
	captureStorageWriteAlerts(t)

	dataDir = t.TempDir()
	probeStorageWritability()
	failingWrite(t, "policy.json")

	// Age the record past the degraded window.
	storageWrites.mu.Lock()
	storageWrites.last = time.Now().Add(-storageDegradedWindow - time.Minute)
	storageWrites.mu.Unlock()

	if storageDegraded() {
		t.Error("storageDegraded() still true outside the degraded window")
	}
	ck := checkStorage()
	if ck.Status != diagWarn {
		t.Fatalf("checkStorage = %q, want warn for a healed incident", ck.Status)
	}
	if !strings.Contains(ck.Message, "policy.json") {
		t.Errorf("warn message %q loses the file that failed", ck.Message)
	}
	if ck.OperatorAction == "" {
		t.Error("warn verdict with no operator action")
	}
}

// TestStorageWriteAlert_RateGated: a broken disk fails EVERY write. Without a
// gate the alert producer floods the bounded webhook queue and evicts every
// other alert — the failure mode would take the alerting channel down with it.
func TestStorageWriteAlert_RateGated(t *testing.T) {
	withCleanStorageWriteHealth(t)
	alerts := captureStorageWriteAlerts(t)

	for i := 0; i < 25; i++ {
		failingWrite(t, "policy.json")
	}

	if got := storageWriteFailures().Total; got != 25 {
		t.Errorf("failure total = %d, want all 25 counted (the COUNTER is not gated)", got)
	}
	if len(*alerts) != 1 {
		t.Fatalf("fired %d alerts for 25 failures, want 1 (rate-gated at %s)", len(*alerts), storageWriteAlertInterval)
	}

	// Once the interval elapses the next failure re-arms the alert — a disk
	// that stays broken must keep paging, not go quiet after one message.
	storageWrites.mu.Lock()
	storageWrites.alertAt = time.Now().Add(-storageWriteAlertInterval - time.Second)
	storageWrites.mu.Unlock()
	failingWrite(t, "policy.json")
	if len(*alerts) != 2 {
		t.Errorf("fired %d alerts after the interval elapsed, want 2 (alert never re-armed)", len(*alerts))
	}
}

// TestStorageWriteAlert_RetryQueueNeverAlerts guards the recursion/deadlock
// hazard: alerts.Dispatch can synchronously persist its retry queue while
// holding the retry mutex, so alerting on a failed retry-queue write would
// re-enter the very code path that failed.
func TestStorageWriteAlert_RetryQueueNeverAlerts(t *testing.T) {
	withCleanStorageWriteHealth(t)
	alerts := captureStorageWriteAlerts(t)

	failingWrite(t, alertRetryQueueBase)

	if got := storageWriteFailures().Total; got != 1 {
		t.Errorf("failure total = %d, want 1 (retry-queue failures are still COUNTED)", got)
	}
	if len(*alerts) != 0 {
		t.Fatalf("fired %d alerts for an alert-retry-queue write failure, want 0 (recursion guard)", len(*alerts))
	}
	// It still degrades the contract row — the operator sees it, just not via
	// the channel that is itself broken.
	if !storageDegraded() {
		t.Error("a retry-queue write failure did not degrade storage health")
	}
}

// TestStorageWriteScope_CollectsFailuresWhileOpen pins the scoped collector the
// config-rollback path uses to report partial-durability applies.
func TestStorageWriteScope_CollectsFailuresWhileOpen(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)

	// Before the scope opens.
	failingWrite(t, "before.json")

	finish := beginStorageWriteScope()
	failingWrite(t, "inside.json")
	failingWrite(t, "inside.json") // same file twice — deduped to one entry
	got := finish()

	// After the scope closes.
	failingWrite(t, "after.json")

	if len(got) != 1 {
		t.Fatalf("scope collected %v, want exactly one entry for inside.json", got)
	}
	if !strings.HasPrefix(got[0], "inside.json:") {
		t.Errorf("scope entry = %q, want it to name inside.json", got[0])
	}
	// finish() is once-guarded: the deferred second call in applyConfigBackup
	// must not clear or duplicate the result.
	if again := finish(); len(again) != len(got) {
		t.Errorf("second finish() returned %v, want the same %v", again, got)
	}
	if total := storageWriteFailures().Total; total != 4 {
		t.Errorf("global total = %d, want 4 (the scope filters, it does not suppress)", total)
	}
}

func TestMetrics_StorageWriteSeries(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)

	// Clean state: the age gauge must be ABSENT, never 0 (a 0 would read as
	// "a write just failed" on every healthy node in the fleet).
	body := renderMetrics(t)
	if !strings.Contains(body, "culvert_storage_write_failures_total 0") {
		t.Error("culvert_storage_write_failures_total missing from /metrics")
	}
	if !strings.Contains(body, "culvert_storage_write_degraded 0") {
		t.Error("culvert_storage_write_degraded missing from /metrics")
	}
	if strings.Contains(body, "culvert_storage_write_last_failure_age_seconds") {
		t.Error("age gauge exported with no failure recorded — 0 would look like a fresh failure")
	}

	failingWrite(t, "policy.json")

	body = renderMetrics(t)
	if !strings.Contains(body, "culvert_storage_write_failures_total 1") {
		t.Error("failure counter did not move on /metrics")
	}
	if !strings.Contains(body, "culvert_storage_write_degraded 1") {
		t.Error("degraded gauge did not move on /metrics")
	}
	if !strings.Contains(body, "culvert_storage_write_last_failure_age_seconds") {
		t.Error("age gauge missing after a failure")
	}
}
