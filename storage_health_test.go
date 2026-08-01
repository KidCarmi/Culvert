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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// hasScopeEntry / countScopeEntries inspect a scope result by CONTENT. Scope
// entries are formatted "<base>: <error>", so the file is matched on the
// prefix.
func hasScopeEntry(entries []string, base string) bool {
	return countScopeEntries(entries, base) > 0
}

func countScopeEntries(entries []string, base string) int {
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e, base+":") {
			n++
		}
	}
	return n
}

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
//
// NOTE on assertion style below: clearing the record at test start is NOT
// enough to make an exact-count assertion safe. The record is process-global
// and the observer fires from whatever goroutine performed the write, so a
// goroutine leaked by an earlier test (a CP publish, an alert retry, a
// heartbeat) can increment it in the middle of this test — and in CI, where
// /data is unwritable, those background writes DO fail. Assertions here
// therefore follow the convention CLAUDE.md already documents for the audit
// ring: assert on CONTENT and on monotonic direction, never on an exact global
// count. The alert seam is swapped for a synchronous recorder, so alert counts
// (unlike failure counts) are scoped to this test and can be exact.
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
	if snap.Total < 1 {
		t.Fatalf("failure total = %d, want at least the one we injected", snap.Total)
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

// TestStorageWriteFailure_NeverLeaksAbsolutePaths pins the redaction boundary.
//
// Regression: the first version of this change put AtomicWrite's raw error
// text into the storage_path row of the operator contract. That endpoint is
// VIEWER-role, and its standing guardrail (TestApiDiagnostics_NoSensitiveValues)
// forbids raw filesystem paths — so on a real appliance, the first failed
// durable write would have handed every viewer the data-directory layout.
// The cause must survive; the path must not.
func TestStorageWriteFailure_NeverLeaksAbsolutePaths(t *testing.T) {
	withCachedStorageState(t)
	captureStorageWriteAlerts(t)

	// Mirror the production shape that triggered it: a file under /data.
	dir := filepath.Join(t.TempDir(), "data", "config_versions")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	target := filepath.Join(dir, "missing-subdir", "v9.json")
	if err := fileutil.AtomicWrite(target, []byte("{}"), 0o600); err == nil {
		t.Fatal("AtomicWrite unexpectedly succeeded")
	}

	snap := storageWriteFailures()
	if strings.Contains(snap.Err, dir) {
		t.Errorf("recorded error still carries the directory %q: %q", dir, snap.Err)
	}
	if strings.Contains(snap.Path, string(filepath.Separator)) {
		t.Errorf("recorded path %q is not a bare base name", snap.Path)
	}
	// The cause must still be actionable: the file and the errno survive.
	if !strings.Contains(snap.Err, "v9.json") {
		t.Errorf("redaction removed the file name too: %q", snap.Err)
	}
	if !strings.Contains(snap.Err, "no such file or directory") {
		t.Errorf("redaction removed the errno: %q", snap.Err)
	}

	// End-to-end: the rendered contract row carries no separator-prefixed path.
	ck := checkStorage()
	if strings.Contains(ck.Message, dir) {
		t.Errorf("storage_path message leaked the directory: %q", ck.Message)
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

	if !storageDegraded() {
		t.Fatal("setup: not degraded immediately after a failure")
	}

	// Recovery must be EVIDENCE, not elapsed time. Merely waiting proves
	// nothing about a filesystem that is still read-only — only a durable write
	// that actually succeeds does. Perform one.
	okTarget := filepath.Join(t.TempDir(), "recovered.json")
	if err := fileutil.AtomicWrite(okTarget, []byte("{}"), 0o600); err != nil {
		t.Fatalf("recovery write: %v", err)
	}

	if storageDegraded() {
		t.Error("storageDegraded() still true after an observed successful write")
	}
	if !storageRecoveryObserved() {
		t.Error("storageRecoveryObserved() = false after a successful write")
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

	if got := storageWriteFailures().Total; got < 25 {
		t.Errorf("failure total = %d, want at least 25 — every failure counts, the COUNTER is not gated", got)
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

	if got := storageWriteFailures().Total; got < 1 {
		t.Errorf("failure total = %d, want the retry-queue failure to still be COUNTED", got)
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

	// Content assertions, not a count: a leaked goroutine's failing write can
	// legitimately land in the scope window (that is the documented, deliberate
	// over-reporting semantic — see storageWriteScope). What must hold is the
	// WINDOW boundary: what happened inside is in, what happened outside is not.
	if !hasScopeEntry(got, "inside.json") {
		t.Errorf("scope = %v, missing the failure that happened while it was open", got)
	}
	if hasScopeEntry(got, "before.json") {
		t.Errorf("scope = %v, captured a failure from BEFORE it opened", got)
	}
	if hasScopeEntry(got, "after.json") {
		t.Errorf("scope = %v, captured a failure from AFTER it closed", got)
	}
	// Per-file dedup: inside.json failed twice, it must appear once.
	if n := countScopeEntries(got, "inside.json"); n != 1 {
		t.Errorf("inside.json appears %d times, want 1 (per-file dedup)", n)
	}
	// finish() is once-guarded: the deferred second call in applyConfigBackup
	// must not clear or duplicate the result.
	if again := finish(); len(again) != len(got) {
		t.Errorf("second finish() returned %v, want the same %v", again, got)
	}
	if total := storageWriteFailures().Total; total < 4 {
		t.Errorf("global total = %d, want at least 4 (the scope filters, it does not suppress)", total)
	}
}

func TestMetrics_StorageWriteSeries(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)

	// Clean state: the age gauge must be ABSENT, never 0 (a 0 would read as
	// "a write just failed" on every healthy node in the fleet). Guarded on a
	// re-read of the record rather than assumed: a leaked goroutine's failing
	// write can dirty it between the reset and the scrape, and that would make
	// the absence assertion wrong for a legitimate reason.
	body := renderMetrics(t)
	if !strings.Contains(body, "culvert_storage_write_failures_total ") {
		t.Error("culvert_storage_write_failures_total missing from /metrics")
	}
	if !strings.Contains(body, "culvert_storage_write_degraded ") {
		t.Error("culvert_storage_write_degraded missing from /metrics")
	}
	if storageWriteFailures().Total == 0 {
		if !strings.Contains(body, "culvert_storage_write_failures_total 0") {
			t.Error("counter is not 0 on /metrics despite a clean record")
		}
		if strings.Contains(body, "culvert_storage_write_last_failure_age_seconds") {
			t.Error("age gauge exported with no failure recorded — 0 would look like a fresh failure")
		}
	}

	before := storageWriteFailures().Total
	failingWrite(t, "policy.json")

	body = renderMetrics(t)
	after := storageWriteFailures().Total
	if after <= before {
		t.Fatalf("failure record did not move: %d -> %d", before, after)
	}
	if !strings.Contains(body, fmt.Sprintf("culvert_storage_write_failures_total %d", after)) {
		t.Errorf("failure counter on /metrics does not match the record (%d)", after)
	}
	if !strings.Contains(body, "culvert_storage_write_degraded 1") {
		t.Error("degraded gauge did not move on /metrics")
	}
	if !strings.Contains(body, "culvert_storage_write_last_failure_age_seconds") {
		t.Error("age gauge missing after a failure")
	}
}

// TestStorageDegraded_SilenceIsNotRecovery pins the Codex P1 correction: an
// earlier draft aged the failure out on a timer, so a filesystem that stayed
// broken but simply received no further write attempts reported itself
// recovered. Only an observed successful write may clear the state.
func TestStorageDegraded_SilenceIsNotRecovery(t *testing.T) {
	withCleanStorageWriteHealth(t)
	captureStorageWriteAlerts(t)

	failingWrite(t, "policy.json")
	if !storageDegraded() {
		t.Fatal("setup: not degraded after a failure")
	}

	// Simulate an arbitrarily long quiet period: push the failure far into the
	// past. Under the old time-based rule this alone cleared the state.
	storageWrites.mu.Lock()
	storageWrites.last = time.Now().Add(-24 * time.Hour)
	storageWrites.mu.Unlock()

	if !storageDegraded() {
		t.Error("storage reported recovered after mere elapsed time — silence is not evidence that the filesystem healed")
	}
	if ck := checkStorage(); ck.Status != diagFail {
		t.Errorf("checkStorage = %q, want fail while no successful write has been observed", ck.Status)
	}

	// A successful durable write is the only thing that clears it.
	if err := fileutil.AtomicWrite(filepath.Join(t.TempDir(), "ok.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("recovery write: %v", err)
	}
	if storageDegraded() {
		t.Error("still degraded after an observed successful durable write")
	}
}

// TestStorageWriteAlert_RetryQueueDoesNotConsumeAlertGate pins the Codex P2
// correction. The alert engine persists its own retry queue, so during a disk
// incident that file is a likely FIRST failure. If it consumed the shared rate
// gate, the next real store failure would be silently un-paged for a full
// interval — muting the signal during exactly the incident it exists for.
func TestStorageWriteAlert_RetryQueueDoesNotConsumeAlertGate(t *testing.T) {
	withCleanStorageWriteHealth(t)
	alerts := captureStorageWriteAlerts(t)

	// The retry queue fails FIRST.
	failingWrite(t, alertRetryQueueBase)
	if len(*alerts) != 0 {
		t.Fatalf("retry-queue failure fired %d alerts, want 0", len(*alerts))
	}

	// A real store fails immediately afterwards, well inside the interval.
	failingWrite(t, "policy.json")
	if len(*alerts) != 1 {
		t.Fatalf("fired %d alerts for the store failure, want 1 — the retry-queue write consumed the alert gate", len(*alerts))
	}
	if !strings.Contains((*alerts)[0], "policy.json") {
		t.Errorf("alert %q does not name the store that failed", (*alerts)[0])
	}
}
