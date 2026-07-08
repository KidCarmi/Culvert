package alerts

// retry_test.go — F16 retry-queue engine tests, consolidated in-package at
// extraction (ADR-0002) from package main's alerts_test.go (tmp-leak guard)
// and the alerts section of coverage_boost_test.go (queue behavior). All are
// whitebox on the package-level retry queue state, so each test snapshots and
// restores it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// snapshotRetryQueue swaps in an empty retry queue and restores the original
// on cleanup.
func snapshotRetryQueue(t *testing.T) {
	t.Helper()
	retryMu.Lock()
	orig := retryQueue
	retryQueue = nil
	retryMu.Unlock()
	t.Cleanup(func() {
		retryMu.Lock()
		retryQueue = orig
		retryMu.Unlock()
	})
}

func TestEnqueueRetry_MaxAttempts(t *testing.T) {
	snapshotRetryQueue(t)

	// Should not enqueue when attempt >= max.
	enqueueRetry("hook-1", Payload{Event: "test"}, retryMax)
	retryMu.Lock()
	count := len(retryQueue)
	retryMu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 entries after max attempts, got %d", count)
	}
}

func TestEnqueueRetry_Success(t *testing.T) {
	snapshotRetryQueue(t)

	enqueueRetry("hook-1", Payload{Event: "test"}, 0)
	retryMu.Lock()
	count := len(retryQueue)
	retryMu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 entry, got %d", count)
	}
}

func TestProcessRetryQueue_Empty(t *testing.T) {
	snapshotRetryQueue(t)

	// Should not panic on empty queue (nil store is also tolerated).
	processRetryQueue(&Store{})
	processRetryQueue(nil)
}

func TestSaveRetryQueueLocked(t *testing.T) {
	snapshotRetryQueue(t)
	retryMu.Lock()
	retryQueue = []retryEntry{{WebhookID: "test", Attempt: 0}}
	retryMu.Unlock()

	// Should not panic.
	retryMu.Lock()
	saveRetryQueueLocked()
	retryMu.Unlock()
}

// TestRetryQueue_Save_NoTmpLeak verifies the retry-queue writer
// (fileutil.AtomicWrite) does not leave orphaned *.tmp.* files.
// Redirects retryFile to a temp dir and seeds one entry to ensure
// the writer actually runs.
func TestRetryQueue_Save_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()

	origFile := retryFile
	retryFile = filepath.Join(dir, "alert_retry_queue.json")
	t.Cleanup(func() { retryFile = origFile })

	snapshotRetryQueue(t)
	retryMu.Lock()
	retryQueue = []retryEntry{{
		WebhookID: "wh-tmpleak",
		Payload:   Payload{Event: "test"},
		Attempt:   1,
		NextRetry: time.Now().Add(time.Minute),
	}}
	saveRetryQueueLocked()
	retryMu.Unlock()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("orphaned tmp file: %s", e.Name())
		}
	}
}
