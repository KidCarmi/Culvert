package main

import (
	"path/filepath"
	"testing"
	"time"
)

// TestAlertRetryQueue_Save_NoTmpLeak verifies the converted retry-queue
// writer (atomicWriteFile) does not leave orphaned *.tmp.* files.
// Redirects alertRetryFile to a temp dir and seeds one entry to ensure
// the writer actually runs.
func TestAlertRetryQueue_Save_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()

	origFile := alertRetryFile
	alertRetryFile = filepath.Join(dir, "alert_retry_queue.json")
	t.Cleanup(func() { alertRetryFile = origFile })

	alertRetryMu.Lock()
	origQueue := alertRetryQueue
	alertRetryQueue = []retryEntry{{
		WebhookID: "wh-tmpleak",
		Payload:   AlertPayload{Event: "test"},
		Attempt:   1,
		NextRetry: time.Now().Add(time.Minute),
	}}
	alertRetryMu.Unlock()
	t.Cleanup(func() {
		alertRetryMu.Lock()
		alertRetryQueue = origQueue
		alertRetryMu.Unlock()
	})

	saveAlertRetryQueueLocked()
	assertNoTmpLeak(t, dir)
}
