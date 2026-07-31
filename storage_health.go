package main

// storage_health.go — runtime durable-write health (CHAOS-45).
//
// Before this file the only storage signal Culvert produced was
// probeStorageWritability: a ONE-SHOT temp-file probe at startup whose verdict
// was cached for the rest of the process lifetime (diagnostics.go). Every
// failure mode that arrives *after* boot — the data volume remounting
// read-only, the filesystem filling up, a quota kicking in, the host revoking
// the mount — was therefore invisible:
//
//   - fileutil.AtomicWrite is the durable-write chokepoint for every persisted
//     store, and a dozen call sites across eight engines discard its error
//     outright (`_ = fileutil.AtomicWrite(...)`) because the surrounding
//     Save() returns nothing.
//   - so a config change made through the admin API answers 200, renders from
//     memory, and evaporates on the next restart.
//   - and checkStorage() kept reporting "data directory writable (verified
//     once at startup)" the whole time.
//
// This file closes that loop from the chokepoint: package main publishes a
// fileutil write-failure observer at init, records every failure, degrades the
// operator-contract storage row, exports Prometheus series, and fires a
// rate-limited `storage_write_failed` alert. It also provides the scoped
// collector that lets a caller (config rollback) report which of ITS writes
// failed instead of returning success over a partial-durability apply.

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

const (
	// storageWriteAlertInterval rate-limits the storage_write_failed alert
	// and its log line. A failing disk fails EVERY write, so an un-gated
	// producer would flood the webhook queue and the log with one entry per
	// save. One signal per interval is enough to page an operator; the
	// counter and the operator-contract row carry the magnitude.
	storageWriteAlertInterval = 5 * time.Minute

	// storageDegradedWindow is how long after the most recent failure the
	// operator contract reports storage as FAILING rather than as a healed
	// historical incident. Sized above storageWriteAlertInterval so a
	// still-broken disk never flips back to a non-fail verdict between alerts.
	storageDegradedWindow = 15 * time.Minute

	// alertRetryQueueBase is the alert engine's own persistent retry queue
	// (internal/alerts). A failure writing THAT file must never fire an alert:
	// alerts.Dispatch can synchronously write the retry queue when the
	// delivery semaphore is full, so alerting on it would recurse and, worse,
	// re-enter the retry mutex the failing writer already holds. Failures on
	// this file are still counted and still degrade the contract row.
	alertRetryQueueBase = "alert_retry_queue.json"
)

// storageWriteHealth is the process-wide record of durable-write failures.
type storageWriteHealth struct {
	mu       sync.Mutex
	total    int64
	last     time.Time
	lastPath string
	lastErr  string
	alertAt  time.Time

	// scopes are the currently-open collectors (see beginStorageWriteScope).
	// Nil until a scope opens; a rollback is the only production user.
	scopes map[*storageWriteScope]struct{}
}

var storageWrites storageWriteHealth

// fireStorageWriteAlert delivers the storage_write_failed alert. Package-level
// seam so tests capture transitions SYNCHRONOUSLY rather than racing the
// process-global alerts sink (the -count/-shuffle determinism class the CI
// gate catches). The production value fires async for the reason documented on
// alertRetryQueueBase: the observer runs on the failing goroutine, which may
// hold a store lock, and alerts.Dispatch can block on a disk write.
var fireStorageWriteAlert = func(detail string) {
	go fireAlert("storage_write_failed", AlertPayload{
		Detail: detail,
		Source: "storage",
	})
}

func init() {
	fileutil.SetWriteFailureObserver(noteStorageWriteFailure)
}

// noteStorageWriteFailure is the fileutil observer. It runs synchronously on
// the goroutine whose durable write just failed, possibly under a store lock,
// so it does memory-only work and hands the alert off to a goroutine.
func noteStorageWriteFailure(path string, err error) {
	base := filepath.Base(path)
	// Inline ReplaceAll so CodeQL sees the CWE-117 sanitiser at the call site
	// (the path and the error text both embed caller-influenced content).
	safeBase := strings.ReplaceAll(strings.ReplaceAll(base, "\n", "_"), "\r", "_")
	safeErr := ""
	if err != nil {
		safeErr = strings.ReplaceAll(strings.ReplaceAll(err.Error(), "\n", "_"), "\r", "_")
	}
	now := time.Now()

	storageWrites.mu.Lock()
	storageWrites.total++
	storageWrites.last = now
	storageWrites.lastPath = safeBase
	storageWrites.lastErr = safeErr
	total := storageWrites.total
	for sc := range storageWrites.scopes {
		sc.record(safeBase, safeErr)
	}
	// Rate-gate the noisy surfaces (log + alert) under the same lock so
	// concurrent failing writers cannot both pass the gate.
	notify := storageWrites.alertAt.IsZero() || now.Sub(storageWrites.alertAt) >= storageWriteAlertInterval
	if notify {
		storageWrites.alertAt = now
	}
	storageWrites.mu.Unlock()

	if !notify {
		return
	}
	// The observer is installed at init, which can precede initLogger for a
	// write that fails during very early startup.
	if logger != nil {
		logger.Printf("Storage: DURABLE WRITE FAILED for %q (%d since boot) — persisted state is being lost: %s",
			safeBase, total, safeErr)
	}
	if base == alertRetryQueueBase {
		// Counted and logged, never alerted — see alertRetryQueueBase.
		return
	}
	fireStorageWriteAlert(fmt.Sprintf("durable write to %s failed (%d failures since boot): %s",
		safeBase, total, safeErr))
}

// storageWriteSnapshot is a consistent read of the failure record.
type storageWriteSnapshot struct {
	Total int64
	Last  time.Time
	Path  string
	Err   string
}

// storageWriteFailures returns the current durable-write failure record.
func storageWriteFailures() storageWriteSnapshot {
	storageWrites.mu.Lock()
	defer storageWrites.mu.Unlock()
	return storageWriteSnapshot{
		Total: storageWrites.total,
		Last:  storageWrites.last,
		Path:  storageWrites.lastPath,
		Err:   storageWrites.lastErr,
	}
}

// storageDegraded reports whether a durable write failed recently enough that
// persistence should be treated as broken RIGHT NOW (as opposed to a healed
// historical incident). Used by the operator contract and /metrics.
func storageDegraded() bool {
	s := storageWriteFailures()
	return s.Total > 0 && time.Since(s.Last) < storageDegradedWindow
}

// ── Scoped collection ────────────────────────────────────────────────────────

// storageWriteScope collects the durable-write failures observed while it is
// open, so an orchestrating caller can report exactly which of its persistence
// steps did not land.
//
// Scope membership is by TIME, not by goroutine: Go has no goroutine-local
// storage, and fileutil's observer is a process-wide seam. A concurrent
// unrelated write that fails inside the window is therefore attributed to the
// scope. That over-reporting is deliberate and safe in the one direction that
// matters — the scope exists to answer "is what I just applied durable?", and
// on a filesystem that is failing OTHER writes at the same instant the honest
// answer is no. Under-reporting would be the dangerous direction.
type storageWriteScope struct {
	mu       sync.Mutex
	failures []string
}

func (sc *storageWriteScope) record(base, errText string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	// Bounded: one entry per distinct file. A failing disk fails the same
	// handful of files repeatedly; the list is for naming them, not counting.
	for _, f := range sc.failures {
		if strings.HasPrefix(f, base+":") {
			return
		}
	}
	if len(sc.failures) >= 32 {
		return
	}
	sc.failures = append(sc.failures, base+": "+errText)
}

// beginStorageWriteScope opens a collector and returns the function that
// closes it. The returned function reports the failures observed while the
// scope was open; it is once-guarded, so a caller may both `defer` it (panic
// safety) and call it explicitly for the result.
func beginStorageWriteScope() func() []string {
	sc := &storageWriteScope{}
	storageWrites.mu.Lock()
	if storageWrites.scopes == nil {
		storageWrites.scopes = map[*storageWriteScope]struct{}{}
	}
	storageWrites.scopes[sc] = struct{}{}
	storageWrites.mu.Unlock()

	var once sync.Once
	var out []string
	return func() []string {
		once.Do(func() {
			storageWrites.mu.Lock()
			delete(storageWrites.scopes, sc)
			storageWrites.mu.Unlock()
			sc.mu.Lock()
			out = append([]string(nil), sc.failures...)
			sc.mu.Unlock()
		})
		return out
	}
}

// resetStorageWriteHealthForTest clears the record. Test-only helper kept in
// the production file so the state and its reset stay adjacent.
func resetStorageWriteHealthForTest() {
	storageWrites.mu.Lock()
	defer storageWrites.mu.Unlock()
	storageWrites.total = 0
	storageWrites.last = time.Time{}
	storageWrites.lastPath = ""
	storageWrites.lastErr = ""
	storageWrites.alertAt = time.Time{}
	storageWrites.scopes = nil
}
