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
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

const (
	// storageWriteAlertInterval rate-limits the storage_write_failed alert
	// and its log line. A failing disk fails EVERY write, so an un-gated
	// producer would flood the webhook queue and the log with one entry per
	// save. One signal per interval is enough to page an operator; the
	// counter and the operator-contract row carry the magnitude.
	storageWriteAlertInterval = 5 * time.Minute

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

	// lastOK is the most recent OBSERVED successful durable write. Recovery is
	// established by evidence, never by elapsed time: a filesystem that is
	// still read-only or still full looks exactly like a healthy one if
	// nothing happens to write during the window. While lastOK is not after
	// `last`, persistence stays degraded (Codex P1).
	lastOK time.Time

	// logAt / alertAt are SEPARATE rate gates. They must not be shared: a
	// failure writing the alert engine's own retry queue is logged but never
	// alerted (see alertRetryQueueBase), and if it consumed the alert gate it
	// would suppress the next real store failure for a full interval —
	// silencing the page during exactly the disk incident it exists for
	// (Codex P2).
	logAt   time.Time
	alertAt time.Time

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
	// Nobody subscribed → do nothing at all, and in particular do not spawn a
	// goroutine. This producer is driven by an EXTERNAL fault: a failing disk
	// fires it from arbitrary goroutines at arbitrary moments. Spawning a
	// delivery goroutine for an alert with no recipient would inject goroutine
	// churn into every node that has no webhooks configured — the default
	// posture, and the state of every test binary, where it shows up as
	// spurious failures in guardrails that sample runtime.NumGoroutine().
	if !globalAlertStore.HasSubscriber("storage_write_failed") {
		return
	}
	go fireAlert("storage_write_failed", AlertPayload{
		Detail: detail,
		Source: "storage",
	})
}

// storageEverFailed short-circuits the success observer until the first
// failure, so the success path stays a single atomic load on a healthy node.
var storageEverFailed atomic.Bool

func init() {
	fileutil.SetWriteFailureObserver(noteStorageWriteFailure)
	fileutil.SetWriteSuccessObserver(noteStorageWriteSuccess)
	// The audit JSONL log does NOT go through fileutil.AtomicWrite — it is an
	// append-only fileutil.RotatingFile — so the chokepoint observer above
	// never saw it, and internal/audit discarded its write error outright.
	// That made a failing volume able to silently destroy the durable
	// "who changed what" record while the admin UI kept rendering entries
	// from the volatile in-memory ring (register item ST-8). Route it into
	// the SAME storage-health plane: counter, degraded operator-contract row,
	// Prometheus series, and the rate-limited storage_write_failed alert.
	//
	// Safe against the recursion documented on internal/audit's observer
	// contract: noteStorageWriteFailure writes no audit entry, and the alert
	// it dispatches is audit-free (internal/alerts never calls audit.Add).
	audit.SetWriteFailureObserver(noteStorageWriteFailure)
	// The success half is not optional: storageDegraded() clears only on an
	// OBSERVED successful write ("silence is not recovery"). Wiring the failure
	// producer alone would pin a node degraded forever after one transient
	// blip, on any node whose only durable writes are audit entries.
	audit.SetWriteSuccessObserver(noteStorageWriteSuccess)
}

// noteStorageWriteFailure is the fileutil observer. It runs synchronously on
// the goroutine whose durable write just failed, possibly under a store lock,
// so it does memory-only work and hands the alert off to a goroutine.
func noteStorageWriteFailure(path string, err error) {
	base := filepath.Base(path)
	// Two barriers applied ONCE here, at the point the values enter shared
	// state, so every downstream sink (log line, alert detail,
	// operator-contract message, rollback API response) is fed clean text:
	//
	//  1. CWE-117 — sanitizeLog is the project-standard control-character
	//     barrier CodeQL recognises.
	//  2. Path redaction — the operator contract (/api/diagnostics) is a
	//     VIEWER-role surface with a standing no-sensitive-values guardrail
	//     that forbids raw filesystem paths (diagnostics_test.go's
	//     TestApiDiagnostics_NoSensitiveValues). AtomicWrite's error text
	//     embeds the absolute target and temp paths, so reporting the cause
	//     verbatim would leak the data-directory layout to every viewer the
	//     moment a write failed. Only base names survive.
	safeBase := sanitizeLog(base)
	safeErr := ""
	if err != nil {
		safeErr = sanitizeLog(redactWritePath(err.Error(), path))
	}
	now := time.Now()

	// A failure writing the alert engine's own retry queue is counted and
	// logged but never alerted, and — critically — never touches the ALERT
	// gate, so it cannot suppress the page for a real store failure that
	// follows it within the interval.
	alertable := base != alertRetryQueueBase

	storageEverFailed.Store(true)

	storageWrites.mu.Lock()
	storageWrites.total++
	storageWrites.last = now
	storageWrites.lastPath = safeBase
	storageWrites.lastErr = safeErr
	total := storageWrites.total
	for sc := range storageWrites.scopes {
		sc.record(safeBase, safeErr)
	}
	// Two independent gates, both evaluated under the lock so concurrent
	// failing writers cannot both pass.
	doLog := storageWrites.logAt.IsZero() || now.Sub(storageWrites.logAt) >= storageWriteAlertInterval
	if doLog {
		storageWrites.logAt = now
	}
	doAlert := alertable &&
		(storageWrites.alertAt.IsZero() || now.Sub(storageWrites.alertAt) >= storageWriteAlertInterval)
	if doAlert {
		storageWrites.alertAt = now
	}
	storageWrites.mu.Unlock()

	// The observer is installed at init, which can precede initLogger for a
	// write that fails during very early startup.
	if doLog && logger != nil {
		logger.Printf("Storage: DURABLE WRITE FAILED for %q (%d since boot) — persisted state is being lost: %q",
			safeBase, total, safeErr)
	}
	if doAlert {
		fireStorageWriteAlert(fmt.Sprintf("durable write to %s failed (%d failures since boot): %s",
			safeBase, total, safeErr))
	}
}

// noteStorageWriteSuccess records an OBSERVED successful durable write. This is
// the only thing that clears the degraded state — see storageWriteHealth.lastOK.
//
// The common case (no failure has ever been recorded) takes no lock: the
// atomic guard keeps the cost of observing every successful durable write to a
// single relaxed load.
func noteStorageWriteSuccess(string) {
	if !storageEverFailed.Load() {
		return
	}
	now := time.Now()
	storageWrites.mu.Lock()
	storageWrites.lastOK = now
	storageWrites.mu.Unlock()
}

// redactWritePath strips the directory prefix from every occurrence of the
// failing path inside msg, leaving base names only.
//
// AtomicWrite's error text names both the target and the temp file it created
// beside it — e.g.
//
//	atomic write /data/config_versions/v9.json: create temp: open
//	/data/config_versions/v9.json.tmp.24: no such file or directory
//
// Both live in the same directory, so removing that one prefix redacts every
// path in the message while preserving the operator-actionable part (which
// file, which syscall, which errno). Applied at the recording boundary, not at
// each sink, so a future consumer of the record cannot reintroduce the leak.
func redactWritePath(msg, path string) string {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." || dir == string(filepath.Separator) {
		return msg
	}
	msg = strings.ReplaceAll(msg, dir+string(filepath.Separator), "")
	// A trailing reference to the bare directory (no separator) can remain,
	// e.g. a mkdir/permission error naming the parent.
	return strings.ReplaceAll(msg, dir, "")
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

// storageDegraded reports whether persistence should be treated as broken
// RIGHT NOW. Used by the operator contract and /metrics.
//
// Degraded means: a durable write has failed, and NO successful durable write
// has been observed since. Recovery is established by evidence only. An
// earlier draft aged the failure out after a fixed window, which was wrong in
// the exact scenario that matters: a filesystem that stays read-only or full
// but happens to receive no write attempts is indistinguishable from a healthy
// one under a timer, so the node would quietly report itself recovered without
// a single successful write to justify it (Codex P1).
//
// Recovery evidence is process-wide, not per-path: any successful durable
// write clears the state, not necessarily one to the file that failed. That is
// deliberate — the failure modes this exists for (volume remounted read-only,
// filesystem or inode table full, quota engaged) are directory- or
// filesystem-wide, and the file that failed may never be written again.
func storageDegraded() bool {
	storageWrites.mu.Lock()
	defer storageWrites.mu.Unlock()
	if storageWrites.total == 0 {
		return false
	}
	return !storageWrites.lastOK.After(storageWrites.last)
}

// storageRecoveryObserved reports whether a successful durable write has been
// seen since the last failure — i.e. the incident is historical.
func storageRecoveryObserved() bool {
	storageWrites.mu.Lock()
	defer storageWrites.mu.Unlock()
	return storageWrites.total > 0 && storageWrites.lastOK.After(storageWrites.last)
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
	storageWrites.lastOK = time.Time{}
	storageWrites.logAt = time.Time{}
	storageWrites.alertAt = time.Time{}
	storageWrites.scopes = nil
	storageEverFailed.Store(false)
}
