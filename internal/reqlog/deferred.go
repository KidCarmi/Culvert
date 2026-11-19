package reqlog

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Deferred open of a configured request log whose STARTUP open failed.
//
// The runtime boot path tolerates a failed Init: it logs the error and keeps
// the volatile ring. Before this file nothing ever opened the configured path
// again, so the request log stayed in-memory only until an operator fixed the
// path AND restarted the proxy. Opening the configured path is exactly what
// startup already tried; ArmDeferredOpen records that intent and
// TryDeferredOpen re-attempts it, publishing the sink through the same
// transition Init uses.
//
// Deliberately NOT done: replaying the ring into the file. Add writes the ring
// and enqueues for persistence outside one critical section, so a backfill
// taken while the sink is being published could write an entry twice or skip
// it, and making it exact would put new work on the per-request hot path. The
// file therefore starts at the moment it opens, which is what a restart would
// have produced too (minus the restart, which also loses the ring). Entries
// recorded before the open stay readable in the ring.
//
// Refusals, all re-checked under writerMu after the open returns: nothing
// armed, a sink already wired (startup or another Init succeeded), or Close
// has run (shutdown). The chosen path is always the armed one; nothing here
// picks a different path.
var (
	// deferredMu serializes attempts and guards the armed intent.
	deferredMu    sync.Mutex
	deferredPath  string // "" = nothing armed
	deferredMaxMB int

	// closedForDeferred is set by Close BEFORE it stops persistence, so an
	// attempt that opens the file while Close runs is discarded rather than
	// published behind the shutdown hook. An atomic (not deferredMu) so Close
	// never waits behind an open(2) on a stalled volume.
	closedForDeferred atomic.Bool
)

// ArmDeferredOpen records that the configured request log at path, whose
// startup Init just failed, should be opened once it becomes writable. It
// reports whether anything was armed: an empty path, a sink already wired, or
// a closed log arm nothing. maxMB carries the same rotation size Init was
// given (≤ 0 means Init's default).
func ArmDeferredOpen(path string, maxMB int) bool {
	if path == "" || closedForDeferred.Load() || PersistActive() {
		return false
	}
	deferredMu.Lock()
	defer deferredMu.Unlock()
	deferredPath, deferredMaxMB = path, maxMB
	return true
}

// DeferredOpenPending returns the armed path, or "" when nothing is pending.
func DeferredOpenPending() string {
	deferredMu.Lock()
	defer deferredMu.Unlock()
	return deferredPath
}

// disarmLocked clears the armed intent. Caller holds deferredMu.
func disarmLocked() { deferredPath, deferredMaxMB = "", 0 }

// publishDeferredSink installs rf as the live request-log sink and starts the
// drain, reporting false when it must not publish (Close ran, or another Init
// already wired a sink). Caller holds deferredMu.
//
// It exists so writerMu is released by DEFER. The unlock used to be explicit
// and straddled startPersist, which is the one claim the retry loop makes about
// this owner — "the owner releases its locks by defer/explicit unlock, so a
// recovered round simply counts as a failed attempt"
// (request_log_persist_retry.go). That did not hold for a panic: runGuarded
// recovers the round and keeps retrying, so a panic in here left writerMu
// write-locked for the life of the process with no crash and no alert. Every
// reader of the sink (FilePath, PersistActive, Sync, the admin
// ReadPersistent) then blocks, the persistence queue is deliberately blocking
// rather than load-shedding, and once it fills every proxied request wedges in
// reqlog.Add — a silent proxy-wide hang. The publish order is unchanged; only
// the unlock is now unconditional.
func publishDeferredSink(rf *fileutil.RotatingFile, path string) bool {
	writerMu.Lock()
	defer writerMu.Unlock()
	if closedForDeferred.Load() || closer != nil {
		return false
	}
	writer, closer, filePath = rf, rf, path
	startPersist()
	return true
}

// TryDeferredOpen makes one attempt to open the armed path. It returns
// opened=true with the path once the sink is published. opened=false with a
// nil error means nothing is pending any more (never armed, a sink already
// wired, or the log was closed) and the caller should stop. A non-nil error
// means the path is still not writable and the intent stays armed.
func TryDeferredOpen() (path string, opened bool, err error) {
	deferredMu.Lock()
	defer deferredMu.Unlock()
	path, maxMB := deferredPath, deferredMaxMB
	if path == "" {
		return "", false, nil
	}
	if closedForDeferred.Load() || PersistActive() {
		disarmLocked()
		return path, false, nil
	}
	if maxMB <= 0 {
		maxMB = 100 // Init's default
	}
	rf, err := fileutil.NewRotatingFile(path, maxMB)
	if err != nil {
		return path, false, fmt.Errorf("request log open %s: %w", path, err)
	}

	if !publishDeferredSink(rf, path) {
		// Close ran, or another Init wired a sink, while the open was in
		// flight: never replace it and never publish behind the shutdown hook.
		_ = rf.Close()
		disarmLocked()
		return path, false, nil
	}
	disarmLocked()
	// Close may have marked the log closed after the check above and run its
	// stopPersist BEFORE the startPersist just made, which would leave a drain
	// goroutine running behind the shutdown hook. Re-check now that it has
	// started: either Close's stopPersist runs after this point and stops it,
	// or this one does (stopPersist is idempotent). Close itself still closes
	// the file, which is now its closer.
	if closedForDeferred.Load() {
		stopPersist()
		return path, false, nil
	}

	// Drop any cached parse, as Init does.
	readCache.mu.Lock()
	readCache.path = ""
	readCache.entries = nil
	readCache.mu.Unlock()
	return path, true, nil
}

// resetDeferredForTest clears the armed intent and the closed mark.
func resetDeferredForTest() {
	deferredMu.Lock()
	disarmLocked()
	deferredMu.Unlock()
	closedForDeferred.Store(false)
}
