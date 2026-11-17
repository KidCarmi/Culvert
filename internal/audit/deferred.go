package audit

// deferred.go — completing a configured audit log that could not be opened at
// STARTUP.
//
// Init failing (a missing directory, wrong ownership, a volume that is not yet
// writable) used to be terminal for the life of the process: the trail fell
// back to the volatile ring and the only documented recovery was "fix the
// path, then restart". The restart is pure toil — the configured path is the
// operator's standing intent and opening it is exactly what Init would do —
// and it also costs every entry recorded in between, because nothing kept them
// for the file.
//
// The caller (package main, at its runtime boot site only) arms a deferred
// open with ArmDeferredOpen after Init fails. From then on:
//
//   - Add keeps a copy of each entry in a bounded backlog (MaxRing, the same
//     bound as the ring), so the gap can be written once the path opens.
//   - TryDeferredOpen opens the SAME path with the same rotation Init uses,
//     writes the backlog in order, and only then publishes the sink — all in
//     one critical section with Add, so no newer entry can land in the file
//     ahead of an older one and no entry is written twice.
//   - Entries the backlog had to discard are charged to WriteErrors when the
//     file opens: they are entries that never reached the durable record.
//
// What it deliberately does NOT do:
//
//   - choose a path. It retries only the path the operator configured.
//   - arm itself. Init's contract is unchanged: a one-shot command that must
//     REFUSE when its audit sink is unavailable (prepare-downgrade) never
//     arms a deferred open, so it can never silently proceed.
//   - act after Close. The shutdown hook closes the sink; a deferred open
//     racing it is refused and its file released, so no handle is published
//     that nothing will close.
//   - replace a live sink. If anything installed persistence meanwhile the
//     attempt releases its file and disarms.
//   - reload history into the ring. Older entries already on disk stay
//     readable through the paginated persistent reads.

import (
	"fmt"
	"sync"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// rotateMaxMB is the rotation threshold shared by Init and the deferred open.
const rotateMaxMB = 50

var (
	// deferredPath is the configured path whose open failed and is still
	// wanted; "" means nothing is pending. Guarded by mu.
	deferredPath string
	// backlog holds the entries added while deferredPath was pending, oldest
	// first, bounded to MaxRing. Guarded by mu.
	backlog []Entry
	// backlogDropped counts entries evicted from the full backlog. Guarded by mu.
	backlogDropped int
	// closed records that the shutdown hook ran Close. Guarded by mu.
	closed bool

	// deferredOpenMu serializes TryDeferredOpen so two callers can never both
	// open the file and race to publish it.
	deferredOpenMu sync.Mutex
)

// ArmDeferredOpen records that path — the operator-configured audit log whose
// Init just failed — should be opened as soon as it becomes openable. It is a
// no-op for an empty path, after Close, or when persistence is already wired.
// It reports whether a deferred open is now pending.
func ArmDeferredOpen(path string) bool {
	if path == "" {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	if closed || persist != nil {
		return false
	}
	if deferredPath != path {
		backlog, backlogDropped = nil, 0
	}
	deferredPath = path
	return true
}

// DeferredOpenPending reports the path awaiting a deferred open, or "".
func DeferredOpenPending() string {
	mu.Lock()
	defer mu.Unlock()
	if closed || persist != nil {
		return ""
	}
	return deferredPath
}

// backlogLocked keeps a copy of e for a pending deferred open. Caller holds mu
// and has observed persist == nil.
func backlogLocked(e Entry) {
	if deferredPath == "" || closed {
		return
	}
	backlog = append(backlog, e)
	if over := len(backlog) - MaxRing; over > 0 {
		backlogDropped += over
		backlog = backlog[over:]
	}
}

// DeferredOpenResult describes a deferred open that succeeded.
type DeferredOpenResult struct {
	Path       string // the configured path now persisting
	Backfilled int    // backlog entries handed to the file
	Dropped    int    // entries evicted from the full backlog (charged to WriteErrors)
}

// TryDeferredOpen makes one attempt to open the pending path. It returns
// (result, true, nil) when the file is now the live sink, (zero, false, err)
// when the path is still not openable (the deferred open stays armed), and
// (zero, false, nil) when nothing is pending any more — disarmed, closed, or
// persistence installed by something else. Safe to call concurrently.
func TryDeferredOpen() (DeferredOpenResult, bool, error) {
	deferredOpenMu.Lock()
	defer deferredOpenMu.Unlock()

	mu.Lock()
	if persist != nil {
		// Another writer is live; this record no longer describes a gap.
		deferredPath, backlog, backlogDropped = "", nil, 0
	}
	path := deferredPath
	if closed {
		path = ""
	}
	mu.Unlock()
	if path == "" {
		return DeferredOpenResult{}, false, nil
	}
	// The open happens outside mu: it is filesystem I/O and Add must not wait
	// on it. Everything that decides whether to USE the file is re-checked
	// under mu below.
	rf, err := fileutil.NewRotatingFile(path, rotateMaxMB)
	if err != nil {
		return DeferredOpenResult{}, false, fmt.Errorf("audit log open %s: %w", path, err)
	}

	mu.Lock()
	if closed || persist != nil || deferredPath != path {
		if persist != nil {
			// Another writer is live; this record no longer describes a gap.
			deferredPath, backlog, backlogDropped = "", nil, 0
		}
		mu.Unlock()
		_ = rf.Close()
		return DeferredOpenResult{}, false, nil
	}
	res := DeferredOpenResult{Path: path, Backfilled: len(backlog), Dropped: backlogDropped}
	// Backfill BEFORE publishing, under mu: a concurrent Add blocks on mu,
	// then sees the published sink and writes after the backlog, so the file
	// keeps Add order and no entry is written twice. Each record is charged
	// exactly as a live write would be (persistEntry), and the observers it
	// calls must not call Add (their documented contract), so holding mu here
	// cannot deadlock.
	for i := range backlog {
		persistEntry(rf, path, backlog[i])
	}
	for i := 0; i < backlogDropped; i++ {
		countWriteError(path, fmt.Errorf("audit entry evicted from the %d-entry backlog before the configured log could be opened", MaxRing))
	}
	persist, persistC, persistPath = rf, rf, path
	deferredPath, backlog, backlogDropped = "", nil, 0
	mu.Unlock()
	return res, true, nil
}

// resetDeferredLocked clears the deferred-open state. Caller holds mu.
func resetDeferredLocked() {
	deferredPath, backlog, backlogDropped, closed = "", nil, 0, false
}
