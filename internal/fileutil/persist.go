package fileutil

// persist.go — CHAOS-27 / F-12: a durable write that FAILS must never be silent.
//
// Every config store in Culvert persists through AtomicWrite, and until this
// file existed the overwhelming majority of them discarded its error:
//
//	_ = fileutil.AtomicWrite(s.path, data, 0o600)
//
// On a full, read-only, or permission-broken data directory that produces the
// worst class of failure an appliance can have — a SILENT one. The admin edits
// a policy rule, the API returns 200, the UI shows the new rule, the in-memory
// store enforces it… and the next restart reloads the OLD file. Nothing logged,
// nothing counted, nothing alerted; the operator learns about it from a
// post-incident diff. The same discard made config-version rollback report
// success after persisting nothing (the CHAOS-27 headline).
//
// AtomicWriteTracked is AtomicWrite plus accounting. It records per-store
// failure state, keeps a monotonic global sequence so a caller can ask "did any
// durable write fail while I was applying this?" (see PersistFailuresSince, used
// by the rollback path), and calls a reporter hook so package main can log,
// alert, and expose the failure without this package depending on the rest of
// Culvert (the package contract is stdlib-only; ADR-0003).
//
// The tracking is deliberately edge-triggered: a store that fails, then
// succeeds, reports a recovery. That makes the derived signals (the
// currently-failing set, the /readyz rows, the Prometheus gauge) describe the
// CURRENT state of the disk rather than accumulating scar tissue, while the
// per-store totals stay monotonic for rate() queries.

import (
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// PersistFailure is the recorded state of a store whose durable write failed.
type PersistFailure struct {
	// Store is the stable logical name of the state file (metric label).
	Store string
	// Path is the file that could not be written.
	Path string
	// Err is the stringified write error (retained as a string so callers
	// cannot accidentally hold a reference into the failing syscall path).
	Err string
	// At is when the most recent failure was recorded.
	At time.Time
	// Consecutive counts failures since the last success for this store.
	Consecutive uint64
	// Total counts failures for this store since process start.
	Total uint64
	// Seq is the global failure sequence at the most recent failure.
	Seq uint64
}

// PersistEvent is what the reporter hook receives. Exactly one of Err (a
// failure) or Recovered (the first success after one) is set.
type PersistEvent struct {
	Store string
	Path  string
	// Err is the write error; nil on a recovery event.
	Err error
	// Recovered is true when this store's write succeeded after failing.
	Recovered bool
	// Consecutive is the number of back-to-back failures INCLUDING this one
	// (1 on the transition into failing). Zero on a recovery event.
	Consecutive uint64
	// Total is this store's failure count since process start.
	Total uint64
}

var (
	persistMu sync.Mutex
	// persistFailing holds only CURRENTLY-failing stores (cleared on success).
	persistFailing = map[string]PersistFailure{}
	// persistTotals is monotonic per store for the whole process lifetime.
	persistTotals = map[string]uint64{}

	persistSeq   atomic.Uint64 // global failure sequence, monotonic
	persistTotal atomic.Uint64 // global failure count, monotonic

	persistReporter atomic.Pointer[func(PersistEvent)]
)

// SetPersistFailureReporter installs the hook called on every durable-write
// failure and on the first success after a failure (a recovery event). Package
// main installs a reporter that logs, alerts, and feeds /readyz. A nil fn clears
// the hook. The hook is called WITHOUT the package lock held, but possibly with
// a caller's store lock held — it must not block and must never re-enter the
// store it is reporting on.
func SetPersistFailureReporter(fn func(PersistEvent)) {
	if fn == nil {
		persistReporter.Store(nil)
		return
	}
	persistReporter.Store(&fn)
}

// AtomicWriteTracked performs an AtomicWrite and records the outcome under the
// logical store name. The error is returned unchanged so callers that can act on
// it still may; callers that cannot are no longer silent, because the failure is
// now counted, logged, alerted, and surfaced on /readyz and /metrics.
func AtomicWriteTracked(store, path string, data []byte, perm os.FileMode) error {
	err := AtomicWrite(path, data, perm)
	recordPersistOutcome(store, path, err)
	return err
}

// recordPersistOutcome updates the registry and fires the reporter on state
// edges (new/continued failure, or recovery).
func recordPersistOutcome(store, path string, err error) {
	if err == nil {
		persistMu.Lock()
		_, wasFailing := persistFailing[store]
		delete(persistFailing, store)
		total := persistTotals[store]
		persistMu.Unlock()
		if wasFailing {
			report(PersistEvent{Store: store, Path: path, Recovered: true, Total: total})
		}
		return
	}

	seq := persistSeq.Add(1)
	persistTotal.Add(1)

	persistMu.Lock()
	prev := persistFailing[store]
	persistTotals[store]++
	rec := PersistFailure{
		Store:       store,
		Path:        path,
		Err:         err.Error(),
		At:          time.Now(),
		Consecutive: prev.Consecutive + 1,
		Total:       persistTotals[store],
		Seq:         seq,
	}
	persistFailing[store] = rec
	persistMu.Unlock()

	report(PersistEvent{
		Store:       store,
		Path:        path,
		Err:         err,
		Consecutive: rec.Consecutive,
		Total:       rec.Total,
	})
}

func report(ev PersistEvent) {
	if p := persistReporter.Load(); p != nil {
		(*p)(ev)
	}
}

// PersistFailureSeq returns the current global durable-write failure sequence.
// It only ever increases. A caller that samples it before and after a
// multi-store operation can detect that SOME durable write failed in between —
// the primitive the config-rollback path uses to stop reporting success after a
// partial-durability apply.
func PersistFailureSeq() uint64 { return persistSeq.Load() }

// PersistFailureTotal returns the process-wide count of failed durable writes.
func PersistFailureTotal() uint64 { return persistTotal.Load() }

// PersistFailures returns a snapshot of the stores whose LAST durable write
// failed (i.e. the state files currently believed to be stale on disk). Empty
// when persistence is healthy.
func PersistFailures() []PersistFailure {
	persistMu.Lock()
	defer persistMu.Unlock()
	out := make([]PersistFailure, 0, len(persistFailing))
	for _, f := range persistFailing {
		out = append(out, f)
	}
	return out
}

// PersistFailureTotals returns per-store monotonic failure counts since process
// start, including stores that have since recovered.
func PersistFailureTotals() map[string]uint64 {
	persistMu.Lock()
	defer persistMu.Unlock()
	out := make(map[string]uint64, len(persistTotals))
	for k, v := range persistTotals {
		out[k] = v
	}
	return out
}

// PersistFailuresSince returns the names of stores that are CURRENTLY failing
// (their most recent durable write failed) and whose most recent failure
// happened after the given sequence value. Results are sorted by store name.
//
// Attribution is conservative by construction: a concurrent save of an
// unrelated store that fails inside the window is reported too. That is the
// correct bias — the fact being reported ("a durable write failed while this
// operation ran, treat the result as not durable") is true either way, and an
// under-report would put us back in the silent-failure regime this file exists
// to end.
func PersistFailuresSince(seq uint64) []string {
	persistMu.Lock()
	defer persistMu.Unlock()
	var out []string
	for name, f := range persistFailing {
		if f.Seq > seq {
			out = append(out, name)
		}
	}
	sortStrings(out)
	return out
}

// sortStrings is a tiny insertion sort — this package is stdlib-only by
// contract and the slices are single-digit in every real call.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ResetPersistTrackingForTest clears all recorded state. Test isolation only —
// production never un-records a failure except through a successful rewrite of
// the same store.
func ResetPersistTrackingForTest() {
	persistMu.Lock()
	persistFailing = map[string]PersistFailure{}
	persistTotals = map[string]uint64{}
	persistMu.Unlock()
	persistSeq.Store(0)
	persistTotal.Store(0)
	persistReporter.Store(nil)
}
