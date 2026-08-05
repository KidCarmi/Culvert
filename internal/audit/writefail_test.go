package audit

import (
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// Durable-write failure accounting for the audit trail (register item ST-8).
//
// The audit JSONL file is the DURABLE compliance record — the in-memory ring
// holds only the newest MaxRing entries and is wiped on restart. Before this
// accounting existed, Add discarded the write error outright, so a full disk /
// read-only remount / failed post-rotation reopen destroyed the "who changed
// what" trail with no counter, no metric, no alert and no log line, while the
// admin UI kept rendering entries from the volatile ring.
//
// These tests pin the contract: every lost entry is counted, the observer sees
// it, a healthy writer stays at zero, and none of it can panic or block the
// admin plane it is recording.

// failWriter fails every write with a fixed error.
type failWriter struct{ err error }

func (f failWriter) Write(p []byte) (int, error) { return 0, f.err }

// shortWriter reports a SHORT write with a nil error — the truncated-line case
// an io.Writer seam may produce even though os.File reports io.ErrShortWrite.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) / 2, nil }

// countingWriter succeeds, recording how many entries it accepted.
type countingWriter struct {
	mu sync.Mutex
	n  int
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return len(p), nil
}

// withCleanAuditState isolates the process-global audit engine for one test:
// a fresh (empty) ring, the given persist sink, and zeroed write-error state.
func withCleanAuditState(t *testing.T, w io.Writer) {
	t.Helper()
	restoreRing := ResetForTest()
	restorePersist := SetPersistForTest(w)
	restoreErrs := ResetWriteErrorsForTest()
	t.Cleanup(func() {
		restoreErrs()
		restorePersist()
		restoreRing()
	})
}

func sampleEntry() Entry {
	return Entry{TS: 1, Time: "2026-08-05 00:00:00", Actor: "10.0.0.1", Action: "policy.add", Object: "rule-1"}
}

// TestWriteErrors_CountedOnFailingSink is the core regression test: an audit
// entry that never reaches the durable file must be COUNTED, not dropped
// silently.
func TestWriteErrors_CountedOnFailingSink(t *testing.T) {
	withCleanAuditState(t, failWriter{err: errors.New("no space left on device")})

	if got := WriteErrors(); got != 0 {
		t.Fatalf("WriteErrors() = %d before any Add; want 0", got)
	}
	Add(sampleEntry())
	if got := WriteErrors(); got != 1 {
		t.Fatalf("WriteErrors() = %d after one failed persist; want 1", got)
	}
	Add(sampleEntry())
	Add(sampleEntry())
	if got := WriteErrors(); got != 3 {
		t.Fatalf("WriteErrors() = %d after three failed persists; want 3", got)
	}
	// The entry must still reach the volatile ring — degraded persistence must
	// not also cost the in-memory trail.
	if got := len(Get()); got != 3 {
		t.Errorf("ring holds %d entries after 3 Adds; want 3 (persistence failure must not drop the in-memory record)", got)
	}
}

// TestWriteErrors_ZeroOnHealthySink is the negative case: a working sink must
// never charge a write error, so the counter stays a true fault signal.
func TestWriteErrors_ZeroOnHealthySink(t *testing.T) {
	cw := &countingWriter{}
	withCleanAuditState(t, cw)

	for i := 0; i < 5; i++ {
		Add(sampleEntry())
	}
	if got := WriteErrors(); got != 0 {
		t.Fatalf("WriteErrors() = %d on a healthy sink; want 0", got)
	}
	if cw.n != 5 {
		t.Fatalf("sink received %d writes; want 5", cw.n)
	}
}

// TestWriteErrors_ShortWriteIsCharged is the boundary case. A short write with
// a nil error leaves a TRUNCATED JSON line on disk: the entry is lost and the
// next append concatenates onto the fragment. Trusting the io.Writer seam to
// report io.ErrShortWrite itself would let that loss go uncounted.
func TestWriteErrors_ShortWriteIsCharged(t *testing.T) {
	withCleanAuditState(t, shortWriter{})

	Add(sampleEntry())
	if got := WriteErrors(); got != 1 {
		t.Fatalf("WriteErrors() = %d after a short write; want 1", got)
	}
}

// TestWriteErrors_NoSinkIsNotAFailure guards the default posture: with no
// persistence configured at all (in-memory only), Add must not manufacture
// write errors — otherwise every unconfigured node would page its operator.
func TestWriteErrors_NoSinkIsNotAFailure(t *testing.T) {
	restoreRing := ResetForTest()
	restoreErrs := ResetWriteErrorsForTest()
	ClearPersistForTest()
	t.Cleanup(func() {
		restoreErrs()
		restoreRing()
	})

	Add(sampleEntry())
	if got := WriteErrors(); got != 0 {
		t.Fatalf("WriteErrors() = %d with no persistence configured; want 0", got)
	}
}

// TestWriteFailureObserver_ReceivesPathAndError proves the seam package main
// wires (storage_health.go → noteStorageWriteFailure) actually fires, with the
// configured path and the real cause, so the storage-health plane can degrade
// the operator contract and raise storage_write_failed.
func TestWriteFailureObserver_ReceivesPathAndError(t *testing.T) {
	withCleanAuditState(t, failWriter{err: errors.New("read-only file system")})

	var (
		mu      sync.Mutex
		calls   int
		gotPath string
		gotErr  error
	)
	SetWriteFailureObserver(func(path string, err error) {
		mu.Lock()
		calls, gotPath, gotErr = calls+1, path, err
		mu.Unlock()
	})
	// SetPersistForTest deliberately leaves persistPath empty (reads keep using
	// the ring), so set it explicitly to prove the path is propagated.
	restorePath := setPersistPathForTest("/data/audit.jsonl")
	t.Cleanup(restorePath)

	Add(sampleEntry())

	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("observer called %d times; want 1", calls)
	}
	if gotPath != "/data/audit.jsonl" {
		t.Errorf("observer path = %q; want %q", gotPath, "/data/audit.jsonl")
	}
	if gotErr == nil || !strings.Contains(gotErr.Error(), "read-only file system") {
		t.Errorf("observer err = %v; want the underlying write error", gotErr)
	}
}

// TestWriteFailureObserver_SilentOnSuccess: a healthy write must never invoke
// the observer, so a working node never degrades its own storage contract.
func TestWriteFailureObserver_SilentOnSuccess(t *testing.T) {
	withCleanAuditState(t, &countingWriter{})

	var calls int
	SetWriteFailureObserver(func(string, error) { calls++ })
	Add(sampleEntry())
	if calls != 0 {
		t.Fatalf("observer called %d times on a healthy sink; want 0", calls)
	}
}

// TestWriteFailureObserver_NilIsSafe: an un-wired or explicitly cleared
// observer must not stop the counter. Losing the observer must never silence
// the loss entirely — that was the whole failure mode being fixed.
func TestWriteFailureObserver_NilIsSafe(t *testing.T) {
	withCleanAuditState(t, failWriter{err: errors.New("boom")})

	SetWriteFailureObserver(nil)
	Add(sampleEntry())
	if got := WriteErrors(); got != 1 {
		t.Fatalf("WriteErrors() = %d with a nil observer; want 1", got)
	}
}

// TestWriteFailureObserver_PanicDoesNotPropagate: audit persistence runs on the
// admin-API goroutine. A panicking observer (a test double, a future sink, a
// mis-wired hook) must not take down the admin plane it exists to record, and
// must not stop the counter that already ran.
func TestWriteFailureObserver_PanicDoesNotPropagate(t *testing.T) {
	withCleanAuditState(t, failWriter{err: errors.New("boom")})

	SetWriteFailureObserver(func(string, error) { panic("observer exploded") })
	Add(sampleEntry()) // must not panic
	if got := WriteErrors(); got != 1 {
		t.Fatalf("WriteErrors() = %d after a panicking observer; want 1", got)
	}
}

// TestWriteErrors_Concurrent is the concurrency contract: N goroutines writing
// through a failing sink must charge exactly N losses. Run under -race, this
// also pins that the counter and the ring are safe under the real concurrency
// of the admin plane.
func TestWriteErrors_Concurrent(t *testing.T) {
	withCleanAuditState(t, failWriter{err: errors.New("no space left on device")})

	const goroutines, perGoroutine = 8, 25
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				Add(sampleEntry())
			}
		}()
	}
	wg.Wait()

	if want := int64(goroutines * perGoroutine); WriteErrors() != want {
		t.Fatalf("WriteErrors() = %d; want %d (every lost entry must be charged exactly once)", WriteErrors(), want)
	}
}

// TestWriteErrors_ObserverIsNotCalledUnderTheRingLock is a deadlock regression
// guard. The observer runs on the failing goroutine and may take process-wide
// locks of its own (the storage-health mutex). If Add still held the audit
// mutex when it fired, an observer that read audit state would self-deadlock.
// Reading the ring from inside the observer must therefore succeed.
func TestWriteErrors_ObserverIsNotCalledUnderTheRingLock(t *testing.T) {
	withCleanAuditState(t, failWriter{err: errors.New("boom")})

	done := make(chan int, 1)
	SetWriteFailureObserver(func(string, error) { done <- len(Get()) })
	Add(sampleEntry())

	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("observer saw %d ring entries; want 1", n)
		}
	default:
		t.Fatal("observer never completed — Add appears to hold the audit lock across the observer call")
	}
}

// TestCountWriteError_LogsOnlyTheFirst pins the log-flood contract inherited
// from internal/reqlog: a failing disk fails EVERY write, so the counter (not
// the log) carries the magnitude. Calling countWriteError directly also covers
// the defensive marshal-failure branch, which Entry's all-scalar shape makes
// unreachable through Add.
func TestCountWriteError_LogsOnlyTheFirst(t *testing.T) {
	restore := ResetWriteErrorsForTest()
	t.Cleanup(restore)

	if !writeErrLogged.CompareAndSwap(false, true) {
		t.Fatal("write-error log gate was not reset")
	}
	writeErrLogged.Store(false)

	countWriteError(1, "/data/audit.jsonl", io.ErrShortWrite)
	if !writeErrLogged.Load() {
		t.Fatal("first failure did not consume the one-shot log gate")
	}
	countWriteError(4, "/data/audit.jsonl", io.ErrShortWrite)
	if got := WriteErrors(); got != 5 {
		t.Fatalf("WriteErrors() = %d; want 5 (every failure counted, only the first logged)", got)
	}
}
