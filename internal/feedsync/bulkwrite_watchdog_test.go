package feedsync

// bulkwrite_watchdog_test.go — F-DISK-RECOVERY-1 req 4: a BulkWrite that never
// returns must still be surfaced as a sync failure. The watchdog polls the
// store's degraded latch and backstops it with a stall deadline, so a contained
// mid-write fault (BulkWrite blocked on a badger-internal goroutine) or a plain
// stall is reported without waiting for BulkWrite to return.

import (
	"errors"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
)

// withWatchdogTimings shrinks the poll/stall timings for a deterministic test
// and restores them.
func withWatchdogTimings(t *testing.T, poll, stall time.Duration) {
	t.Helper()
	op, os := bulkWriteDegradedPoll, bulkWriteStallTimeout
	bulkWriteDegradedPoll, bulkWriteStallTimeout = poll, stall
	t.Cleanup(func() { bulkWriteDegradedPoll, bulkWriteStallTimeout = op, os })
}

func openWatchdogStore(t *testing.T) *catdb.CommunityDB {
	t.Helper()
	db, err := catdb.Open(filepath.Join(t.TempDir(), "catfeeddb"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestWriteBulkWatched_DegradedMidWriteSurfacedWhileBulkWriteBlocks is the core
// req-4 gate: BulkWrite is blocked inside a fault that has latched the store
// degraded, and the watchdog reports the failure WITHOUT the write returning.
func TestWriteBulkWatched_DegradedMidWriteSurfacedWhileBulkWriteBlocks(t *testing.T) {
	withWatchdogTimings(t, time.Millisecond, 10*time.Second) // poll fast, stall far away
	db := openWatchdogStore(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // let the abandoned BulkWrite goroutine exit
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 1 {
			db.ForceDegradedForTest() // a contained mmap fault would latch this
			<-release                 // ...while the outer BulkWrite never returns
		}
		return nil
	})
	fs := New(db, "http://unused", time.Hour)

	done := make(chan bulkWriteOutcome, 1)
	go func() {
		outcome, _ := fs.writeBulkWatched(map[string]string{"a.example": "Social"})
		done <- outcome
	}()
	select {
	case got := <-done:
		if got != bulkWriteDegradedMidWrite {
			t.Fatalf("outcome = %v, want bulkWriteDegradedMidWrite", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writeBulkWatched did not report the degraded store while BulkWrite was blocked")
	}
}

// TestWriteBulkWatched_StallSurfaced: a BulkWrite that neither returns nor
// degrades is reported as stalled once the deadline elapses.
func TestWriteBulkWatched_StallSurfaced(t *testing.T) {
	withWatchdogTimings(t, time.Second, 20*time.Millisecond) // stall fires first
	db := openWatchdogStore(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 1 {
			<-release // block without degrading
		}
		return nil
	})
	fs := New(db, "http://unused", time.Hour)

	done := make(chan bulkWriteOutcome, 1)
	go func() {
		outcome, _ := fs.writeBulkWatched(map[string]string{"a.example": "Social"})
		done <- outcome
	}()
	select {
	case got := <-done:
		if got != bulkWriteStalled {
			t.Fatalf("outcome = %v, want bulkWriteStalled", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("writeBulkWatched did not report the stall")
	}
}

// TestWriteBulkWatched_NormalWriteUnaffected: a healthy BulkWrite returns
// normally through the watchdog, so the favourable path is unchanged.
func TestWriteBulkWatched_NormalWriteUnaffected(t *testing.T) {
	withWatchdogTimings(t, 10*time.Millisecond, 5*time.Second)
	db := openWatchdogStore(t)
	fs := New(db, "http://unused", time.Hour)
	outcome, err := fs.writeBulkWatched(map[string]string{"a.example": "Social"})
	if outcome != bulkWriteReturned || err != nil {
		t.Fatalf("healthy write: outcome=%v err=%v", outcome, err)
	}
	if cat, ok := db.Lookup("a.example"); !ok || cat != "Social" {
		t.Fatalf("healthy write did not land: %q %v", cat, ok)
	}
}

// TestWriteBulkWatched_ReturnedErrorPropagates: a BulkWrite that returns an
// error (a clean write error, not a stall) is reported as returned-with-error,
// the favourable-landing path that already incremented sync_failures.
func TestWriteBulkWatched_ReturnedErrorPropagates(t *testing.T) {
	withWatchdogTimings(t, 10*time.Millisecond, 5*time.Second)
	db := openWatchdogStore(t)
	boom := errors.New("simulated clean write error")
	db.SetBulkWriteFaultForTest(func(n int) error { return boom })
	fs := New(db, "http://unused", time.Hour)
	outcome, err := fs.writeBulkWatched(map[string]string{"a.example": "Social"})
	if outcome != bulkWriteReturned || !errors.Is(err, boom) {
		t.Fatalf("clean write error: outcome=%v err=%v", outcome, err)
	}
}

// TestSyncRound_QuiescesAfterAbandonedWrite is the ASTRA held-writer-overwrite
// gate. When a BulkWrite is abandoned mid-write (here a stall — it neither
// returns nor degrades the store), the abandoned goroutine still holds the
// badger WriteBatch and will flush its (stale) data if the disk later frees.
// The scheduler's next round therefore MUST NOT start a second BulkWrite: a
// second writer that reaches CompleteImport would certify a store the held
// writer then overwrites, which the import-pending marker would not quarantine.
// With the fix syncRound quiesces (the writeAbandoned latch). Against the
// pre-fix tree it starts a second BulkWrite — faultCalls increases — racing the
// still-in-flight held writer, which is the defect this gate proves.
func TestSyncRound_QuiescesAfterAbandonedWrite(t *testing.T) {
	// The scenario drives a real syncRound, whose BeginImport writes the durable
	// import-pending marker with a parent-DIRECTORY fsync (F-DISK-RECOVERY-1 C1).
	// That is a POSIX guarantee the Linux appliance depends on; Windows rejects a
	// directory fsync, so BeginImport fails there before the held writer is
	// reached (ASTRA ran this on Windows/amd64 and recorded platform-blocked
	// target coverage). The fix under test — the writeAbandoned quiescence latch
	// — is plain Go and platform-independent; only this test's marker dependency
	// is POSIX-specific, so skip off Linux rather than report a false failure.
	if runtime.GOOS != "linux" {
		t.Skipf("F-DISK recovery marker needs POSIX directory fsync (BeginImport); the fix is platform-independent — skipped on %s", runtime.GOOS)
	}
	// Stall fires quickly; the degrade poll is far away so this is the pure
	// stall path (storeDegraded stays false — the path with no other latch).
	withWatchdogTimings(t, time.Second, 20*time.Millisecond)
	url, _, _ := controlledFeed(t, 50)
	db := openStore(t, t.TempDir())
	t.Cleanup(func() { _ = db.Close() })

	var faultCalls atomic.Int64
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // let the abandoned writer exit at test end
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 1 {
			faultCalls.Add(1)
			<-release // block the first write => the write stalls, never returns
		}
		return nil
	})
	s := New(db, url, 24*time.Hour)

	// Round 1: the write stalls; writeBulkWatched abandons it and latches.
	if s.syncRound() {
		t.Fatal("a stalled import must not count as a sync")
	}
	// The abandoned writer reached its (now blocked) first write.
	deadline := time.Now().Add(5 * time.Second)
	for faultCalls.Load() < 1 {
		if time.Now().After(deadline) {
			t.Fatal("the abandoned BulkWrite never reached its first write")
		}
		time.Sleep(time.Millisecond)
	}
	if !s.writeAbandoned.Load() {
		t.Fatal("a stalled BulkWrite must latch writeAbandoned (quiescence)")
	}

	// Round 2 (the scheduler's retry): MUST be quiesced — no second BulkWrite,
	// no download, no BeginImport — so the held writer stays the sole writer.
	before := faultCalls.Load()
	if s.syncRound() {
		t.Fatal("a quiesced round must not count as a sync")
	}
	// Give any (erroneously started) second BulkWrite time to reach its first
	// write before asserting it did not happen.
	time.Sleep(50 * time.Millisecond)
	if got := faultCalls.Load(); got != before {
		t.Fatalf("held-writer overwrite: a second BulkWrite started while the first was still in flight (faultCalls %d -> %d); the retry must be quiesced", before, got)
	}
}
