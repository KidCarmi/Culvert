package feedsync

// heldwriter_recovery_test.go — Linux source-level evidence for the held-writer
// abandon path (ASTRA 2026-10-20 held-writer review, correction 6304005247:
// "Linux source-level held-writer/late-return/... marker tests ... can be
// prepared and evidenced against exact review-branch source in an isolated
// Linux test environment"). These run HERE, on Linux, against the review-branch
// source — they are NOT the replacement-OVA / ESXi gates (physical ENOSPC,
// mmap/SIGBUS, real power loss and a booted recovery remain a later candidate
// step). They need BeginImport's POSIX directory fsync, so they skip off Linux
// exactly like TestSyncRound_QuiescesAfterAbandonedWrite.
//
// What they add beyond TestSyncRound_QuiescesAfterAbandonedWrite (which proves
// no SECOND BulkWrite starts): they RELEASE the abandoned writer, let its late
// write COMPLETE, and prove the late completion is harmless — the store is never
// certified and the import-pending marker is never cleared, so the next boot
// quarantines and discards the abandoned data. This is the "late-return",
// "no early marker clear" and "post-restart integrity" evidence ASTRA named,
// settled node-locally where cancellation is impossible (badger WriteBatch.Flush
// takes no context — the latched-fault/controlled-restart path is the substitute).

import (
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
	"github.com/KidCarmi/Culvert/internal/storeguard"
)

// stallParkedWrite installs a fault that parks the FIRST BulkWrite on release
// (so the write neither returns nor degrades the store — the pure stall path),
// runs one syncRound that must abandon it, and returns the release func and the
// store dir with the writer still in flight.
func stallParkedWrite(t *testing.T) (s *Syncer, db *catdb.CommunityDB, dir string, release func(), domains []string) {
	t.Helper()
	withWatchdogTimings(t, time.Second, 20*time.Millisecond) // stall fires fast; no degrade poll
	url, dl, _ := controlledFeed(t, 30)
	dir = t.TempDir()
	db = openStore(t, dir)
	rel := make(chan struct{})
	var once bool
	db.SetBulkWriteFaultForTest(func(n int) error {
		if n == 1 && !once { // park the writer mid-write, exactly once
			once = true
			<-rel
		}
		return nil
	})
	s = New(db, url, 24*time.Hour)
	if s.syncRound() {
		t.Fatal("a stalled import must not count as a sync")
	}
	if !s.writeAbandoned.Load() {
		t.Fatal("a stalled BulkWrite must latch writeAbandoned")
	}
	return s, db, dir, func() { close(rel) }, dl
}

func markerPresent(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Stat(dir + storeguard.ImportPendingSuffix)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat import-pending marker: %v", err)
	}
	return err == nil
}

// TestHeldWriter_LateReturnDoesNotCertifyAndKeepsMarker proves the abandoned
// writer's LATE completion cannot certify the store: syncRound abandoned before
// CompleteImport, so when the parked write finally flushes its (stale) data the
// store stays uncertified and the import-pending marker stays set — the next
// boot will quarantine it. This is the overwrite hazard's real closure: the Old
// writer may still land, but it can never land over a CERTIFIED store, because
// quiescence guaranteed no writer certified one.
func TestHeldWriter_LateReturnDoesNotCertifyAndKeepsMarker(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("BeginImport needs POSIX directory fsync; Linux source-level test skipped on %s", runtime.GOOS)
	}
	s, db, dir, release, domains := stallParkedWrite(t)

	// Before the late return: uncertified, marker present (no early clear).
	if s.ImportComplete() {
		t.Fatal("an abandoned import must not be certified")
	}
	if !markerPresent(t, dir) {
		t.Fatal("the import-pending marker must still be present after an abandoned write (no early clear)")
	}

	// Release the parked writer and let its late write COMPLETE (all domains land).
	release()
	deadline := time.Now().Add(10 * time.Second)
	for present(db, domains) < len(domains) {
		if time.Now().After(deadline) {
			t.Fatalf("the released writer never completed its late flush: %d/%d present", present(db, domains), len(domains))
		}
		time.Sleep(5 * time.Millisecond)
	}

	// After the late return: STILL uncertified, marker STILL present. The late
	// Old flush changed the data but could not certify it or clear the marker.
	if s.ImportComplete() {
		t.Fatal("the late writer's completion must NOT certify the store (no CompleteImport ran)")
	}
	if _, err := db.ImportRecord(); err == nil {
		t.Fatal("a certification record must not exist after an abandoned+late-returned write")
	}
	if !markerPresent(t, dir) {
		t.Fatal("the import-pending marker must survive the late write (no early clear) so the next boot quarantines")
	}
}

// TestHeldWriter_InterruptedImportQuarantinesOnReopen proves the recovery the
// marker is for: after the abandoned write (uncertified + marker present), the
// NEXT open via OpenResilient quarantines the store as an interrupted import and
// opens a fresh one, discarding the abandoned writer's data. This SIMULATES the
// next-boot recovery at the unit level; the actual OVA boot + full re-convergence
// remains the ESXi replacement gate.
func TestHeldWriter_InterruptedImportQuarantinesOnReopen(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("BeginImport needs POSIX directory fsync; Linux source-level test skipped on %s", runtime.GOOS)
	}
	_, db, dir, release, domains := stallParkedWrite(t)

	// Let the late write complete so nothing is in flight when we close — then
	// close WITHOUT certifying (exactly the state a crash/kill would leave).
	release()
	deadline := time.Now().Add(10 * time.Second)
	for present(db, domains) < len(domains) {
		if time.Now().After(deadline) {
			t.Fatalf("the released writer never completed: %d/%d present", present(db, domains), len(domains))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// The next boot: OpenResilient sees the uncleared marker and quarantines.
	next, rec, err := catdb.OpenResilient(dir)
	if err != nil {
		t.Fatalf("OpenResilient after an abandoned import: %v", err)
	}
	defer next.Close()
	if rec.Trigger != catdb.TriggerInterruptedImport || !rec.Quarantined || rec.QuarantinePath == "" {
		t.Fatalf("an abandoned import must quarantine on reopen as an interrupted import: trigger=%v quarantined=%v path=%q",
			rec.Trigger, rec.Quarantined, rec.QuarantinePath)
	}
	if _, err := os.Stat(rec.QuarantinePath); err != nil {
		t.Fatalf("the quarantined copy must exist (moved aside, not deleted): %v", err)
	}
	if got := catdb.QuarantinedCopies(dir); len(got) != 1 {
		t.Fatalf("want exactly one quarantined copy, got %v", got)
	}
	// The rebuilt store is fresh (the abandoned data is discarded) and the marker
	// is gone (recovery cleared it), so a later boot does not re-quarantine.
	if present(next, domains) != 0 {
		t.Fatalf("the rebuilt store must be empty, not the abandoned writer's data: %d present", present(next, domains))
	}
	if markerPresent(t, dir) {
		t.Fatal("recovery must clear the import-pending marker so the next boot does not re-quarantine")
	}
}
