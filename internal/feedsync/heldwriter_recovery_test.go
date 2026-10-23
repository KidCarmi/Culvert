package feedsync

// heldwriter_recovery_test.go — Linux source-level evidence for the held-writer
// abandon path (ASTRA held-writer review; correction 6304005247; d75afe85 audit
// 6304420199). These run on Linux against review-branch source. They are NOT
// the replacement-OVA / ESXi gates: physical ENOSPC, mmap/SIGBUS, real power
// loss, a service-manager restart and a booted recovery remain later candidate
// steps. They need BeginImport's POSIX directory fsync, so they skip off Linux.
//
// Beside TestSyncRound_QuiescesAfterAbandonedWrite (no SECOND BulkWrite starts),
// these RELEASE the abandoned writer and JOIN its actual BulkWrite return (the
// writeReturnedForTest seam — quiescence is never inferred from visible keys),
// then assert, AFTER that join:
//   - the late completion did not certify the store and did not clear the
//     import-pending marker;
//   - the next open quarantines it as an interrupted import; a SECOND clean
//     open neither re-quarantines nor changes the retained-copy inventory;
//   - a fresh import then certifies, and a further clean open keeps the
//     certified data with no new quarantine.

import (
	"os"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catdb"
	"github.com/KidCarmi/Culvert/internal/storeguard"
)

func skipOffLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("BeginImport needs POSIX directory fsync; Linux source-level test skipped on %s", runtime.GOOS)
	}
}

// abandonParkedWrite opens a store, parks its first BulkWrite, runs one
// syncRound that must abandon it (pure stall path: the store is not degraded),
// and returns with the writer still parked. The DB Close is registered before
// the parked-writer helper, so teardown is release -> join -> close.
// abandonedWrite is what abandonParkedWrite leaves behind: the syncer whose
// round abandoned, its store, and the still-parked writer.
type abandonedWrite struct {
	s       *Syncer
	db      *catdb.CommunityDB
	closeDB func() error
	dir     string
	url     string
	p       *parkedWriter
	domains []string
}

func abandonParkedWrite(t *testing.T) abandonedWrite {
	t.Helper()
	withWatchdogTimings(t, time.Second, 20*time.Millisecond) // stall fires fast; no degrade poll
	url, domains, _ := controlledFeed(t, 30)
	dir := t.TempDir()
	db := openStore(t, dir)
	var once sync.Once
	var closeErr error
	closeDB := func() error { once.Do(func() { closeErr = db.Close() }); return closeErr }
	t.Cleanup(func() { _ = closeDB() }) // idempotent; runs AFTER the writer teardown
	p := newParkedWriter(t)             // registered after Close => its teardown runs first
	db.SetBulkWriteFaultForTest(p.hook(nil))
	s := New(db, url, 24*time.Hour)
	p.attach(s)
	if s.syncRound() {
		t.Fatal("a stalled import must not count as a sync")
	}
	if !s.writeAbandoned.Load() {
		t.Fatal("a stalled BulkWrite must latch writeAbandoned")
	}
	if !p.started.Load() {
		t.Fatal("the BulkWrite never reached the parked write")
	}
	return abandonedWrite{s: s, db: db, closeDB: closeDB, dir: dir, url: url, p: p, domains: domains}
}

// closeOnFatal registers an idempotent Close for a store the moment it is
// opened, so a fatal assertion before the test's own Close never leaves a store
// open (ASTRA 6359611097 #5). The returned func is the test's explicit Close.
func closeOnFatal(t *testing.T, db *catdb.CommunityDB) func() error {
	t.Helper()
	var once sync.Once
	var err error
	closeDB := func() error { once.Do(func() { err = db.Close() }); return err }
	t.Cleanup(func() { _ = closeDB() })
	return closeDB
}

func markerPresent(t *testing.T, dir string) bool {
	t.Helper()
	_, err := os.Stat(dir + storeguard.ImportPendingSuffix)
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat import-pending marker: %v", err)
	}
	return err == nil
}

// TestHeldWriter_LateReturnDoesNotCertifyAndKeepsMarker: the abandoned writer's
// late return — joined at the actual BulkWrite boundary — cannot certify the
// store or clear the marker, because syncRound abandoned before CompleteImport
// and quiescence admits no other writer.
func TestHeldWriter_LateReturnDoesNotCertifyAndKeepsMarker(t *testing.T) {
	skipOffLinux(t)
	a := abandonParkedWrite(t)
	s, db, dir, p, domains := a.s, a.db, a.dir, a.p, a.domains

	if s.ImportComplete() {
		t.Fatal("an abandoned import must not be certified")
	}
	if !markerPresent(t, dir) {
		t.Fatal("the import-pending marker must be present after an abandoned write (no early clear)")
	}

	p.release()
	if err := p.join(); err != nil { // the ACTUAL BulkWrite return, and its result
		t.Fatalf("the released writer returned an error: %v", err)
	}

	// Every assertion below is made AFTER the writer is known to have returned.
	if got := present(db, domains); got != len(domains) {
		t.Fatalf("the late write returned nil but only %d/%d keys are visible", got, len(domains))
	}
	if s.ImportComplete() {
		t.Fatal("the late writer's completion must NOT certify the store (no CompleteImport ran)")
	}
	if _, err := db.ImportRecord(); err == nil {
		t.Fatal("no certification record may exist after an abandoned, late-returned write")
	}
	if !markerPresent(t, dir) {
		t.Fatal("the import-pending marker must survive the late write so the next boot quarantines")
	}
	// No further round may run: quiescence holds after the late return too.
	if s.syncRound() {
		t.Fatal("a round after an abandoned write must stay quiesced, even once the writer returned")
	}
	if s.ImportComplete() || !markerPresent(t, dir) {
		t.Fatal("a quiesced round must not certify or clear the marker")
	}
}

// TestHeldWriter_RecoveryPersistsAcrossReopens: after the abandoned write the
// next open quarantines; a second clean open does not re-quarantine and leaves
// the retained-copy inventory unchanged; a fresh import then certifies; and a
// further clean open keeps the certified data without a new quarantine. This is
// a unit-level simulation of successive boots, not a booted appliance.
func TestHeldWriter_RecoveryPersistsAcrossReopens(t *testing.T) {
	skipOffLinux(t)
	a := abandonParkedWrite(t)
	closeDB, dir, url, p, domains := a.closeDB, a.dir, a.url, a.p, a.domains

	p.release()
	if err := p.join(); err != nil {
		t.Fatalf("the released writer returned an error: %v", err)
	}
	// Close WITHOUT certifying (the state a kill would leave), after the join.
	if err := closeDB(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Open #1 — recovery: interrupted-import quarantine, empty replacement.
	o1, rec, err := catdb.OpenResilient(dir)
	if err != nil {
		t.Fatalf("open #1: %v", err)
	}
	closeO1 := closeOnFatal(t, o1)
	if rec.Trigger != catdb.TriggerInterruptedImport || !rec.Quarantined || rec.QuarantinePath == "" {
		t.Fatalf("open #1 must quarantine as an interrupted import: trigger=%v quarantined=%v path=%q",
			rec.Trigger, rec.Quarantined, rec.QuarantinePath)
	}
	if _, err := os.Stat(rec.QuarantinePath); err != nil {
		t.Fatalf("the quarantined copy must be retained (moved aside, not deleted): %v", err)
	}
	inventory := catdb.QuarantinedCopies(dir)
	if len(inventory) != 1 || inventory[0] != rec.QuarantinePath {
		t.Fatalf("retained inventory after open #1 = %v, want [%s]", inventory, rec.QuarantinePath)
	}
	if got := present(o1, domains); got != 0 {
		t.Fatalf("the replacement store must be empty, not the abandoned writer's data: %d present", got)
	}
	if markerPresent(t, dir) {
		t.Fatal("recovery must clear the import-pending marker")
	}
	if err := closeO1(); err != nil {
		t.Fatalf("close after open #1: %v", err)
	}

	// Open #2 — a clean reopen is EXERCISED, not inferred: no new quarantine,
	// unchanged retained-copy inventory.
	o2, rec, err := catdb.OpenResilient(dir)
	if err != nil {
		t.Fatalf("open #2: %v", err)
	}
	closeO2 := closeOnFatal(t, o2)
	if rec.Trigger != catdb.TriggerNone || rec.Quarantined {
		t.Fatalf("open #2 must be clean: trigger=%v quarantined=%v", rec.Trigger, rec.Quarantined)
	}
	if got := catdb.QuarantinedCopies(dir); !slices.Equal(got, inventory) {
		t.Fatalf("retained inventory changed on a clean reopen: %v -> %v", inventory, got)
	}

	// Fresh import on the recovered store: it must complete and certify. Lift
	// the 20 ms stall deadline used to provoke the abandon so a healthy import
	// under -race is not misreported as a stall.
	bulkWriteStallTimeout = 30 * time.Second
	fresh := New(o2, url, 24*time.Hour)
	if !fresh.syncRound() {
		t.Fatal("a fresh import on the recovered store must succeed")
	}
	if !fresh.ImportComplete() {
		t.Fatal("the fresh import must certify the store")
	}
	if got := present(o2, domains); got != len(domains) {
		t.Fatalf("the fresh import must land the whole feed: %d/%d", got, len(domains))
	}
	if markerPresent(t, dir) {
		t.Fatal("a certified import must clear the import-pending marker")
	}
	if err := closeO2(); err != nil {
		t.Fatalf("close after the fresh import: %v", err)
	}

	// Open #3 — clean reopen after certification: data and record kept, no
	// quarantine, inventory still unchanged.
	o3, rec, err := catdb.OpenResilient(dir)
	if err != nil {
		t.Fatalf("open #3: %v", err)
	}
	closeOnFatal(t, o3)
	if rec.Trigger != catdb.TriggerNone || rec.Quarantined {
		t.Fatalf("open #3 must be clean: trigger=%v quarantined=%v", rec.Trigger, rec.Quarantined)
	}
	if _, err := o3.ImportRecord(); err != nil {
		t.Fatalf("the certification record must survive a clean reopen: %v", err)
	}
	if got := present(o3, domains); got != len(domains) {
		t.Fatalf("the certified data must survive a clean reopen: %d/%d", got, len(domains))
	}
	if got := catdb.QuarantinedCopies(dir); !slices.Equal(got, inventory) {
		t.Fatalf("retained inventory changed after certification + reopen: %v -> %v", inventory, got)
	}
}
