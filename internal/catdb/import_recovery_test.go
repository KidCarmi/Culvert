package catdb

// import_recovery_test.go — F-DISK-RECOVERY-1 gates at the catdb layer: the
// durable import-pending intent, the interrupted-import quarantine+rebuild, and
// the fail-closed behaviour when the intent cannot be made durable.
//
// The ACTUAL lab failure (run 39314161458 attempt-1): a mid-write ENOSPC faults
// the store, CHAOS-74 contains the fault, but recordFault's marker write fails
// on the full disk, so the next boot re-opens the torn store and re-faults
// forever. These tests reproduce the recoverable shape — an import that began
// and never certified complete — and prove it is quarantined+rebuilt in ONE
// restart, with no dependence on a fault-time write to a full disk.

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/storeguard"
)

func importMarker(dir string) string { return dir + storeguard.ImportPendingSuffix }

// TestBeginImport_WritesDurableIntentBeforeData: the intent marker is on disk
// after BeginImport and before any bulk data — it is written while the disk
// still has space, so recovery never depends on a write after the disk fills.
func TestBeginImport_WritesDurableIntentBeforeData(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, _, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.BeginImport(); err != nil {
		t.Fatalf("BeginImport: %v", err)
	}
	if _, err := os.Lstat(importMarker(dir)); err != nil {
		t.Fatalf("BeginImport did not lay down the import-pending marker: %v", err)
	}
}

// TestInterruptedImport_QuarantinesAndRebuildsInOneRestart reproduces the lab
// failure's recoverable shape: an import that began (marker written, completion
// record withdrawn) and never reached CompleteImport — the process was killed,
// faulted, or filled the disk mid-write. The partial store is quarantined and
// rebuilt empty on the NEXT open — exactly one restart — and no fault-time write
// was needed. Verified against the pre-fix tree: without the marker the reopen
// returned the torn store with TriggerNone and the proxy served stale/empty
// Layer-2 forever.
func TestInterruptedImport_QuarantinesAndRebuildsInOneRestart(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, _, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// A completed import first, so the store holds real data to be discarded.
	if err := db.BeginImport(); err != nil {
		t.Fatalf("BeginImport #1: %v", err)
	}
	if err := db.BulkWrite(map[string]string{"old.example": "Social"}); err != nil {
		t.Fatalf("BulkWrite #1: %v", err)
	}
	if err := db.CompleteImport(SyncRecord{FeedURL: "u", Entries: 1, CompletedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CompleteImport #1: %v", err)
	}
	// Now an import that BEGINS and is interrupted before CompleteImport.
	if err := db.BeginImport(); err != nil {
		t.Fatalf("BeginImport #2: %v", err)
	}
	if err := db.BulkWrite(map[string]string{"partial.example": "Malware"}); err != nil {
		t.Fatalf("partial BulkWrite: %v", err)
	}
	_ = db.Close() // the kill: no CompleteImport, marker still present

	next, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("restart after an interrupted import must rebuild, got err=%v rec=%+v", err, rec)
	}
	t.Cleanup(func() { _ = next.Close() })
	if rec.Trigger != TriggerInterruptedImport || !rec.Quarantined || rec.QuarantinePath == "" {
		t.Fatalf("interrupted import not quarantined: %+v", rec)
	}
	// The rebuilt store is empty — neither the old nor the partial data survives.
	if cat, ok := next.Lookup("old.example"); ok || cat != "" {
		t.Fatalf("rebuilt store answered from quarantined data: %q %v", cat, ok)
	}
	if cat, ok := next.Lookup("partial.example"); ok || cat != "" {
		t.Fatalf("rebuilt store answered partial data: %q %v", cat, ok)
	}
	if _, err := next.ImportRecord(); err == nil {
		t.Fatal("rebuilt store should carry no completion record")
	}
	assertServing(t, next)
	if _, err := os.Lstat(importMarker(dir)); !os.IsNotExist(err) {
		t.Fatalf("import-pending marker not cleared after rebuild: err=%v", err)
	}
	// Idempotent: the next open is a plain healthy open, not a re-quarantine.
	_ = next.Close()
	third, rec3, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("third open: %v", err)
	}
	t.Cleanup(func() { _ = third.Close() })
	if rec3.Trigger != TriggerNone || rec3.Quarantined {
		t.Fatalf("interrupted-import signal not consumed: %+v", rec3)
	}
}

// TestCompleteImport_ClearsIntent_NoFalseQuarantine: a completed import clears
// the marker, so a clean shutdown after a complete import is NEVER quarantined.
func TestCompleteImport_ClearsIntent_NoFalseQuarantine(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	db, _, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.BeginImport(); err != nil {
		t.Fatalf("BeginImport: %v", err)
	}
	if err := db.BulkWrite(map[string]string{"a.example": "Social"}); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}
	if err := db.CompleteImport(SyncRecord{FeedURL: "u", Entries: 1, CompletedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CompleteImport: %v", err)
	}
	if _, err := os.Lstat(importMarker(dir)); !os.IsNotExist(err) {
		t.Fatalf("CompleteImport did not clear the marker: err=%v", err)
	}
	_ = db.Close()
	next, rec, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = next.Close() })
	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("a cleanly completed store was quarantined: %+v", rec)
	}
	if cat, ok := next.Lookup("a.example"); !ok || cat != "Social" {
		t.Fatalf("completed data did not survive a clean restart: %q %v", cat, ok)
	}
}

// TestBeginImport_RefusesWhenIntentNotDurable: if the intent marker cannot be
// made durable, BeginImport returns an error and touches no badger state — the
// import does not start (fail closed), so no torn store is left without a marker.
func TestBeginImport_RefusesWhenIntentNotDurable(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "catfeeddb")
	db, _, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// Seed a completed import so we can prove BeginImport did not withdraw it.
	if err := db.BeginImport(); err != nil {
		t.Fatalf("BeginImport seed: %v", err)
	}
	if err := db.BulkWrite(map[string]string{"keep.example": "Social"}); err != nil {
		t.Fatalf("BulkWrite seed: %v", err)
	}
	if err := db.CompleteImport(SyncRecord{FeedURL: "u", Entries: 1, CompletedAt: time.Now().UTC()}); err != nil {
		t.Fatalf("CompleteImport seed: %v", err)
	}
	// Force the marker's atomic rename to fail in a way ROOT cannot bypass (the
	// tests run as root, so a chmod on the parent would be ignored — the exact
	// root-bypass class this whole fix exists under): pre-create a DIRECTORY at
	// the marker path, so os.Rename(tmp, <dir>.importing) fails because the
	// target is a non-empty directory.
	if err := os.MkdirAll(importMarker(dir), 0o700); err != nil {
		t.Fatalf("seed blocking dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(importMarker(dir), "x"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocking dir file: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(importMarker(dir)) })

	if err := db.BeginImport(); err == nil {
		t.Fatal("BeginImport must refuse when the intent marker cannot be made durable")
	}
	// The badger completion record must be untouched — the import never started.
	if _, err := db.ImportRecord(); err != nil {
		t.Fatalf("BeginImport withdrew the completion record despite refusing: %v", err)
	}
}
