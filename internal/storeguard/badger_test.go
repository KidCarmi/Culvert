package storeguard

// badger_test.go — gates for OpenBadger, the proof that badger.Open returned the
// whole store.
//
// Real badger drops a table only while a table-open panic is killing the
// process, which no in-process test can survive. These gates therefore drop it
// at the one seam the verifier reads — the table listing — against a REAL store
// and a REAL manifest. The end-to-end path through the actual panic is pinned by
// the two consumers' child-process gates (catdb, logstore).

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	badger "github.com/dgraph-io/badger/v4"
)

func badgerOpts(dir string) badger.Options {
	return badger.DefaultOptions(dir).WithLogger(nil)
}

// seedBadger creates a cleanly closed store holding two on-disk tables (each
// close flushes its memtable to one) and returns its directory.
func seedBadger(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "store")
	for round := 0; round < 2; round++ {
		db, err := badger.Open(badgerOpts(dir))
		if err != nil {
			t.Fatalf("seed open: %v", err)
		}
		err = db.Update(func(txn *badger.Txn) error {
			for i := 0; i < 50; i++ {
				if serr := txn.Set([]byte(fmt.Sprintf("k-%d-%03d", round, i)), []byte("v")); serr != nil {
					return serr
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("seed write: %v", err)
		}
		if err := db.Close(); err != nil {
			t.Fatalf("seed close: %v", err)
		}
	}
	return dir
}

// dropFirstTable stands in for badger losing one table during the open: the
// listing the verifier sees omits the lowest-ID table the store really loaded.
func dropFirstTable(db *badger.DB) []badger.TableInfo {
	tables := db.Tables()
	if len(tables) == 0 {
		return tables
	}
	lowest := 0
	for i := range tables {
		if tables[i].ID < tables[lowest].ID {
			lowest = i
		}
	}
	return append(tables[:lowest:lowest], tables[lowest+1:]...)
}

func TestOpenBadger_CompleteStoreOpens(t *testing.T) {
	dir := seedBadger(t)
	db, err := OpenBadger(badgerOpts(dir))
	if err != nil {
		t.Fatalf("OpenBadger on a complete store: %v", err)
	}
	defer func() { _ = db.Close() }()
	if n := len(db.Tables()); n < 2 {
		t.Fatalf("seed produced %d tables, want at least 2 — the gate is not exercising the check", n)
	}
	if err := db.View(func(txn *badger.Txn) error {
		_, gerr := txn.Get([]byte("k-0-000"))
		return gerr
	}); err != nil {
		t.Errorf("data from the first table is not readable: %v", err)
	}
}

func TestOpenBadger_FreshDirectoryHasNothingToVerify(t *testing.T) {
	db, err := OpenBadger(badgerOpts(filepath.Join(t.TempDir(), "fresh")))
	if err != nil {
		t.Fatalf("OpenBadger on a first start: %v", err)
	}
	_ = db.Close()
}

// THE gate. A table the manifest lists that badger did not load is an
// incomplete open: the store is refused, and closed so its directory lock does
// not outlive the refusal.
func TestOpenBadger_DroppedTableIsReportedIncomplete(t *testing.T) {
	dir := seedBadger(t)

	db, err := openBadgerWith(badgerOpts(dir), badger.Open, dropFirstTable)
	if !errors.Is(err, ErrIncompleteOpen) {
		if db != nil {
			_ = db.Close()
		}
		t.Fatalf("OpenBadger with a dropped table = %v, want ErrIncompleteOpen", err)
	}
	if db != nil {
		t.Error("a store was returned alongside ErrIncompleteOpen")
	}
	if !strings.Contains(err.Error(), "1 of the") {
		t.Errorf("error does not say how many tables were lost: %v", err)
	}
	// The refused store must have been closed: badger's directory lock is free.
	again, oerr := badger.Open(badgerOpts(dir))
	if oerr != nil {
		t.Fatalf("the refused store was left open (directory lock still held): %v", oerr)
	}
	_ = again.Close()
}

// The negative control for the compaction case. A table can legitimately leave
// the levels after the open, because a compaction started inside the open
// retired it. badger writes the retirement to the manifest first, so re-reading
// the manifest tells the two apart. Without that re-read, every store a
// compaction touched during its open would be refused as incomplete.
func TestOpenBadger_TableRetiredAfterTheOpenIsNotMissing(t *testing.T) {
	dir := seedBadger(t)
	openThenRetire := func(o badger.Options) (*badger.DB, error) {
		db, err := badger.Open(o)
		if err != nil {
			return nil, err
		}
		if derr := db.DropAll(); derr != nil { // retires every table through the manifest
			_ = db.Close()
			return nil, derr
		}
		return db, nil
	}

	db, err := openBadgerWith(badgerOpts(dir), openThenRetire, (*badger.DB).Tables)
	if err != nil {
		t.Fatalf("a store whose tables were retired after the open was refused: %v", err)
	}
	defer func() { _ = db.Close() }()
	if n := len(db.Tables()); n != 0 {
		t.Fatalf("tables after DropAll = %d, want 0 — the gate is not exercising retirement", n)
	}
}

// Every error badger.Open returns must reach the classifier exactly as badger
// worded it: the empirical message table is the contract.
func TestOpenBadger_OpenErrorIsBadgersOwn(t *testing.T) {
	dir := seedBadger(t)
	manifest := filepath.Join(dir, badger.ManifestFilename)
	if err := os.WriteFile(manifest, []byte("not a manifest"), 0o600); err != nil {
		t.Fatalf("damage manifest: %v", err)
	}
	_, want := badger.Open(badgerOpts(dir))
	if want == nil {
		t.Fatal("badger opened a store with a garbage manifest; the gate needs another fault")
	}
	_, got := OpenBadger(badgerOpts(dir))
	if got == nil || got.Error() != want.Error() {
		t.Errorf("OpenBadger error = %v, want badger's own %v", got, want)
	}
	if ClassifyOpenError(got, Policy{}) != ClassCorrupt {
		t.Errorf("the damaged manifest is no longer classified as corruption: %v", got)
	}
}

// End to end through the engine against a real store: the dropped table keeps
// the marker, the store is left where it is, and the NEXT open quarantines it
// before badger reads it and comes up on a fresh store.
func TestOpen_DroppedBadgerTableIsQuarantinedOnTheNextOpen(t *testing.T) {
	dir := seedBadger(t)

	_, rec, err := Open(dir, Policy{}, func(d string) (*badger.DB, error) {
		return openBadgerWith(badgerOpts(d), badger.Open, dropFirstTable)
	})
	if !errors.Is(err, ErrIncompleteOpen) {
		t.Fatalf("Open = %v, want ErrIncompleteOpen", err)
	}
	if rec.Trigger != TriggerIncompleteOpen || rec.Quarantined || rec.Skipped == "" {
		t.Errorf("recovery = %+v, want an incomplete open whose quarantine is deferred", rec)
	}
	if got := AbandonedMarkers(dir); len(got) != 1 {
		t.Fatalf("abandoned markers = %v, want exactly 1 — the next open could not see the incomplete store", got)
	}
	if got := QuarantinedCopies(dir); len(got) != 0 {
		t.Fatalf("quarantined in the same call: %v", got)
	}

	db, rec2, err := Open(dir, Policy{}, func(d string) (*badger.DB, error) { return OpenBadger(badgerOpts(d)) })
	if err != nil {
		t.Fatalf("next open did not recover: %v", err)
	}
	defer func() { _ = db.Close() }()
	if rec2.Trigger != TriggerPoisonMarker || !rec2.Quarantined {
		t.Errorf("next open recovery = %+v, want a poison-marker quarantine", rec2)
	}
	if got := AbandonedMarkers(dir); len(got) != 0 {
		t.Errorf("markers left after the recovery: %v", got)
	}
	if n := len(db.Tables()); n != 0 {
		t.Errorf("the recovered store still carries %d tables from the damaged one", n)
	}
	if _, serr := os.Stat(filepath.Join(rec2.QuarantinePath, badger.ManifestFilename)); serr != nil {
		t.Errorf("the quarantined copy does not hold the damaged store: %v", serr)
	}
}
