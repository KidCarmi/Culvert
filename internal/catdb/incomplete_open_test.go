package catdb

// incomplete_open_test.go — badger.Open returning a store without one of its
// tables must not clear the poison marker.
//
// badger's per-table goroutine releases its throttle while a table-open panic
// unwinds, so badger.Open can return (db, nil) without the panicking table just
// before the panic ends the process. Open now verifies the loaded tables
// against the manifest (storeguard.OpenBadger) and reports the gap as
// storeguard.ErrIncompleteOpen. These gates pin what THIS store does with that
// verdict; the verdict itself is pinned against a real manifest in
// internal/storeguard/badger_test.go, and the live race by
// TestOpenResilient_SurvivesUncatchableOpenPanicOnNextBoot.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/storeguard"
)

func TestOpenResilient_IncompleteOpenIsQuarantinedOnTheNextBoot(t *testing.T) {
	dir := seedStore(t, 50)
	// The real open, followed by the verdict OpenBadger reaches when badger
	// returned without a table: the store is closed and refused.
	incomplete := func(d string) (*CommunityDB, error) {
		db, err := Open(d)
		if err != nil {
			return nil, err
		}
		_ = db.Close()
		return nil, fmt.Errorf("%w: 1 of the 1 tables its manifest lists were not loaded", storeguard.ErrIncompleteOpen)
	}

	db, rec, err := openResilientWith(dir, incomplete)
	if !errors.Is(err, storeguard.ErrIncompleteOpen) || db != nil {
		t.Fatalf("openResilientWith = (%v, %v), want ErrIncompleteOpen and no store", db, err)
	}
	if rec.Trigger != TriggerIncompleteOpen || rec.Quarantined || rec.Skipped == "" {
		t.Errorf("recovery = %+v, want an incomplete open with its quarantine deferred", rec)
	}
	if got := abandonedMarkers(dir); len(got) != 1 {
		t.Fatalf("abandoned markers = %v, want exactly 1 — the next boot would hand badger the same store", got)
	}
	if got := QuarantinedCopies(dir); len(got) != 0 {
		t.Fatalf("quarantined in the same boot: %v", got)
	}

	// Next boot: the marker moves the store aside before badger reads it.
	db2, rec2, err := OpenResilient(dir)
	if err != nil {
		t.Fatalf("next boot did not recover: %v", err)
	}
	defer func() { _ = db2.Close() }()
	if rec2.Trigger != TriggerPoisonMarker || !rec2.Quarantined {
		t.Errorf("next boot recovery = %+v, want a poison-marker quarantine", rec2)
	}
	if _, ok := db2.Lookup(hostFor(0)); ok {
		t.Error("the next boot is still serving the store that opened incomplete")
	}
	if m := markerFiles(t, dir); len(m) != 0 {
		t.Errorf("markers left after the recovery: %v", m)
	}
	if got := QuarantinedCopies(dir); len(got) != 1 {
		t.Errorf("quarantined copies = %v, want exactly 1 (the evidence)", got)
	}
}

// The protection lives in Open, so it holds only while Open is the one way this
// package reaches badger. A direct badger.Open in production code would return
// a store without its panicking table as a success and clear the marker again.
func TestCatDB_OpensBadgerOnlyThroughTheVerifiedOpen(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	verified := 0
	for _, e := range ents {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		if strings.Contains(string(src), "badger.Open(") {
			t.Errorf("%s calls badger.Open directly; use storeguard.OpenBadger", name)
		}
		verified += strings.Count(string(src), "storeguard.OpenBadger(")
	}
	if verified == 0 {
		t.Error("no storeguard.OpenBadger call found; the gate is not looking at the right sources")
	}
}
