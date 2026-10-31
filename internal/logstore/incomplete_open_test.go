package logstore

// incomplete_open_test.go — the request-history store gets the same protection
// as the category store: an open that returns without one of its tables keeps
// the poison marker, and the next open quarantines the store before badger
// reads it.
//
// OpenTTL verifies the loaded tables against the manifest
// (storeguard.OpenBadger). These gates pin what THIS store does with an
// incomplete verdict — including that it is never mistaken for an encryption
// error — under this store's own policy and encrypted options. The verdict
// itself is pinned against a real manifest in internal/storeguard/badger_test.go,
// and the live race by TestChaos62_SurvivesUncatchableOpenPanicOnNextRun.

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/storeguard"
)

func TestChaos62_IncompleteOpenIsQuarantinedOnTheNextRun(t *testing.T) {
	dir := seedHistory(t, 50)
	key, err := EncKey(dir, chaosPass)
	if err != nil {
		t.Fatalf("enckey: %v", err)
	}
	// The real encrypted open, followed by the verdict OpenBadger reaches when
	// badger returned without a table: the store is closed and refused.
	incomplete := func(d string) (*Store, error) {
		s, oerr := OpenTTL(d, 0, 0, key, nil)
		if oerr != nil {
			return nil, oerr
		}
		_ = s.Close()
		return nil, fmt.Errorf("%w: 1 of the 1 tables its manifest lists were not loaded", storeguard.ErrIncompleteOpen)
	}

	s, rec, err := storeguard.Open(dir, historyStorePolicy, incomplete)
	if !errors.Is(err, storeguard.ErrIncompleteOpen) || s != nil {
		t.Fatalf("Open = (%v, %v), want ErrIncompleteOpen and no store", s, err)
	}
	if errors.Is(err, ErrEncMismatch) {
		t.Fatal("an incomplete open was reported as an encryption mismatch")
	}
	if rec.Trigger != storeguard.TriggerIncompleteOpen || rec.Quarantined {
		t.Errorf("recovery = %+v, want an incomplete open with its quarantine deferred", rec)
	}
	if got := storeguard.AbandonedMarkers(dir); len(got) != 1 {
		t.Fatalf("abandoned markers = %v, want exactly 1 — the next run would hand badger the same store", got)
	}

	// Next run, through the production entry point.
	s2, rec2, err := openHistory(t, dir)
	if err != nil {
		t.Fatalf("next run did not recover: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if rec2.Trigger != storeguard.TriggerPoisonMarker || !rec2.Quarantined {
		t.Errorf("next run recovery = %+v, want a poison-marker quarantine", rec2)
	}
	if got := QuarantinedCopies(dir); len(got) != 1 {
		t.Errorf("quarantined copies = %v, want exactly 1 (the evidence)", got)
	}
	if _, serr := os.Stat(dir + ".salt"); serr != nil {
		t.Errorf("the salt sidecar did not survive the quarantine: %v", serr)
	}
}

// The protection lives in OpenTTL, so it holds only while OpenTTL is the one way
// this package reaches badger. A direct badger.Open in production code would
// return a store without its panicking table as a success and clear the marker.
func TestChaos62_OpensBadgerOnlyThroughTheVerifiedOpen(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var direct []string
	verified := false
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), "_test.go") || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		b, rerr := os.ReadFile(e.Name())
		if rerr != nil {
			t.Fatalf("read %s: %v", e.Name(), rerr)
		}
		if strings.Contains(string(b), "badger.Open(") {
			direct = append(direct, e.Name())
		}
		verified = verified || strings.Contains(string(b), "storeguard.OpenBadger(")
	}
	if len(direct) != 0 {
		t.Errorf("badger.Open called directly in %v; use storeguard.OpenBadger", direct)
	}
	if !verified {
		t.Error("no storeguard.OpenBadger call found; the gate is not looking at the right sources")
	}
}
