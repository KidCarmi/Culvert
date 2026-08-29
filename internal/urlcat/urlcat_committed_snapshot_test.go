package urlcat

// urlcat_committed_snapshot_test.go — transactional-read correction (§4):
// SnapshotWithRevision must wait for the DURABLE MUTATION BOUNDARY. The
// content-derived fingerprint already prevents the version-alias false-pass,
// but a snapshot taken inside an open transaction still exposed taxonomy that
// was never durably acknowledged, never recomposed into the effective view,
// and vanished on rollback. The corrected snapshot holds mutMu (mutMu → fpMu
// → mu) and therefore describes committed truth only. Fails against e221106d.

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"testing"
)

func TestSnapshotWithRevision_WaitsForDurableBoundary_NeverExposesFailedTransient(t *testing.T) {
	s, _ := newDurableStore(t)
	if err := s.CreateDurable(nil, "keep", []string{"keep.example.com"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	fp0 := s.ContentFingerprint()

	// Publication seam: block inside the durable write, then fail it — the
	// transaction's memory (the transient category) is live while the write
	// is in flight, and rolled back when it fails.
	entered := make(chan struct{})
	release := make(chan struct{})
	prev := writeFile
	writeFile = func(p string, data []byte, mode os.FileMode) error {
		close(entered)
		<-release
		return fmt.Errorf("induced publication failure")
	}
	t.Cleanup(func() { writeFile = prev })

	mutDone := make(chan struct{})
	var mutErr error
	go func() {
		defer close(mutDone)
		mutErr = s.CreateDurable(nil, "transient", []string{"transient.example.com"})
	}()
	<-entered

	snapDone := make(chan struct{})
	var rows []Entry
	var rev string
	go func() {
		defer close(snapDone)
		rows, rev = s.SnapshotWithRevision()
	}()
	for i := 0; i < 200000; i++ {
		runtime.Gosched()
	}
	escaped := false
	select {
	case <-snapDone:
		escaped = true
	default:
	}
	close(release)
	<-mutDone
	<-snapDone

	if !errors.Is(mutErr, ErrPersist) {
		t.Fatalf("induced publication failure expected, got %v", mutErr)
	}
	transientSeen := false
	for i := range rows {
		if rows[i].Name == "transient" {
			transientSeen = true
		}
	}
	if escaped {
		t.Fatalf("SnapshotWithRevision completed inside an open durable transaction: transient-category-exposed=%t rev=%q — a management read described taxonomy that was never durably acknowledged and vanished on rollback", transientSeen, rev)
	}
	if transientSeen {
		t.Fatalf("snapshot exposed the rolled-back transient category: %v", rows)
	}
	if rev != fp0 {
		t.Fatalf("snapshot revision %q, want committed %q", rev, fp0)
	}
}
