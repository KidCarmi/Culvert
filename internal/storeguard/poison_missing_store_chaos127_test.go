package storeguard

// CHAOS-127 — an abandoned open-attempt marker whose store is already gone.
//
// Every gate here failed before the fix. They pin one property, the property
// the FAULT branch beside this one already had (faultguard_test.go's
// TestOpen_RecordedFaultForAMissingStoreIsCleared): a breadcrumb whose
// condition is RESOLVED is cleared rather than carried forward, because
// carrying it forward arms a quarantine against whatever healthy store is
// rebuilt at that path next.
//
// Before the fix, recoverBeforeOpen's poison branch had no missing-directory
// case. ApplyQuarantine reports an absent directory as a SKIP, and the skip is
// what makes the marker clearing conditional, so the marker survived every
// open at which the directory was absent. Control run on the pre-fix tree, the
// two-open sequence below: open 2 reported
// {Trigger: poison_marker, Quarantined: true} and renamed the HEALTHY rebuilt
// store to <dir>.corrupt.<T2>, after which pruneQuarantines (MaxQuarantinedCopies
// is 1) deleted <dir>.corrupt.<T1> — the genuine evidence from the original
// failure. Both assertions in TestChaos127_StaleMarkerDoesNotQuarantineTheRebuiltStore
// failed; both now hold.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plantPoison writes an abandoned open-attempt marker for dir, standing in for
// a start that died inside badger.Open. No live process holds it, so
// AbandonedMarkers lists it.
func plantPoison(t *testing.T, dir string) string {
	t.Helper()
	marker := dir + MarkerSuffix + "1234-5678"
	if err := os.WriteFile(marker, []byte("pid=1234\n"), 0o600); err != nil {
		t.Fatalf("plant marker: %v", err)
	}
	return marker
}

// seedingOpener stands in for badger, which MkdirAll's the store directory it
// is handed. The package's shared `opener` fake never touches the disk, and
// this scenario turns entirely on the directory EXISTING at the next open.
type seedingOpener struct {
	t     *testing.T
	calls int
}

func (o *seedingOpener) open(path string) (*fakeStore, error) {
	o.calls++
	seedDir(o.t, path)
	return &fakeStore{}, nil
}

// failPoisonRemoval refuses to unlink an open-attempt marker and behaves like
// os.Remove for everything else. The sibling of faultguard_test.go's
// failMarkerRemoval, for the other marker kind.
func failPoisonRemoval(path string) error {
	if strings.Contains(filepath.Base(path), strings.TrimSuffix(MarkerSuffix, ".")) {
		return &os.PathError{Op: "remove", Path: path, Err: os.ErrPermission}
	}
	return os.Remove(path)
}

// A store that is already gone has nothing to quarantine, so the marker's
// condition is resolved: it is cleared and the open proceeds normally, rather
// than being reported as a phantom recovery for the life of the data directory.
func TestChaos127_AbandonedMarkerForAMissingStoreIsCleared(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	marker := plantPoison(t, dir)

	o := &opener{}
	st, rec, err := Open(dir, Policy{}, o.open)
	if err != nil || st == nil {
		t.Fatalf("Open = (%v, %v), want a plain open", st, err)
	}
	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("recovery = %+v, want a plain open (nothing to quarantine)", rec)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Error("the marker for an absent store was not cleared; the next open would quarantine the replacement")
	}
}

// The destructive consequence, end to end. A previous start quarantined the
// damaged store and died before clearing its marker; the store is rebuilt, and
// the NEXT open must not treat that healthy rebuild as the thing the marker
// accused — nor let pruneQuarantines destroy the real evidence.
func TestChaos127_StaleMarkerDoesNotQuarantineTheRebuiltStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	// The genuine evidence the earlier failure left behind. Fixed-width
	// unixnano, so lexical order is chronological as QuarantinedCopies assumes.
	evidence := dir + QuarantineSuffix + "1700000000000000000"
	seedDir(t, evidence)
	marker := plantPoison(t, dir)

	// Open 1: the directory is absent and badger recreates it.
	o1 := &seedingOpener{t: t}
	if _, rec, err := Open(dir, Policy{}, o1.open); err != nil || rec.Quarantined {
		t.Fatalf("open 1 = (%+v, %v), want a plain open", rec, err)
	}
	if _, serr := os.Stat(marker); serr == nil {
		t.Fatal("open 1 kept the resolved marker")
	}

	// Open 2: the start that used to destroy the healthy store.
	o2 := &seedingOpener{t: t}
	st, rec, err := Open(dir, Policy{}, o2.open)
	if err != nil || st == nil {
		t.Fatalf("open 2 = (%v, %v)", st, err)
	}
	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Errorf("open 2 recovery = %+v, want a plain open — it quarantined the HEALTHY rebuilt store", rec)
	}
	if _, serr := os.Stat(filepath.Join(dir, "MANIFEST")); serr != nil {
		t.Errorf("the healthy store is no longer at %s: %v", dir, serr)
	}
	if _, serr := os.Stat(evidence); serr != nil {
		t.Errorf("the genuine corruption evidence was pruned: %v", serr)
	}
	if copies := QuarantinedCopies(dir); len(copies) != 1 || copies[0] != evidence {
		t.Errorf("quarantined copies = %v, want only the original evidence", copies)
	}
}

// Same rule the fault branch applies: a marker that cannot be cleared must not
// be followed by opening a replacement, because the surviving marker would
// quarantine that replacement on the next start.
func TestChaos127_UnclearableMarkerForAMissingStoreStopsRecovery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	plantPoison(t, dir)

	o := &opener{}
	st, _, err := openWith(dir, Policy{}, o.open, markerFS{remove: failPoisonRemoval, syncDir: syncDir})
	if err == nil || st != nil || o.calls != 0 {
		t.Fatalf("openWith = (%v, %v) after %d open(s), want an error and no open", st, err, o.calls)
	}
}

// A fault marker recording the same resolved condition sits in the branch the
// poison marker shadows, so clearing only the poison marker would leave the
// fault marker to quarantine the replacement by itself on the next open.
func TestChaos127_FaultMarkerBesideAResolvedPoisonMarkerIsAlsoCleared(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	if err := RecordFault(dir, "test fault"); err != nil {
		t.Fatalf("RecordFault: %v", err)
	}
	plantPoison(t, dir)

	o1 := &seedingOpener{t: t}
	if _, rec, err := Open(dir, Policy{}, o1.open); err != nil || rec.Quarantined {
		t.Fatalf("open 1 = (%+v, %v), want a plain open", rec, err)
	}
	if faultRecorded(dir) {
		t.Fatal("the fault marker for the same resolved condition was kept")
	}

	o2 := &seedingOpener{t: t}
	_, rec, err := Open(dir, Policy{}, o2.open)
	if err != nil || rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("open 2 = (%+v, %v), want a plain open", rec, err)
	}
}
