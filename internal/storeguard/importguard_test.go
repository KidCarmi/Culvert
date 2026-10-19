package storeguard

// importguard_test.go — F-DISK-RECOVERY-1 gates for the import-pending marker and
// the interrupted-import quarantine, driven with the synthetic opener.

import (
	"os"
	"path/filepath"
	"testing"
)

// TestOpen_InterruptedImportQuarantinesAndRebuilds: a store with an
// import-pending marker still present at Open means the last bulk import never
// certified complete; the partial store is quarantined and rebuilt, and the
// marker is consumed so the fresh store is not quarantined again.
func TestOpen_InterruptedImportQuarantinesAndRebuilds(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	seedDir(t, dir)
	if err := MarkImportPending(dir); err != nil {
		t.Fatalf("MarkImportPending: %v", err)
	}
	o := &opener{}
	st, rec, err := Open(dir, Policy{}, o.open)
	if err != nil || st == nil {
		t.Fatalf("interrupted-import open must rebuild, got st=%v err=%v rec=%+v", st, err, rec)
	}
	if rec.Trigger != TriggerInterruptedImport || !rec.Quarantined || rec.QuarantinePath == "" {
		t.Fatalf("interrupted import not quarantined: %+v", rec)
	}
	if _, err := os.Stat(rec.QuarantinePath); err != nil {
		t.Fatalf("quarantined evidence missing: %v", err)
	}
	if importPending(dir) {
		t.Fatal("import-pending marker was not cleared after quarantine")
	}
	// The signal is consumed: the next open is a plain healthy open.
	_, rec2, err := Open(dir, Policy{}, (&opener{}).open)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	if rec2.Trigger != TriggerNone || rec2.Quarantined {
		t.Fatalf("interrupted-import signal not consumed: %+v", rec2)
	}
}

// TestOpen_NoImportMarkerNeverQuarantines is the shared-engine regression:
// a store that never writes an import-pending marker (logstore, or catdb between
// imports) is never quarantined by the new path. Byte-identical behaviour.
func TestOpen_NoImportMarkerNeverQuarantines(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	seedDir(t, dir)
	_, rec, err := Open(dir, Policy{}, (&opener{}).open)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("a store with no import-pending marker was recovered: %+v", rec)
	}
}

// TestMarkImportPending_IsASibling: the marker lives beside the store directory,
// not inside it, so the quarantine rename does not carry it along.
func TestMarkImportPending_IsASibling(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	seedDir(t, dir)
	if err := MarkImportPending(dir); err != nil {
		t.Fatalf("MarkImportPending: %v", err)
	}
	if _, err := os.Lstat(dir + ImportPendingSuffix); err != nil {
		t.Fatalf("marker is not the expected sibling %q: %v", dir+ImportPendingSuffix, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 || entries[0].Name() != "MANIFEST" {
		t.Fatalf("marker leaked INTO the store dir: %v", entries)
	}
	if !importPending(dir) {
		t.Fatal("importPending did not see the marker")
	}
	if err := ClearImportPending(dir); err != nil {
		t.Fatalf("ClearImportPending: %v", err)
	}
	if importPending(dir) {
		t.Fatal("marker still present after ClearImportPending")
	}
}

// TestOpen_InterruptedImportMarkerClearedWhenStoreGone: a marker beside a store
// that no longer exists is a phantom — it is cleared, and a fresh store is
// created WITHOUT a spurious quarantine.
func TestOpen_InterruptedImportMarkerClearedWhenStoreGone(t *testing.T) {
	base := filepath.Join(t.TempDir(), "catfeeddb")
	// The store dir never created; only the sibling marker exists.
	if err := MarkImportPending(base); err != nil {
		t.Fatalf("MarkImportPending: %v", err)
	}
	_, rec, err := Open(base, Policy{}, (&opener{}).open)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if rec.Trigger != TriggerNone || rec.Quarantined {
		t.Fatalf("a phantom marker caused a quarantine: %+v", rec)
	}
	if importPending(base) {
		t.Fatal("phantom import-pending marker was not cleared")
	}
}

// TestOpen_InterruptedImportIsLeastSevere: when BOTH a fault marker and an
// import-pending marker are present, the fault wins the reported trigger (it is
// the more specific signal), and BOTH markers are cleared after the quarantine.
func TestOpen_InterruptedImportIsLeastSevere(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "catfeeddb")
	seedDir(t, dir)
	if err := RecordFault(dir, "test fault"); err != nil {
		t.Fatalf("RecordFault: %v", err)
	}
	if err := MarkImportPending(dir); err != nil {
		t.Fatalf("MarkImportPending: %v", err)
	}
	_, rec, err := Open(dir, Policy{}, (&opener{}).open)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if rec.Trigger != TriggerRuntimeFault || !rec.Quarantined {
		t.Fatalf("fault should outrank interrupted-import: %+v", rec)
	}
	if faultRecorded(dir) || importPending(dir) {
		t.Fatalf("markers not both cleared after quarantine: fault=%v import=%v", faultRecorded(dir), importPending(dir))
	}
}
