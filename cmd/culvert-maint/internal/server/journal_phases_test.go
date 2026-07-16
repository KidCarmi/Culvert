package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"culvert-maint/internal/journal"
)

// a canonical, strictly-valid ULID (journal paths reject non-ULID op_ids).
const testOpULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// seedAdmitted writes the PhaseAdmitted record the admission path would have
// written, so the read-modify-write advance has something to update.
func seedAdmitted(t *testing.T, jnl *journal.Journal, started time.Time) {
	t.Helper()
	if err := jnl.Write(journal.Record{
		OpID: testOpULID, Kind: "upgrades.apply", Phase: journal.PhaseAdmitted,
		Actor: "cp", StartedAt: started, UpdatedAt: started,
	}); err != nil {
		t.Fatalf("seed admitted: %v", err)
	}
}

// TestAdvanceJournalPhase_FoldsIdentifiers: advancing folds the prior/target
// identifiers acc knows and preserves the immutable admission fields.
func TestAdvanceJournalPhase_FoldsIdentifiers(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	started := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	seedAdmitted(t, jnl, started)

	acc := &upgradeApplyAccumulator{
		opID:         testOpULID,
		actor:        "cp",
		priorRef:     repo + "@sha256:" + digOld,
		priorDigests: []string{"sha256:" + digOld},
		pinnedRef:    repo + "@sha256:" + digNew,
		pinnedDigest: "sha256:" + digNew,
	}
	if err := srv.advanceJournalPhase(acc, journal.PhaseResolved); err != nil {
		t.Fatalf("advance: %v", err)
	}
	rec, found, err := jnl.Read(testOpULID)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if rec.Phase != journal.PhaseResolved {
		t.Errorf("phase = %q, want resolved", rec.Phase)
	}
	if rec.TargetRef != acc.pinnedRef || rec.TargetDigest != digNew {
		t.Errorf("target ref=%q digest=%q, want %q / %s", rec.TargetRef, rec.TargetDigest, acc.pinnedRef, digNew)
	}
	if rec.PriorRef != acc.priorRef || rec.PriorDigest != digOld {
		t.Errorf("prior ref=%q digest=%q, want %q / %s", rec.PriorRef, rec.PriorDigest, acc.priorRef, digOld)
	}
	// Immutable admission fields preserved; UpdatedAt advanced.
	if !rec.StartedAt.Equal(started) {
		t.Errorf("StartedAt mutated: got %v want %v", rec.StartedAt, started)
	}
	if rec.Kind != "upgrades.apply" || rec.Actor != "cp" {
		t.Errorf("immutable fields changed: kind=%q actor=%q", rec.Kind, rec.Actor)
	}
	if !rec.UpdatedAt.After(started) {
		t.Errorf("UpdatedAt not advanced: %v", rec.UpdatedAt)
	}
}

// TestAdvanceJournalPhase_NoOps: nil journal, empty opID, and an absent record
// all no-op with a nil error (an absent record must NOT fail closed — a
// progress advance on an already-retired op is benign).
func TestAdvanceJournalPhase_NoOps(t *testing.T) {
	// nil journal
	srvNil := &Server{}
	if err := srvNil.advanceJournalPhase(&upgradeApplyAccumulator{opID: testOpULID}, journal.PhasePulled); err != nil {
		t.Errorf("nil journal should no-op, got %v", err)
	}

	srv, _ := newJournalTestServer(t)
	// empty opID
	if err := srv.advanceJournalPhase(&upgradeApplyAccumulator{}, journal.PhasePulled); err != nil {
		t.Errorf("empty opID should no-op, got %v", err)
	}
	// absent record (valid ULID, nothing seeded)
	if err := srv.advanceJournalPhase(&upgradeApplyAccumulator{opID: testOpULID}, journal.PhasePulled); err != nil {
		t.Errorf("absent record should no-op, got %v", err)
	}
}

// TestAdvanceJournalPhase_FailClosedOnCorrupt: a corrupt/unreadable record
// makes the advance RETURN an error — this is what makes the PhaseRestarting
// write-ahead barrier fail closed (the restart stage propagates it and refuses
// to advance the tag).
func TestAdvanceJournalPhase_FailClosedOnCorrupt(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	// Write a syntactically-invalid record file at the op's path.
	corrupt := filepath.Join(jnl.Dir(), testOpULID+".json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if err := srv.advanceJournalPhase(&upgradeApplyAccumulator{opID: testOpULID}, journal.PhaseRestarting); err == nil {
		t.Fatal("expected fail-closed error advancing over a corrupt record")
	}
}

// TestApply_JournalRetiredAtTerminal proves the phase writes are wired into the
// live flow without breaking it: a full successful apply advances the record
// through the lifecycle AND retires it at terminal (no leaked record), and the
// tag/up did run (the write-ahead barrier did not block the happy path).
func TestApply_JournalRetiredAtTerminal(t *testing.T) {
	rig := startApplyRig(t)
	defer rig.stop()

	op, _ := rig.acceptAndWait(t, map[string]interface{}{"image_ref": repo + ":v2"})
	if op["state"] != "succeeded" {
		t.Fatalf("apply state = %v, want succeeded; op=%+v", op["state"], op)
	}
	// Record retired at terminal — nothing left to reconcile.
	recs, err := rig.journal.List()
	if err != nil {
		t.Fatalf("journal list: %v", err)
	}
	if len(recs) != 0 {
		t.Errorf("expected the journal record retired at terminal, got %d record(s)", len(recs))
	}
	// The happy path crossed the danger window: tag + up ran.
	if !rig.sawCommand("tag") {
		t.Error("expected `docker tag` to run (write-ahead barrier must not block the happy path)")
	}
}
