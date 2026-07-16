package server

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
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
	found, err := srv.advanceJournalPhase(acc, journal.PhaseResolved)
	if err != nil {
		t.Fatalf("advance: %v", err)
	}
	if !found {
		t.Fatal("expected the seeded record to be found")
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
	if found, err := srvNil.advanceJournalPhase(&upgradeApplyAccumulator{opID: testOpULID}, journal.PhasePulled); err != nil || found {
		t.Errorf("nil journal should no-op, got found=%v err=%v", found, err)
	}

	srv, _ := newJournalTestServer(t)
	// empty opID
	if found, err := srv.advanceJournalPhase(&upgradeApplyAccumulator{}, journal.PhasePulled); err != nil || found {
		t.Errorf("empty opID should no-op, got found=%v err=%v", found, err)
	}
	// absent record (valid ULID, nothing seeded) → found=false, no error.
	if found, err := srv.advanceJournalPhase(&upgradeApplyAccumulator{opID: testOpULID}, journal.PhasePulled); err != nil || found {
		t.Errorf("absent record should no-op, got found=%v err=%v", found, err)
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
	if _, err := srv.advanceJournalPhase(&upgradeApplyAccumulator{opID: testOpULID}, journal.PhaseRestarting); err == nil {
		t.Fatal("expected fail-closed error advancing over a corrupt record")
	}
}

// TestWriteBarrier_UpdatesExisting: with an admission record present, the
// barrier advances it to PhaseRestarting in place, preserving admission fields.
func TestWriteBarrier_UpdatesExisting(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	started := time.Now().UTC().Add(-time.Minute).Truncate(time.Second)
	seedAdmitted(t, jnl, started)

	acc := &upgradeApplyAccumulator{opID: testOpULID, actor: "cp", pinnedRef: repo + "@sha256:" + digNew, pinnedDigest: "sha256:" + digNew}
	if err := srv.writeBarrier(acc); err != nil {
		t.Fatalf("writeBarrier: %v", err)
	}
	rec, found, err := jnl.Read(testOpULID)
	if err != nil || !found {
		t.Fatalf("read: found=%v err=%v", found, err)
	}
	if rec.Phase != journal.PhaseRestarting || rec.TargetDigest != digNew {
		t.Errorf("record = %+v, want restarting + target %s", *rec, digNew)
	}
	if !rec.StartedAt.Equal(started) {
		t.Errorf("StartedAt mutated: got %v want %v", rec.StartedAt, started)
	}
}

// TestWriteBarrier_RecreatesWhenMissing is the Codex P2 fix: a MISSING record
// right before the danger window must NOT silently proceed — the barrier
// re-establishes a durable PhaseRestarting record so a crash after the tag
// advance is still reconcilable.
func TestWriteBarrier_RecreatesWhenMissing(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	// Nothing seeded — the admission record is absent.
	acc := &upgradeApplyAccumulator{
		opID: testOpULID, actor: "cp",
		pinnedRef: repo + "@sha256:" + digNew, pinnedDigest: "sha256:" + digNew,
		priorRef: repo + "@sha256:" + digOld, priorDigests: []string{"sha256:" + digOld},
	}
	if err := srv.writeBarrier(acc); err != nil {
		t.Fatalf("writeBarrier: %v", err)
	}
	rec, found, err := jnl.Read(testOpULID)
	if err != nil || !found {
		t.Fatalf("barrier must have re-created the record: found=%v err=%v", found, err)
	}
	if rec.Phase != journal.PhaseRestarting {
		t.Errorf("phase = %q, want restarting", rec.Phase)
	}
	if rec.Kind != ops.KindUpgradeApply || rec.TargetDigest != digNew || rec.PriorDigest != digOld {
		t.Errorf("re-created record incomplete: %+v", *rec)
	}
}

// TestWriteBarrier_FailClosedOnCorrupt: a corrupt record makes the barrier
// return an error (the restart stage then refuses to advance the tag).
func TestWriteBarrier_FailClosedOnCorrupt(t *testing.T) {
	srv, jnl := newJournalTestServer(t)
	corrupt := filepath.Join(jnl.Dir(), testOpULID+".json")
	if err := os.WriteFile(corrupt, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if err := srv.writeBarrier(&upgradeApplyAccumulator{opID: testOpULID}); err == nil {
		t.Fatal("expected fail-closed error from the barrier over a corrupt record")
	}
}

// TestWriteBarrier_NilJournalNoOp: a non-journaled build's barrier is a no-op
// (returns nil so the upgrade proceeds normally).
func TestWriteBarrier_NilJournalNoOp(t *testing.T) {
	srvNil := &Server{}
	if err := srvNil.writeBarrier(&upgradeApplyAccumulator{opID: testOpULID}); err != nil {
		t.Errorf("nil-journal barrier should no-op, got %v", err)
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
