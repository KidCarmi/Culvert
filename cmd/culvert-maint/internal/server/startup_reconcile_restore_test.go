package server

// startup_reconcile_restore_test.go — reconcile_on_startup = "converge" and an
// interrupted restore. The reconcile must leave such a record alone: report
// recovery_required with a reason of its own, keep the record, and run no
// Docker command for it — in particular not the `compose up` that would bring
// a stopped stack back on a data directory nobody has looked at.

import (
	"testing"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

func (r *reconRig) psCalls() int {
	r.world.mu.Lock()
	defer r.world.mu.Unlock()
	return r.world.psCount
}

// TestStartupReconcile_RestoreRecordIsReportedOnly: every stage of both kinds,
// with the stack down (what an interrupted restore leaves) and Docker readable.
func TestStartupReconcile_RestoreRecordIsReportedOnly(t *testing.T) {
	for _, k := range restoreKinds {
		wantReason := "restore_window_manual"
		if k.kind == ops.KindRollbackCreate {
			wantReason = "data_window_manual" // unchanged for a data rollback
		}
		for _, stage := range []journal.RestoreStage{
			"", journal.RestoreStageAdmitted, journal.RestoreStagePreflight, journal.RestoreStageStopping, journal.RestoreStageCommitting,
			journal.RestoreStageCommitFailed, journal.RestoreStageCommitted, journal.RestoreStageStarting, journal.RestoreStageStarted,
		} {
			t.Run(k.name+"/"+string(stage), func(t *testing.T) {
				assertRestoreRecordReportedOnly(t, k.kind, k.mode, stage, wantReason)
			})
		}
	}
}

// assertRestoreRecordReportedOnly runs the reconcile over one restore-class
// record at stage, with the stack down, and checks nothing was done about it.
func assertRestoreRecordReportedOnly(t *testing.T, kind, mode string, stage journal.RestoreStage, wantReason string) {
	t.Helper()
	r := newReconRig(t, true)
	r.world.running = "" // the restore stopped the stack
	r.seed(t, journal.PhaseAdmitted, func(rec *journal.Record) {
		rec.Kind, rec.Mode, rec.RestoreStage = kind, mode, stage
		rec.TargetRef, rec.TargetDigest, rec.PriorRef, rec.PriorDigest, rec.PriorImageID = "", "", "", "", ""
	})
	got := r.run(t)

	if got.Decision != "recovery_required" || got.Reason != wantReason || got.Outcome != OutcomeRecoveryRequired {
		t.Fatalf("result = %s/%s outcome=%s, want recovery_required/%s", got.Decision, got.Reason, got.Outcome, wantReason)
	}
	if got.DockerReconciled || len(got.Actions) != 0 || got.Kind != kind {
		t.Errorf("the reconcile claims it acted, or misnames the kind: %+v", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("a Docker mutation ran for an interrupted restore: %v", c)
	}
	// One read in the whole reconcile: the "is Docker there at all" test that
	// precedes every record. None on account of this one.
	if n := r.psCalls(); n != 1 {
		t.Errorf("docker `ps` ran %d times, want 1 (the reconcile's own readability test only)", n)
	}
	rec := r.recordOnDisk(t)
	if rec == nil {
		t.Fatal("the restore record was retired by the startup reconcile")
	}
	if rec.RestoreStage != stage || rec.ReconcileAttempts != 0 || rec.ReconcileOutcome != OutcomeRecoveryRequired {
		t.Errorf("record: stage=%q attempts=%d outcome=%q", rec.RestoreStage, rec.ReconcileAttempts, rec.ReconcileOutcome)
	}
	if !r.rt.RecoveryRequired() {
		t.Error("status would not report recovery_required")
	}
	if op := r.mgr.Get(r.rt.Snapshot().OpID); op == nil || op.FailureReason != string(ops.ReasonRecoveryRequired) {
		t.Errorf("reconcile op = %+v, want failed(recovery_required)", op)
	}
}

// TestStartupReconcile_RestoreRecordWithDockerDown: Docker being down changes
// nothing about it. It is not deferred (a deferral would be decided again and
// again and never say what it is), and nothing is attempted.
func TestStartupReconcile_RestoreRecordWithDockerDown(t *testing.T) {
	r := dockerDownRig(t)
	r.seed(t, journal.PhaseAdmitted, func(rec *journal.Record) {
		rec.Kind, rec.Mode, rec.RestoreStage = ops.KindRestoreCommit, "", journal.RestoreStageCommitting
		rec.TargetRef, rec.TargetDigest, rec.PriorRef, rec.PriorDigest, rec.PriorImageID = "", "", "", "", ""
	})
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "restore_window_manual" {
		t.Fatalf("result = %s/%s outcome=%s, want recovery_required/restore_window_manual", got.Decision, got.Reason, got.Outcome)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("the restore record was retired")
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("a mutation was attempted: %v", c)
	}
}

// TestStartupReconcile_RestoreRecordBesideAnImageRecord: an interrupted upgrade
// is still reconciled when a restore record is outstanding too, and the restore
// record is still left alone.
func TestStartupReconcile_RestoreRecordBesideAnImageRecord(t *testing.T) {
	r := newReconRig(t, true)
	r.world.pinned = cfgNew // tag ahead of the container: realign
	r.seed(t, journal.PhaseRestarting, nil)
	const restoreID = "01HZZZZZZZZZZZZZZZZZZZZZR1"
	if err := r.jnl.Write(journal.Record{OpID: restoreID, Kind: ops.KindRestoreCommit, Phase: journal.PhaseAdmitted,
		RestoreStage: journal.RestoreStageStopping}); err != nil {
		t.Fatal(err)
	}
	if got := r.run(t); got.Outcome != OutcomeConverged || got.Decision != "realign" {
		t.Fatalf("upgrade record = %+v, want realign/converged", got)
	}
	if c := r.world.calls(); len(c) != 1 || c[0] != "tag:"+cfgOld {
		t.Errorf("mutating calls = %v, want exactly the upgrade's [tag:prior]", c)
	}
	rr, ok := r.rt.RecordFor(restoreID)
	if !ok || rr.Outcome != OutcomeRecoveryRequired || rr.Reason != "restore_window_manual" {
		t.Errorf("restore record result = %+v", rr)
	}
	if _, found, _ := r.jnl.Read(restoreID); !found {
		t.Error("the restore record was retired")
	}
}
