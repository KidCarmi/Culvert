package server

import (
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// dockerDownRig is a reconcile whose Docker does not answer, whose settle
// window is far longer than the reconcile's whole deadline, and whose agent
// has only just started (the window is fully open).
func dockerDownRig(t *testing.T) *reconRig {
	t.Helper()
	r := newReconRig(t, true)
	r.world.down = true
	r.srv.opts.Cfg.StageTimeout = 400 * time.Millisecond // Docker wait <= 400ms; reconcile deadline = 800ms
	r.srv.opts.Cfg.InterruptedSettle = 30 * time.Second
	r.srv.startedAt = time.Now()
	return r
}

// TestStartupReconcile_DockerDownDefersWithoutSettleWait: Docker is down at
// agent start. The record must be deferred (docker_unavailable) and decided
// again at the next start. It must not be reported as needing manual recovery
// because the settle wait, which only exists to make Docker reads trustworthy,
// used up the reconcile's deadline (real-Docker E2E: docker_unavailable_defers,
// second_instance_skips).
func TestStartupReconcile_DockerDownDefersWithoutSettleWait(t *testing.T) {
	r := dockerDownRig(t)
	r.world.pinned = cfgNew // a state the reconcile WOULD act on if it could read it
	r.seed(t, journal.PhaseRestarting, nil)

	got := r.run(t)

	if got.Decision != "defer" || got.Reason != "docker_unavailable" || got.Outcome != OutcomeDeferred {
		t.Fatalf("result = %s/%s outcome=%s, want defer/docker_unavailable outcome=%s", got.Decision, got.Reason, got.Outcome, OutcomeDeferred)
	}
	if got.DockerReconciled {
		t.Error("docker_reconciled is set although Docker was never readable")
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("a mutation was attempted while Docker was down: %v", c)
	}
	rec := r.recordOnDisk(t)
	if rec == nil {
		t.Fatal("the record was retired although Docker was never read")
	}
	if rec.ReconcileAttempts != 0 {
		t.Errorf("reconcile_attempts = %d, want 0: a deferral must not use up an attempt", rec.ReconcileAttempts)
	}
	if r.rt.RecoveryRequired() {
		t.Error("recovery_required is reported for a Docker that was merely down")
	}
}

// TestStartupReconcile_DockerDownDataRecordKeepsItsReport: a record that never
// touches Docker keeps the report it always had, Docker down or not.
func TestStartupReconcile_DockerDownDataRecordKeepsItsReport(t *testing.T) {
	r := dockerDownRig(t)
	r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) {
		rec.Kind, rec.Mode = ops.KindRollbackCreate, "data"
	})
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "data_window_manual" {
		t.Fatalf("result = %s/%s outcome=%s, want recovery_required/data_window_manual", got.Decision, got.Reason, got.Outcome)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("the data record was retired")
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("a mutation was attempted: %v", c)
	}
}

// TestStartupReconcile_DeadlineSpentIsNotADeferral: when the reconcile's whole
// deadline is gone before a record is reached, the record is abandoned
// (deadline_elapsed), not deferred: a real failure must not be turned into
// "Docker was down".
func TestStartupReconcile_DeadlineSpentIsNotADeferral(t *testing.T) {
	r := dockerDownRig(t)
	r.srv.opts.Cfg.StageTimeout = time.Nanosecond // the deadline is over before the first record
	r.seed(t, journal.PhaseRestarting, nil)
	got := r.run(t)
	if got.Reason != "deadline_elapsed" || got.Outcome != OutcomeAbandoned {
		t.Fatalf("result = %s/%s outcome=%s, want deadline_elapsed/%s", got.Decision, got.Reason, got.Outcome, OutcomeAbandoned)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("the record was retired")
	}
}
