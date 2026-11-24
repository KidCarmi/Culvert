package server

import (
	"testing"
	"time"

	"culvert-maint/internal/journal"
)

// TestStartupReconcile_RealignNotReadyKeepsRecord: the tag is ahead and the
// container is on the prior image — identities that used to be enough to
// realign, report "converged" and retire. They were true, on real Docker, of a
// proxy dockerd was already stopping. Without a fresh successful readiness
// probe the record is kept and the outcome is recovery_required.
func TestStartupReconcile_RealignNotReadyKeepsRecord(t *testing.T) {
	r := newReconRig(t, false)
	r.world.pinned = cfgNew
	r.seed(t, journal.PhaseRestarting, nil)
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "not_ready_at_retirement" || got.DockerReconciled {
		t.Fatalf("result = %+v, want recovery_required/not_ready_at_retirement and docker_reconciled=false", got)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("the record was retired although the proxy was not ready")
	}
	if !r.rt.RecoveryRequired() {
		t.Error("recovery_required is not reported")
	}
}

// TestStartupReconcile_NoopNotReadyKeepsRecord: nothing to change (tag and
// container both on the prior image) is still not convergence unless the proxy
// answers ready now.
func TestStartupReconcile_NoopNotReadyKeepsRecord(t *testing.T) {
	r := newReconRig(t, false)
	r.seed(t, journal.PhaseRestarting, nil)
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "not_ready_at_retirement" {
		t.Fatalf("result = %+v, want recovery_required/not_ready_at_retirement", got)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("the record was retired although the proxy was not ready")
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("a no-op decision made mutating calls: %v", c)
	}
}

// TestStartupReconcile_WaitsOutTheSettleWindow: Docker is read, and the tag
// moved, only after agent start + interrupted_settle.
func TestStartupReconcile_WaitsOutTheSettleWindow(t *testing.T) {
	const settle = 1500 * time.Millisecond
	r := newReconRig(t, true)
	r.srv.opts.Cfg.InterruptedSettle = settle
	r.srv.startedAt = time.Now()
	r.world.pinned = cfgNew
	r.seed(t, journal.PhaseRestarting, nil)

	done := make(chan ReconcileRecord, 1)
	go func() { done <- r.run(t) }()

	// Inside the window: no tag yet, no record retired.
	time.Sleep(settle / 3)
	if c := r.world.calls(); len(c) != 0 {
		t.Fatalf("the reconcile made mutating calls inside the settle window: %v", c)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("the record was retired inside the settle window")
	}

	got := <-done
	if waited := time.Since(r.srv.startedAt); waited < settle {
		t.Errorf("the reconcile finished %v after the start; it must not act before %v", waited, settle)
	}
	if got.Outcome != OutcomeConverged || !got.DockerReconciled {
		t.Fatalf("result = %+v, want converged after the wait", got)
	}
	if r.recordOnDisk(t) != nil {
		t.Error("record not retired after the settle window and a ready probe")
	}
}

// TestStartupReconcile_SettleCutShortKeepsRecord: if the reconcile's own
// deadline ends before the settle window does, nothing is read as settled,
// nothing is changed, and the record is kept.
func TestStartupReconcile_SettleCutShortKeepsRecord(t *testing.T) {
	r := newReconRig(t, true)
	r.srv.opts.Cfg.StageTimeout = 150 * time.Millisecond // reconcile deadline = 2 x stage timeout
	r.srv.opts.Cfg.InterruptedSettle = 30 * time.Second
	r.srv.startedAt = time.Now()
	r.world.pinned = cfgNew
	r.seed(t, journal.PhaseRestarting, nil)
	began := time.Now()
	got := r.run(t)
	if time.Since(began) > 10*time.Second {
		t.Fatalf("the reconcile ignored its own deadline")
	}
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "settle_wait_cut_short" {
		t.Fatalf("result = %+v, want recovery_required/settle_wait_cut_short", got)
	}
	if r.recordOnDisk(t) == nil {
		t.Fatal("the record was retired without the settle window having passed")
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls before the settle window was over: %v", c)
	}
}
