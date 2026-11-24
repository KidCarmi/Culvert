package server

import (
	"reflect"
	"testing"

	"culvert-maint/internal/journal"
)

// restoreRig: an upgrade died at phase restarting, the fixed tag is on the
// target, and no proxy container is running. ownUpCut says whether this agent
// start found the marker of its own unfinished `compose up`.
func restoreRig(t *testing.T, ready, ownUpCut bool) *reconRig {
	t.Helper()
	r := newReconRig(t, ready)
	r.world.running = ""
	r.world.pinned = cfgNew
	r.srv.startOnlyUp = ownUpCut
	r.srv.startMarkerLive.Store(ownUpCut)
	r.seed(t, journal.PhaseRestarting, nil)
	return r
}

// TestStartupReconcile_RestoresPriorAfterItsOwnInterruptedUp: the proxy is down
// because the agent's own recreate was cut. The start that follows puts the
// fixed tag back on the image that was serving before the upgrade, starts it,
// requires it to answer ready, verifies both by id, and only then retires the
// record. The target image is never started.
func TestStartupReconcile_RestoresPriorAfterItsOwnInterruptedUp(t *testing.T) {
	r := restoreRig(t, true, true)
	got := r.run(t)
	if got.Decision != "restore_prior" || got.Reason != "stack_down_up_interrupted" || got.Outcome != OutcomeConverged || !got.DockerReconciled {
		t.Fatalf("result = %+v, want restore_prior/stack_down_up_interrupted converged", got)
	}
	if want := []string{"tag:" + cfgOld, "up"}; !reflect.DeepEqual(r.world.calls(), want) {
		t.Errorf("mutating calls = %v, want %v", r.world.calls(), want)
	}
	if r.world.running != cfgOld || r.world.pinned != cfgOld {
		t.Errorf("after restore: container %.8s tag %.8s, want both on the prior image", r.world.running, r.world.pinned)
	}
	if r.recordOnDisk(t) != nil {
		t.Error("the record was not retired after a verified restore")
	}
	if r.rt.RecoveryRequired() {
		t.Error("recovery_required is reported after a successful restore")
	}
}

// TestStartupReconcile_StackDownWithoutTheMarkerIsOnlyReported: with nothing
// that attributes the outage to the agent, the stack may be down because an
// operator took it down. Nothing is started.
func TestStartupReconcile_StackDownWithoutTheMarkerIsOnlyReported(t *testing.T) {
	r := restoreRig(t, true, false)
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "stack_down" {
		t.Fatalf("result = %+v, want recovery_required/stack_down", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls without the marker: %v", c)
	}
	if r.world.running != "" {
		t.Error("a container was started")
	}
	if r.recordOnDisk(t) == nil {
		t.Error("the record was retired")
	}
}

// TestStartupReconcile_RestoreThatIsNotReadyKeepsTheRecord: the prior image was
// started but does not answer ready. That is not a recovery: the record stays,
// recovery_required is reported, and the attempt is counted.
func TestStartupReconcile_RestoreThatIsNotReadyKeepsTheRecord(t *testing.T) {
	r := restoreRig(t, false, true)
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "prior_not_ready" || got.DockerReconciled {
		t.Fatalf("result = %+v, want recovery_required/prior_not_ready", got)
	}
	rec := r.recordOnDisk(t)
	if rec == nil {
		t.Fatal("the record was retired although the restored proxy is not ready")
	}
	if rec.ReconcileAttempts != 1 {
		t.Errorf("reconcile_attempts = %d, want 1 (the attempt is durable before the action)", rec.ReconcileAttempts)
	}
	if !r.rt.RecoveryRequired() {
		t.Error("recovery_required is not reported")
	}
}

// TestStartupReconcile_RestoreRunsUpOnceMoreAfterACleanupOnlyPass: after an
// interrupted recreate Compose's next `up` can exit 0 having only tidied up.
// The restore reads Docker, sees no running proxy, and runs `up` once more.
func TestStartupReconcile_RestoreRunsUpOnceMoreAfterACleanupOnlyPass(t *testing.T) {
	r := restoreRig(t, true, true)
	r.world.upNoop = 1
	got := r.run(t)
	if got.Outcome != OutcomeConverged {
		t.Fatalf("result = %+v, want converged after the second `up`", got)
	}
	if want := []string{"tag:" + cfgOld, "up", "up"}; !reflect.DeepEqual(r.world.calls(), want) {
		t.Errorf("mutating calls = %v, want %v", r.world.calls(), want)
	}
}

// TestStartupReconcile_RestoreIsBoundedByTheAttemptCap: a restore that keeps
// failing is not retried for ever. At the cap the record is only reported.
func TestStartupReconcile_RestoreIsBoundedByTheAttemptCap(t *testing.T) {
	r := newReconRig(t, true)
	r.world.running = ""
	r.world.pinned = cfgNew
	r.srv.startOnlyUp = true
	r.srv.startMarkerLive.Store(true)
	r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) { rec.ReconcileAttempts = maxReconcileAttempts })
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "reconcile_exhausted" {
		t.Fatalf("result = %+v, want recovery_required/reconcile_exhausted", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls past the attempt cap: %v", c)
	}
}
