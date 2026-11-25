package server

import (
	"reflect"
	"testing"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// priorRestoreRig: an upgrade died at phase restarting with the fixed tag on
// the target, and no proxy container is running. diedInUp says whether THIS
// agent start found that the previous process died inside a `compose up` of
// that operation (the command intent of ADR-0062 slice 3); such a death also
// leaves the "created" proxy container Docker shows (the up evidence).
func priorRestoreRig(t *testing.T, ready, diedInUp bool) *reconRig {
	t.Helper()
	r := newReconRig(t, ready)
	r.world.running, r.world.pinned = "", cfgNew
	r.seed(t, journal.PhaseRestarting, nil)
	if diedInUp {
		r.srv.SetCommandAttribution(map[string]string{testOpULID: journal.MutationComposeUp})
		r.world.leftover = true
	}
	return r
}

// TestStartupReconcile_RestoresPriorAfterADeathInsideItsOwnUp: the proxy is
// down because the agent died inside this operation's recreate. The fixed tag
// goes back to the image that was serving, the proxy is started, gated, and
// verified by id; only then is the record retired. The target is never started.
func TestStartupReconcile_RestoresPriorAfterADeathInsideItsOwnUp(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	got := r.run(t)
	if got.Decision != "restore_prior" || got.Reason != "stack_down_up_interrupted" || got.Outcome != OutcomeConverged || !got.DockerReconciled {
		t.Fatalf("result = %+v, want restore_prior/stack_down_up_interrupted converged", got)
	}
	if want := []string{"tag:" + cfgOld, "up"}; !reflect.DeepEqual(r.world.calls(), want) {
		t.Errorf("mutating calls = %v, want %v", r.world.calls(), want)
	}
	if r.world.running != cfgOld || r.world.pinned != cfgOld {
		t.Errorf("after the restore: container %.8s tag %.8s, want both on the prior image", r.world.running, r.world.pinned)
	}
	if r.recordOnDisk(t) != nil {
		t.Error("the record was not retired after a verified restore")
	}
	if r.rt.RecoveryRequired() {
		t.Error("recovery_required is reported after a successful restore")
	}
}

// TestStartupReconcile_StackDownWithoutAttributionIsOnlyReported: nothing says
// the agent died inside its own `up`. The stack may be down because an
// operator took it down: it is reported, and nothing is started.
func TestStartupReconcile_StackDownWithoutAttributionIsOnlyReported(t *testing.T) {
	r := priorRestoreRig(t, true, false)
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "stack_down" {
		t.Fatalf("result = %+v, want recovery_required/stack_down", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls without attribution: %v", c)
	}
	if r.world.running != "" {
		t.Error("a container was started")
	}
}

// TestStartupReconcile_AttributionIsForThatOperationAndTakenOnce: the
// attribution names one operation and a decision takes it: another record
// cannot use it, and the same process cannot use it twice (ADR-0062 slice 4,
// obligation 1).
func TestStartupReconcile_AttributionIsForThatOperationAndTakenOnce(t *testing.T) {
	r := priorRestoreRig(t, true, false)
	r.srv.SetCommandAttribution(map[string]string{"01BX5ZZKBKACTAV9WEVGEMMVRZ": journal.MutationComposeUp})
	if got := r.run(t); got.Reason != "stack_down" || len(r.world.calls()) != 0 {
		t.Fatalf("another operation's attribution was used: %+v calls=%v", got, r.world.calls())
	}
	r.srv.SetCommandAttribution(map[string]string{testOpULID: journal.MutationComposeUp})
	if c := r.srv.takeCommandAttribution(testOpULID); c != journal.MutationComposeUp {
		t.Fatalf("first take = %q", c)
	}
	if c := r.srv.takeCommandAttribution(testOpULID); c != "" {
		t.Errorf("second take = %q, want nothing: the attribution is taken once", c)
	}
}

// TestStartupReconcile_ADeathInsideComposeDownIsNotARestore: the operation died
// inside `compose down`, not `up`. Only an interrupted `up` explains a missing
// proxy as this operation's own recreate.
func TestStartupReconcile_ADeathInsideComposeDownIsNotARestore(t *testing.T) {
	r := priorRestoreRig(t, true, false)
	r.srv.SetCommandAttribution(map[string]string{testOpULID: journal.MutationComposeDown})
	if got := r.run(t); got.Reason != "stack_down" || len(r.world.calls()) != 0 {
		t.Fatalf("result = %+v calls=%v, want stack_down and nothing started", got, r.world.calls())
	}
}

// TestStartupReconcile_RestoreRechecksDockerBeforeItsUp: between the retag and
// the `up`, something else starts a container. The recheck before the `up`
// no longer decides restore_prior: nothing more is done, the record is kept.
func TestStartupReconcile_RestoreRechecksDockerBeforeItsUp(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.world.onTag = func(w *reconWorld) { w.running = cfgNew }
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "docker_changed_before_up" {
		t.Fatalf("result = %+v, want recovery_required/docker_changed_before_up", got)
	}
	if want := []string{"tag:" + cfgOld}; !reflect.DeepEqual(r.world.calls(), want) {
		t.Errorf("mutating calls = %v, want only the retag", r.world.calls())
	}
	if r.recordOnDisk(t) == nil {
		t.Error("the record was retired")
	}
}

// TestStartupReconcile_RestoreRunsUpOnceMoreAfterATidyOnlyPass: after an
// interrupted recreate Compose's next `up` can exit 0 having only tidied up.
// The restore reads Docker, sees nothing running, rechecks, and runs `up` once
// more.
func TestStartupReconcile_RestoreRunsUpOnceMoreAfterATidyOnlyPass(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.world.upNoop = 1
	got := r.run(t)
	if got.Outcome != OutcomeConverged {
		t.Fatalf("result = %+v, want converged after the second `up`", got)
	}
	if want := []string{"tag:" + cfgOld, "up", "up"}; !reflect.DeepEqual(r.world.calls(), want) {
		t.Errorf("mutating calls = %v, want %v", r.world.calls(), want)
	}
}

// TestStartupReconcile_RestoreDoesNotRunUpAThirdTime: two tidy-only passes in a
// row. The plan has one second `up`, not a loop: the gate decides and the
// record is kept.
func TestStartupReconcile_RestoreDoesNotRunUpAThirdTime(t *testing.T) {
	r := priorRestoreRig(t, false, true)
	r.world.upNoop = 2
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired {
		t.Fatalf("result = %+v, want recovery_required", got)
	}
	if want := []string{"tag:" + cfgOld, "up", "up"}; !reflect.DeepEqual(r.world.calls(), want) {
		t.Errorf("mutating calls = %v, want %v", r.world.calls(), want)
	}
}

// TestStartupReconcile_RestoreThatIsNotReadyKeepsTheRecord: the prior image was
// started but does not answer ready. That is not a recovery: the record stays,
// recovery_required is reported, and the attempt is counted.
func TestStartupReconcile_RestoreThatIsNotReadyKeepsTheRecord(t *testing.T) {
	r := priorRestoreRig(t, false, true)
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
}

// TestStartupReconcile_RestoreIsBoundedByTheAttemptCap: a restore that keeps
// failing is not retried for ever. At the cap the record is only reported.
func TestStartupReconcile_RestoreIsBoundedByTheAttemptCap(t *testing.T) {
	r := newReconRig(t, true)
	r.world.running, r.world.pinned = "", cfgNew
	r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) { rec.ReconcileAttempts = maxReconcileAttempts })
	r.srv.SetCommandAttribution(map[string]string{testOpULID: journal.MutationComposeUp})
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "reconcile_exhausted" {
		t.Fatalf("result = %+v, want recovery_required/reconcile_exhausted", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls past the attempt cap: %v", c)
	}
}

// TestStartupReconcile_TheReconcilesOwnUpIsUnderTheRecordsOperation: if the
// agent dies inside the restore's own `up`, the next start must find the
// intent in this record (ADR-0062 slice 3), so the reconcile runs it under the
// record's operation.
func TestStartupReconcile_TheReconcilesOwnUpIsUnderTheRecordsOperation(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) *reconRig{
		"restore_prior": func(t *testing.T) *reconRig { return priorRestoreRig(t, true, true) },
		"finish_rollback": func(t *testing.T) *reconRig {
			r := newReconRig(t, true)
			r.world.running, r.world.pinned = cfgNew, cfgOld
			r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) { rec.RollbackArmed = true })
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := setup(t)
			var during *journal.CommandIntent
			r.world.onUp = func() { during = r.intentOnDisk(t) }
			if got := r.run(t); got.Outcome != OutcomeConverged {
				t.Fatalf("result = %+v, want converged", got)
			}
			if during == nil || during.Command != journal.MutationComposeUp {
				t.Errorf("intent in the record while the reconcile's `up` ran = %+v, want compose up", during)
			}
		})
	}
}

// TestStartupReconcile_RestoreKindAndPhaseGuards: the attribution is there, the
// stack is down, but the record is not an upgrade in the danger window that
// never reached verified. Nothing is started.
func TestStartupReconcile_RestoreKindAndPhaseGuards(t *testing.T) {
	for name, mod := range map[string]func(*journal.Record){
		"verified upgrade": func(rec *journal.Record) {
			rec.Phase, rec.TargetImageID = journal.PhaseVerified, "sha256:"+cfgNew
		},
		"safe phase": func(rec *journal.Record) { rec.Phase = journal.PhasePulled },
		"restore.commit": func(rec *journal.Record) {
			rec.Kind, rec.RestoreStage = ops.KindRestoreCommit, journal.RestoreStageStopping
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newReconRig(t, true)
			r.world.running, r.world.pinned = "", cfgNew
			r.seed(t, journal.PhaseRestarting, mod)
			r.srv.SetCommandAttribution(map[string]string{testOpULID: journal.MutationComposeUp})
			got := r.run(t)
			if got.Decision == "restore_prior" || len(r.world.calls()) != 0 || r.world.running != "" {
				t.Errorf("result = %+v calls=%v running=%q, want nothing started", got, r.world.calls(), r.world.running)
			}
		})
	}
}

// TestStartupReconcile_RestoreRechecksDockerBeforeItsSecondUp: the first `up`
// only tidied up, and meanwhile the fixed tag was moved to an image this
// operation never named. The second `up` must not run on that: the recheck
// before it no longer decides restore_prior, and the record is kept.
func TestStartupReconcile_RestoreRechecksDockerBeforeItsSecondUp(t *testing.T) {
	const elsewhere = "7777777777777777777777777777777777777777777777777777777777777777"
	r := priorRestoreRig(t, true, true)
	r.world.upNoop = 1
	ups := 0
	r.world.onUp = func() {
		r.world.mu.Lock()
		defer r.world.mu.Unlock()
		ups++
		if ups == 1 {
			r.world.pinned = elsewhere
		}
	}
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "docker_changed_before_up_again" {
		t.Fatalf("result = %+v, want recovery_required/docker_changed_before_up_again", got)
	}
	if want := []string{"tag:" + cfgOld, "up"}; !reflect.DeepEqual(r.world.calls(), want) {
		t.Errorf("mutating calls = %v, want %v (no second `up`)", r.world.calls(), want)
	}
	if r.world.running != "" {
		t.Error("a container was started on a tag this operation did not put there")
	}
}
