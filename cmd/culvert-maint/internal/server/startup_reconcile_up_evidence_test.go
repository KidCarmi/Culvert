package server

import (
	"errors"
	"testing"

	"culvert-maint/internal/journal"
)

// The Docker-side evidence restore_prior requires (ADR-0062 slice 4, B1): a
// death inside `compose up` leaves a "created" proxy container; the journal's
// attribution alone cannot tell that death from a `compose up` that returned
// while the state directory could not record it.

func assertNothingStarted(t *testing.T, r *reconRig, got ReconcileRecord, reason string) {
	t.Helper()
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != reason {
		t.Errorf("result = %+v, want recovery_required/%s", got, reason)
	}
	if calls := r.world.calls(); len(calls) != 0 || r.world.running != "" {
		t.Errorf("calls = %v running = %q, want nothing changed", calls, r.world.running)
	}
	if r.recordOnDisk(t) == nil {
		t.Error("the record was retired without a restore")
	}
}

// TestStartupReconcile_NoLeftoverNoRestore: attributed, stack down, every other
// condition holds, but Docker shows no "created" proxy container (an operator's
// `compose down` removed it). Nothing is started.
func TestStartupReconcile_NoLeftoverNoRestore(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.world.leftover = false
	assertNothingStarted(t, r, r.run(t), "stack_down_no_up_evidence")
}

// TestStartupReconcile_UnreadableEvidenceNoRestore: `compose ps -a` fails (an
// install whose sudoers file predates the rule). Unreadable evidence is never
// taken for present, and the journal's attribution is not enough on its own.
// (That an "exited" proxy, as a `docker stop` leaves, is not evidence is
// tested where the listing is parsed: runner.ProxyCreatedLeftover.)
func TestStartupReconcile_UnreadableEvidenceNoRestore(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.world.psAllFail = true
	assertNothingStarted(t, r, r.run(t), "up_evidence_unreadable")
}

// TestStartupReconcile_EvidenceIsReadOnlyWhenItCanDecide: without the
// attribution, or with a proxy listed, `compose ps -a` is never issued, so an
// install whose sudoers file predates it sees no new failing call.
func TestStartupReconcile_EvidenceIsReadOnlyWhenItCanDecide(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T) *reconRig{
		"no attribution": func(t *testing.T) *reconRig { return priorRestoreRig(t, true, false) },
		"proxy running": func(t *testing.T) *reconRig {
			r := priorRestoreRig(t, true, true)
			r.setWorld(cfgOld, cfgOld)
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := setup(t)
			_ = r.run(t)
			if r.world.psAllCount != 0 {
				t.Errorf("compose ps -a issued %d times, want 0", r.world.psAllCount)
			}
		})
	}
}

// TestStartupReconcile_EvidenceIsRecheckedBeforeTheFirstChange: the leftover is
// there when the start decides, and gone (an operator's `compose down`) by the
// recheck in front of the retag. Nothing is changed.
func TestStartupReconcile_EvidenceIsRecheckedBeforeTheFirstChange(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.world.onPS = func(int) {
		// After the decision's `compose ps -a` has answered, before the next read.
		r.world.mu.Lock()
		if r.world.psAllCount == 1 {
			r.world.leftover = false
		}
		r.world.mu.Unlock()
	}
	got := r.run(t)
	if got.Reason != "docker_changed_before_action" || len(r.world.calls()) != 0 {
		t.Errorf("result = %+v calls = %v, want docker_changed_before_action and nothing changed", got, r.world.calls())
	}
}

// TestStartupReconcile_StaleCloseThenOperatorDownIsNotRestored is the review's
// B1 scenario. The restore's own `up` returns to a live agent, but the state
// directory cannot record that (disk full) until the process ends, so the
// intent stays in the record. The operator then takes the stack down on
// purpose. The next start attributes the outage to a death inside `up` (the
// journal cannot tell), but Docker shows no "created" container: nothing is
// started.
func TestStartupReconcile_StaleCloseThenOperatorDownIsNotRestored(t *testing.T) {
	r := priorRestoreRig(t, false, true) // the restored prior will not be ready
	r.world.onUp = func() { r.jnl.SetWriteErrorForTest(errors.New("no space left on device")) }
	_ = r.run(t)
	if r.intentOnDisk(t) == nil {
		t.Fatal("setup: the stale intent must be on disk")
	}
	r.world.onUp = nil
	_ = r.srv.Close()
	// The operator's `compose down`: no container in any state.
	r.setWorld("", r.world.pinned)
	r.world.mu.Lock()
	r.world.leftover = false
	r.world.mu.Unlock()
	r.jnl.SetWriteErrorForTest(nil)
	rec := r.recordOnDisk(t)
	cmd, attributed, _ := rec.TakeIntent()
	if err := r.jnl.Write(*rec); err != nil {
		t.Fatal(err)
	}
	if !attributed || cmd != journal.MutationComposeUp {
		t.Fatalf("setup: the next start must attribute the outage to compose up (got %q, %v)", cmd, attributed)
	}
	r.restart(t)
	r.clearCalls()
	r.ready.Store(true)
	r.srv.SetCommandAttribution(map[string]string{testOpULID: cmd})
	assertNothingStarted(t, r, r.run(t), "stack_down_no_up_evidence")
}

// TestStartupReconcile_EvidenceIsRecheckedBeforeTheFirstUp: the leftover is
// there at the decision and at the recheck before the retag; an operator's
// `compose down` removes it after the retag. The reconcile's own `up` must not
// run (independent review, S1).
func TestStartupReconcile_EvidenceIsRecheckedBeforeTheFirstUp(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.world.onTag = func(w *reconWorld) { w.leftover = false } // called under the world's lock
	got := r.run(t)
	if calls := r.world.calls(); got.Reason != "docker_changed_before_up" || len(calls) != 1 {
		t.Errorf("result = %+v calls = %v, want docker_changed_before_up after the tag only", got, calls)
	}
	if r.recordOnDisk(t) == nil {
		t.Error("the record was retired without a restore")
	}
}

// TestStartupReconcile_AStaleOneOffIsNotEvidence: an operator once ran
// `compose run` without --rm and its start failed, leaving a "created" one-off
// of the proxy service that `compose down` does not remove. After a later
// death inside `up` and a deliberate `compose down`, that one-off must not
// stand in for the leftover the down removed (independent review, B1').
func TestStartupReconcile_AStaleOneOffIsNotEvidence(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.world.leftover, r.world.oneOffRun = false, true
	assertNothingStarted(t, r, r.run(t), "stack_down_no_up_evidence")
}
