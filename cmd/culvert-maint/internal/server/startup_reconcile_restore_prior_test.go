package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// priorRestoreRig: an upgrade died at phase restarting, the fixed tag is on the
// target, and no proxy container is running. ownUpCut says whether this agent
// start found the marker of its own unfinished `compose up`.
func priorRestoreRig(t *testing.T, ready, ownUpCut bool) *reconRig {
	t.Helper()
	r := newReconRig(t, ready)
	r.world.running = ""
	r.world.pinned = cfgNew
	if ownUpCut {
		r.srv.startUpOf = testOpULID
	}
	r.srv.startMarkerLive.Store(ownUpCut)
	r.seed(t, journal.PhaseRestarting, nil)
	return r
}

// otherOpULID is an operation other than the rig's record.
const otherOpULID = "01BX5ZZKBKACTAV9WEVGEMMVRZ"

func assertOnlyReported(t *testing.T, r *reconRig, got ReconcileRecord) {
	t.Helper()
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "stack_down" {
		t.Errorf("result = %+v, want recovery_required/stack_down", got)
	}
	if c := r.world.calls(); len(c) != 0 {
		t.Errorf("mutating calls: %v, want none", c)
	}
	if r.world.running != "" {
		t.Error("a container was started")
	}
	if r.recordOnDisk(t) == nil {
		t.Error("the record was retired")
	}
}

// TestStartupReconcile_AnotherOperationsCutUpIsNotThisRecords: the marker found
// at start belongs to a different operation. This record cannot claim it.
func TestStartupReconcile_AnotherOperationsCutUpIsNotThisRecords(t *testing.T) {
	r := priorRestoreRig(t, true, false)
	r.srv.startUpOf = otherOpULID
	r.srv.startOnlyUp = true
	r.srv.startMarkerLive.Store(true)
	assertOnlyReported(t, r, r.run(t))
}

// TestStartupReconcile_AnUpOnlyMarkerWithoutAnOwnerIsNotEnough: a marker that
// names only `compose up` but that this start is not the first to find, or
// that says nothing about whose it was, attributes nothing (the stack may have
// been taken down since by anyone).
func TestStartupReconcile_AnUpOnlyMarkerWithoutAnOwnerIsNotEnough(t *testing.T) {
	r := priorRestoreRig(t, true, false)
	r.srv.startOnlyUp = true
	r.srv.startMarkerLive.Store(true)
	assertOnlyReported(t, r, r.run(t))
}

// TestStartupReconcile_AMarkerClearedInThisProcessAttributesNothing: a `compose
// up` of this process has since succeeded with nothing in doubt and removed
// the marker. What Docker shows now is no longer the cut command's doing.
func TestStartupReconcile_AMarkerClearedInThisProcessAttributesNothing(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.srv.startMarkerLive.Store(false)
	assertOnlyReported(t, r, r.run(t))
}

// TestStartupReconcile_OnlyTheCutOperationsRecordRestores: two records are left.
// The older upgrade (old -> new) was never retired; the newer one (new -> X)
// died in the `compose up` of its armed rollback, with the fixed tag back on
// `new`. The marker belongs to the newer operation. The older record must not
// claim it and bring back `old`, an image two generations behind what was
// serving.
func TestStartupReconcile_OnlyTheCutOperationsRecordRestores(t *testing.T) {
	r := newReconRig(t, true)
	r.world.running = ""
	r.world.pinned = cfgNew
	r.srv.startOnlyUp = true
	r.srv.startUpOf = otherOpULID
	r.srv.startMarkerLive.Store(true)
	r.seed(t, journal.PhaseRestarted, nil) // old -> new, lingering
	now := time.Now().UTC()
	x := "ab" + digNew[2:]
	if err := r.jnl.Write(journal.Record{OpID: otherOpULID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting, Actor: "cp",
		StartedAt: now, UpdatedAt: now, TargetRef: repo + "@sha256:" + x, TargetDigest: x,
		PriorRef: repo + "@sha256:" + digNew, PriorDigest: digNew, PriorImageID: "sha256:" + cfgNew, RollbackArmed: true}); err != nil {
		t.Fatal(err)
	}
	older := r.run(t)
	if older.Outcome != OutcomeRecoveryRequired || older.Reason != "stack_down" || len(older.Actions) != 0 {
		t.Errorf("older record = %+v, want recovery_required/stack_down with no action", older)
	}
	for _, c := range r.world.calls() {
		if c == "tag:"+cfgOld {
			t.Errorf("the fixed tag was moved to the older record's prior image: %v", r.world.calls())
		}
	}
	if r.world.running == cfgOld {
		t.Error("the image of two generations back was started")
	}
	if r.recordOnDisk(t) == nil {
		t.Error("the older record was retired")
	}
}

// TestStartupReconcile_RestoreIsVerifiedByImageID: `compose up` returned and
// something answers ready, but the container is not on the prior image.
// Readiness is not identity: the record is kept.
func TestStartupReconcile_RestoreIsVerifiedByImageID(t *testing.T) {
	r := priorRestoreRig(t, true, true)
	r.world.upStarts = cfgNew
	got := r.run(t)
	if got.Outcome != OutcomeRecoveryRequired || got.Reason != "post_verify_failed" || got.DockerReconciled {
		t.Fatalf("result = %+v, want recovery_required/post_verify_failed", got)
	}
	if r.recordOnDisk(t) == nil {
		t.Error("the record was retired although the container is not on the prior image")
	}
}

// TestStartupReconcile_ItsUpIsMarkedWithTheRecordsOperation: an `up` the
// reconcile runs for a record (restore_prior, finish_rollback) is written to
// the marker under THAT record's operation, not under the reconcile's own. So
// a start after a cut reconcile can still tell whose `up` it was, and no other
// record can claim it.
func TestStartupReconcile_ItsUpIsMarkedWithTheRecordsOperation(t *testing.T) {
	for name, rig := range map[string]func(t *testing.T) *reconRig{
		"restore_prior": func(t *testing.T) *reconRig { return priorRestoreRig(t, true, true) },
		"finish_rollback": func(t *testing.T) *reconRig {
			r := newReconRig(t, true)
			r.world.running, r.world.pinned = cfgNew, cfgOld
			r.seed(t, journal.PhaseRestarting, func(rec *journal.Record) { rec.RollbackArmed = true })
			return r
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := rig(t)
			var seen []byte
			r.world.onUp = func() {
				seen, _ = os.ReadFile(filepath.Join(r.srv.opts.StateDir, "mutation", "pending.json")) // #nosec G304 -- test-owned temp dir
			}
			if got := r.run(t); got.Decision != name || got.Outcome != OutcomeConverged {
				t.Fatalf("result = %+v, want %s converged", got, name)
			}
			var mk journal.MutationMarker
			if err := json.Unmarshal(seen, &mk); err != nil {
				t.Fatalf("marker during the up: %q: %v", seen, err)
			}
			if len(mk.Ops) != len(mk.Commands) || len(mk.Ops) == 0 || mk.Ops[len(mk.Ops)-1] != testOpULID || mk.Seen {
				t.Errorf("marker during the up = %+v, want its last command attributed to %s and unseen", mk, testOpULID)
			}
		})
	}
}

// TestStartupReconcile_RestoresPriorAfterItsOwnInterruptedUp: the proxy is down
// because the agent's own recreate was cut. The start that follows puts the
// fixed tag back on the image that was serving before the upgrade, starts it,
// requires it to answer ready, verifies both by id, and only then retires the
// record. The target image is never started.
func TestStartupReconcile_RestoresPriorAfterItsOwnInterruptedUp(t *testing.T) {
	r := priorRestoreRig(t, true, true)
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
	r := priorRestoreRig(t, true, false)
	assertOnlyReported(t, r, r.run(t))
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
	if !r.rt.RecoveryRequired() {
		t.Error("recovery_required is not reported")
	}
}

// TestStartupReconcile_RestoreRunsUpOnceMoreAfterACleanupOnlyPass: after an
// interrupted recreate Compose's next `up` can exit 0 having only tidied up.
// The restore reads Docker, sees no running proxy, and runs `up` once more.
func TestStartupReconcile_RestoreRunsUpOnceMoreAfterACleanupOnlyPass(t *testing.T) {
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

// TestStartupReconcile_RestoreIsBoundedByTheAttemptCap: a restore that keeps
// failing is not retried for ever. At the cap the record is only reported.
func TestStartupReconcile_RestoreIsBoundedByTheAttemptCap(t *testing.T) {
	r := newReconRig(t, true)
	r.world.running = ""
	r.world.pinned = cfgNew
	r.srv.startUpOf = testOpULID
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

// TestStartupReconcile_AnUpThatReturnedLeavesNoFreshMarker: the reconcile's
// `compose up` returned to a live agent, and the record is kept: the command
// failed, or it ran and the restored proxy is not ready. The agent did not die
// in it, so the marker it leaves must not tell a later start that it did. An
// operator may start the stack by hand and stop it again days later; the start
// after that must find nothing to attribute the outage to.
func TestStartupReconcile_AnUpThatReturnedLeavesNoFreshMarker(t *testing.T) {
	for name, tc := range map[string]struct {
		ready  bool
		fails  int
		reason string
	}{
		"up failed":          {true, 1, "up_failed"},
		"up ran, not ready":  {false, 0, "prior_not_ready"},
		"second up failed":   {true, 0, "up_failed"},
		"ran, another image": {true, 0, "post_verify_failed"},
	} {
		t.Run(name, func(t *testing.T) {
			r := priorRestoreRig(t, tc.ready, true)
			r.world.upFails = tc.fails
			switch name {
			case "second up failed":
				r.world.upNoop = 1
				r.world.onUp = func() {
					r.world.mu.Lock()
					defer r.world.mu.Unlock()
					if r.world.upNoop == 0 { // the first pass is over: fail the next one
						r.world.upFails = 1
					}
				}
			case "ran, another image":
				r.world.upStarts = cfgNew
			}
			got := r.run(t)
			if got.Outcome != OutcomeRecoveryRequired || got.Reason != tc.reason {
				t.Fatalf("result = %+v, want recovery_required/%s", got, tc.reason)
			}
			if r.recordOnDisk(t) == nil {
				t.Fatal("the record was retired")
			}
			raw, err := os.ReadFile(filepath.Join(r.srv.opts.StateDir, "mutation", "pending.json")) // #nosec G304 -- test-owned temp dir
			if err != nil {
				t.Fatalf("no marker after the reconcile's up: %v", err)
			}
			var mk journal.MutationMarker
			if err := json.Unmarshal(raw, &mk); err != nil {
				t.Fatal(err)
			}
			if !mk.Seen {
				t.Errorf("marker after an up that returned = %s, want seen", raw)
			}
			// And what the next agent start is told:
			if _, at, _ := journal.OpenMutationLog(r.srv.opts.StateDir); at.FreshUpOf != "" || !at.Pending {
				t.Errorf("next start: %+v, want Pending and no FreshUpOf", at)
			}
		})
	}
}
