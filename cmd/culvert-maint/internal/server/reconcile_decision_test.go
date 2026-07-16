package server

import (
	"testing"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// Digest fixtures. IMG* are config-digest (image .Id) class; MAN* are
// per-platform manifest descriptor class; LIST* is a manifest-list class. The
// point of several tests is that these classes must NOT be assumed equal.
const (
	imgTarget = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	imgPrior  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	manTarget = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	manPrior  = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	listTgt   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
)

// base returns a valid, unbounded, upgrades.apply input the individual tests
// mutate. RefValid=true and no attempt cap so the phase/digest ladder is reached.
func base() reconcileInputs {
	return reconcileInputs{
		Kind:        ops.KindUpgradeApply,
		RefValid:    true,
		MaxAttempts: 3,
	}
}

func TestReconcileDecision_Routing(t *testing.T) {
	// mode=data always routes to manual, even with valid refs / live target.
	in := base()
	in.Kind = ops.KindRollbackCreate
	in.Mode = "data"
	in.Phase = journal.PhaseRestarting
	if v := reconcileDecision(in); v.Action != actDataManual {
		t.Errorf("mode=data → %s, want data_manual", v.Action)
	}
}

func TestReconcileDecision_TrustAndBound(t *testing.T) {
	// invalid ref → loud stop, before any digest logic.
	in := base()
	in.RefValid = false
	in.Phase = journal.PhaseRestarting
	if v := reconcileDecision(in); v.Action != actLoudStop || v.Reason != "invalid_record_ref" {
		t.Errorf("invalid ref → %s/%s, want loud_stop/invalid_record_ref", v.Action, v.Reason)
	}
	// exhausted attempts → loud stop.
	in = base()
	in.Attempts = 3
	in.Phase = journal.PhaseRestarting
	in.RunningDigests = []string{"sha256:" + manPrior}
	in.PriorDigests = []string{"sha256:" + manPrior}
	if v := reconcileDecision(in); v.Action != actLoudStop || v.Reason != "reconcile_exhausted" {
		t.Errorf("exhausted → %s/%s, want loud_stop/reconcile_exhausted", v.Action, v.Reason)
	}
}

// TestReconcileDecision_PrefixMismatch is the P0-A regression: a record field
// stored STRIPPED must still match a prefixed capture set. Before the fix this
// fell through to a spurious rollback.
func TestReconcileDecision_PrefixMismatch(t *testing.T) {
	in := base()
	in.Phase = journal.PhaseVerified
	in.RunningDigests = []string{"sha256:" + manTarget} // capture keeps the prefix
	in.TargetDigests = []string{manTarget}              // record stored it stripped
	v := reconcileDecision(in)
	if v.Action != actVerifyAdoptElseRollback {
		t.Errorf("stripped-record vs prefixed-capture → %s, want verify_adopt_else_rollback (must NOT false-rollback)", v.Action)
	}
}

// TestReconcileDecision_ConfigDigestClassInvariant is the P0-B regression: the
// running image was tag/seed-pulled (reports a LIST digest, not the per-platform
// target manifest digest), so the manifest sets DON'T intersect — but the
// class-invariant config digest matches, so it must ADOPT, not rollback.
func TestReconcileDecision_ConfigDigestClassInvariant(t *testing.T) {
	in := base()
	in.Phase = journal.PhaseRestarted
	in.RunningImageID = imgTarget                      // config digest matches
	in.TargetImageID = imgTarget                       //
	in.RunningDigests = []string{"sha256:" + listTgt}  // list class (tag/seed pull)
	in.TargetDigests = []string{"sha256:" + manTarget} // per-platform class (record)
	in.PriorImageID = imgPrior
	in.PriorDigests = []string{"sha256:" + manPrior}
	v := reconcileDecision(in)
	if v.Action != actVerifyAdoptElseRollback {
		t.Errorf("config-digest match across manifest classes → %s, want verify_adopt_else_rollback (no false rollback)", v.Action)
	}
}

func TestReconcileDecision_DangerWindowTable(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*reconcileInputs)
		want    reconcileAction
		wantWhy string
	}{
		{
			name: "live target → verify/adopt",
			mutate: func(in *reconcileInputs) {
				in.Phase = journal.PhaseRestarted
				in.RunningDigests = []string{"sha256:" + manTarget}
				in.TargetDigests = []string{"sha256:" + manTarget}
				in.PriorDigests = []string{"sha256:" + manPrior}
			},
			want: actVerifyAdoptElseRollback, wantWhy: "live_target",
		},
		{
			name: "already on prior → noop",
			mutate: func(in *reconcileInputs) {
				in.Phase = journal.PhaseRestarting
				in.RunningDigests = []string{"sha256:" + manPrior}
				in.TargetDigests = []string{"sha256:" + manTarget}
				in.PriorDigests = []string{"sha256:" + manPrior}
			},
			want: actNoop, wantWhy: "already_on_prior",
		},
		{
			name: "tag advanced, container stale → reup",
			mutate: func(in *reconcileInputs) {
				in.Phase = journal.PhaseRestarting
				in.RunningDigests = []string{"sha256:" + manPrior} // still old
				in.TargetDigests = []string{"sha256:" + manTarget}
				in.TagDigests = []string{"sha256:" + manTarget} // tag moved
				in.PriorDigests = nil                           // not prior either (force past liveIsPrior)
			},
			want: actReup, wantWhy: "tag_advanced_container_stale",
		},
		{
			name: "indeterminate + prior known → rollback",
			mutate: func(in *reconcileInputs) {
				in.Phase = journal.PhaseRestarting
				in.RunningDigests = []string{"sha256:0000000000000000000000000000000000000000000000000000000000000000"}
				in.TargetDigests = []string{"sha256:" + manTarget}
				in.PriorImageID = imgPrior
				in.PriorDigests = []string{"sha256:" + manPrior}
			},
			want: actRollbackToPrior, wantWhy: "indeterminate_restore_prior",
		},
		{
			name: "indeterminate + no prior → loud stop",
			mutate: func(in *reconcileInputs) {
				in.Phase = journal.PhaseRestarting
				in.RunningDigests = []string{"sha256:0000000000000000000000000000000000000000000000000000000000000000"}
				in.TargetDigests = []string{"sha256:" + manTarget}
				// no prior at all
			},
			want: actLoudStop, wantWhy: "no_recovery_target",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			tc.mutate(&in)
			v := reconcileDecision(in)
			if v.Action != tc.want {
				t.Errorf("action = %s, want %s (reason %q)", v.Action, tc.want, v.Reason)
			}
			if tc.wantWhy != "" && v.Reason != tc.wantWhy {
				t.Errorf("reason = %q, want %q", v.Reason, tc.wantWhy)
			}
		})
	}
}

func TestReconcileDecision_SafeBoundary(t *testing.T) {
	// Genuine safe boundary: target not live, tag not on target → noop.
	in := base()
	in.Phase = journal.PhasePulled
	in.RunningDigests = []string{"sha256:" + manPrior}
	in.TargetDigests = []string{"sha256:" + manTarget}
	in.PriorDigests = nil // not prior-match either, so we reach the safe-boundary branch
	if v := reconcileDecision(in); v.Action != actNoop || v.Reason != "safe_boundary_confirmed" {
		t.Errorf("genuine safe boundary → %s/%s, want noop/safe_boundary_confirmed", v.Action, v.Reason)
	}
}

// TestReconcileDecision_ElidedFsyncSafeBoundary is the crash-F4 regression: the
// journal says a SAFE boundary (pulled) but Docker shows the target IS live (an
// elided parent-fsync lost the restarting/restarted write). Trusting the phase
// would adopt a never-health-gated image invisibly; we must instead verify.
func TestReconcileDecision_ElidedFsyncSafeBoundary(t *testing.T) {
	in := base()
	in.Phase = journal.PhasePulled // journal thinks tag never advanced
	in.RunningImageID = imgTarget  // but Docker says target is live
	in.TargetImageID = imgTarget
	in.PriorImageID = imgPrior
	if v := reconcileDecision(in); v.Action != actVerifyAdoptElseRollback {
		t.Errorf("elided-fsync safe boundary with live target → %s, want verify_adopt_else_rollback", v.Action)
	}
}

// TestReconcileDecision_PriorEqualsTarget: same-version apply — prior==target.
// Rolling back is meaningless; must verify/adopt, never rollback.
func TestReconcileDecision_PriorEqualsTarget(t *testing.T) {
	in := base()
	in.Phase = journal.PhaseRestarting
	in.RunningImageID = imgTarget
	in.TargetImageID = imgTarget
	in.PriorImageID = imgTarget // prior == target
	v := reconcileDecision(in)
	if v.Action != actVerifyAdoptElseRollback || v.Reason != "live_target_prior_equals_target" {
		t.Errorf("prior==target → %s/%s, want verify_adopt_else_rollback/live_target_prior_equals_target", v.Action, v.Reason)
	}
}
