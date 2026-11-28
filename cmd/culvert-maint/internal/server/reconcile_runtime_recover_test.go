package server

import (
	"testing"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// rtBase is a runtime.recover record as the executor writes it: armed, at
// restarted, prior R = P (the image the upgrade replaced), target X = T (the
// unhealthy installed image), container and tag on T, R local, compatible.
func rtBase() reconcileInputsV2 {
	in := v2Base()
	in.Kind, in.RollbackArmed = ops.KindRuntimeRecover, true
	in.RunningImageID, in.TagImageID, in.TargetImageID = idT, idT, idT
	in.Compat, in.CompatReason = compatOK, compatReasonCompatibleWithin
	return in
}

// The decision for a runtime.recover record is the armed-rollback branch, and
// every verdict that tags or starts the prior requires proven compatibility.
func TestRuntimeRecover_Decision(t *testing.T) {
	type row struct {
		name   string
		mod    func(*reconcileInputsV2)
		action reconcileActionV2
		reason string
	}
	runTag := func(run, tag string) func(*reconcileInputsV2) {
		return func(in *reconcileInputsV2) { in.RunningImageID, in.TagImageID = run, tag }
	}
	compat := func(v compatVerdict) func(*reconcileInputsV2) {
		return func(in *reconcileInputsV2) { in.Compat = v }
	}
	all := func(fs ...func(*reconcileInputsV2)) func(*reconcileInputsV2) {
		return func(in *reconcileInputsV2) {
			for _, f := range fs {
				f(in)
			}
		}
	}
	none := func(*reconcileInputsV2) {}
	rows := []row{
		{"admitted: X/X, compatible", none, actV2RetagFinishRollback, "rollback_armed_tag_not_moved"},
		{"after the retag: X running, tag on R", runTag(idT, idP), actV2FinishRollback, "rollback_interrupted"},
		{"after up: R/R, ready", all(runTag(idP, idP), func(in *reconcileInputsV2) { in.Probe = probeReady }), actV2Noop, "armed_rollback_prior_ready"},
		{"X/X, compatibility unknown", compat(compatUnknown), actV2RecoveryRequired, "restore_compatibility_unknown"},
		{"X/X, incompatible", compat(compatIncompatible), actV2RecoveryRequired, "restore_incompatible"},
		{"tag on R, X running, compatibility unknown", all(runTag(idT, idP), compat(compatUnknown)), actV2RecoveryRequired, "restore_compatibility_unknown"},
		{"R/R is retired whatever the compatibility: nothing more moves", all(runTag(idP, idP), compat(compatUnknown), func(in *reconcileInputsV2) { in.Probe = probeReady }), actV2Noop, "armed_rollback_prior_ready"},
		{"not armed: not a record this agent writes", func(in *reconcileInputsV2) { in.RollbackArmed = false }, actV2RecoveryRequired, "runtime_recover_not_armed"},
		{"another phase: not a record this agent writes", func(in *reconcileInputsV2) { in.Phase = journal.PhaseVerified }, actV2RecoveryRequired, "runtime_recover_unexpected_phase"},
		{"a third image under the tag (a manual change)", runTag(idT, idX), actV2RecoveryRequired, "docker_state_unrecognised"},
		{"a third image running (a manual change)", runTag(idX, idX), actV2RecoveryRequired, "docker_state_unrecognised"},
		{"R no longer local", func(in *reconcileInputsV2) { in.PriorLocalID = "" }, actV2RecoveryRequired, "prior_not_restorable"},
		{"stack down, nothing attributed", runTag("", idT), actV2RecoveryRequired, "stack_down"},
		{"stack down, own up cut but the evidence is not read for this kind", all(runTag("", idT), func(in *reconcileInputsV2) { in.UpInterrupted = true }), actV2RecoveryRequired, "up_evidence_unreadable"},
		{"Docker unreadable", func(in *reconcileInputsV2) { in.DockerReadable = false }, actV2Defer, "docker_unavailable"},
		{"exhausted", func(in *reconcileInputsV2) { in.Attempts = in.MaxAttempts }, actV2RecoveryRequired, "reconcile_exhausted"},
		{"a mode on the record", func(in *reconcileInputsV2) { in.Mode = "data" }, actV2RecoveryRequired, "unknown_kind_or_mode"},
	}
	for _, r := range rows {
		in := rtBase()
		r.mod(&in)
		got := reconcileDecisionV2(in)
		if got.Action != r.action || got.Reason != r.reason {
			t.Errorf("%s: %s/%s, want %s/%s", r.name, got.Action, got.Reason, r.action, r.reason)
		}
	}
}

// Exhaustive over the Docker identities, compatibility, arming, the prior's
// local image and the probe: a runtime.recover verdict that changes Docker
// always has compatibility proven and an armed record, and no verdict adopts
// the image the recovery exists to replace.
func TestRuntimeRecover_NeverActsWithoutProof(t *testing.T) {
	acting := 0
	for _, in := range runtimeRecoverInputs() {
		v := reconcileDecisionV2(in)
		if v.Action == actV2Adopt {
			t.Fatalf("a runtime recovery adopted the unhealthy image: %+v", in)
		}
		if !v.Action.mutatesDocker() {
			continue
		}
		acting++
		if in.Compat != compatOK || !in.RollbackArmed {
			t.Fatalf("%s/%s acts with compat=%v armed=%v (run=%s tag=%s)", v.Action, v.Reason, in.Compat, in.RollbackArmed,
				in.RunningImageID, in.TagImageID)
		}
	}
	if acting == 0 {
		t.Fatal("vacuous: no runtime.recover input acts")
	}
}

// runtimeRecoverInputs is the product of the dimensions above, from rtBase.
func runtimeRecoverInputs() []reconcileInputsV2 {
	ids := []string{"", idP, idT, idX}
	var out []reconcileInputsV2
	for i := 0; i < len(ids)*len(ids)*3*2*3*3; i++ {
		n := i
		pick := func(k int) int { r := n % k; n /= k; return r }
		in := rtBase()
		in.RunningImageID, in.TagImageID = ids[pick(len(ids))], ids[pick(len(ids))]
		in.Compat = []compatVerdict{compatUnknown, compatOK, compatIncompatible}[pick(3)]
		in.RollbackArmed = pick(2) == 0
		in.PriorLocalID = []string{idP, "", idX}[pick(3)]
		in.Probe = []probeState{probeNotRun, probeReady, probeNotReady}[pick(3)]
		in.ContainerRunning = in.RunningImageID != ""
		out = append(out, in)
	}
	return out
}

// Without the kind branch, an unarmed or incompatible record would be decided
// as an upgrade: these inputs prove the branch is what refuses.
func TestRuntimeRecover_TheKindIsWhatGates(t *testing.T) {
	in := rtBase()
	in.Compat = compatUnknown
	if v := reconcileDecisionV2(in); v.Action.mutatesDocker() {
		t.Fatalf("runtime.recover acted without compatibility: %v", v)
	}
	in.Kind = ops.KindUpgradeApply
	if v := reconcileDecisionV2(in); !v.Action.mutatesDocker() {
		t.Fatalf("control: the same armed upgrade record should act (%v), or this test proves nothing", v)
	}
}
