// Pure decision core, version 2, for the opt-in startup reconcile in `converge`
// mode (contract AGT-900; owner decision 1 of the AGT-900 recovery proposal).
//
// THIS FILE HAS NO SIDE EFFECTS. It runs no docker command, touches no disk and,
// in this change, has no production caller. The original reconcileDecision
// (reconcile_decision.go) is left exactly as it was: the lifecycle conformance
// suite pins it as the transcription of the PR-E v2 design table. V2 is the
// table the owner approved, which is deliberately narrower:
//
//   - Default posture is "report and change nothing". Every verdict that is not
//     backed by Docker identity evidence is recovery_required (RR), which
//     changes nothing in Docker. When Docker cannot be read the verdict is
//     defer: no action, and the caller does not count an attempt.
//   - It NEVER starts an image that has not passed the health gate. There is no
//     `reup` (N4) and no `rollback_to_prior` on an indeterminate running image
//     (N5). The only actions that touch Docker are:
//     realign — `docker tag <PriorRef> culvert/proxy:pinned` while the container
//     provably still runs the prior image; nothing is restarted.
//     finish_rollback — the fixed tag is ALREADY on the prior image and the
//     journal durably records that inline rollback was armed
//     (Record.RollbackArmed): `compose up` starts the prior image, which the
//     caller then health-gates and verifies by id.
//     restore_prior — no proxy container is running and a durable marker shows
//     the agent's own `compose up` was cut: retag to the prior image and
//     `compose up` it, which the caller then health-gates and verifies by id
//     (owner decision of 2026-11-24; see stackDownV2).
//     adopt — no Docker mutation at all: only at phase `verified` (the gate
//     and the digest verify passed durably before the crash), with the
//     container and the tag on the target by id and a fresh ReadyOK probe.
//   - Identity is by local image id (N6/N8): the id the pinned tag resolves to
//     (runner.PinnedTagImageID) and the running container's image id are
//     compared with `docker image inspect <validated TargetRef>`.Id and the
//     journal's PriorImageID (captured from the running container before the op
//     touched anything). The journal's TargetImageID is trusted only at phase
//     `verified` and must then agree with the local target id (N1); a
//     TargetImageID that equals PriorImageID while the digests differ is the F1
//     artefact and is therefore never evidence.
//   - The repo-digest axis is used only as an additional condition for adopt:
//     the running image's RepoDigests must contain the record's TargetDigest,
//     which is what the online verify stage accepted (N7). It never identifies
//     the tag.
package server

import (
	"strings"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// reconcileActionV2 is a V2 verdict's action.
type reconcileActionV2 int

const (
	// actV2Noop: Docker is provably in a consistent pre-operation (or completed
	// rollback) state; nothing is changed.
	actV2Noop reconcileActionV2 = iota
	// actV2Realign: retag the fixed tag to the validated PriorRef. No restart.
	actV2Realign
	// actV2FinishRollback: the tag is already on the prior image and inline
	// rollback was durably armed: `compose up`, gate the prior image, verify.
	actV2FinishRollback
	// actV2RestorePrior: no proxy container is running, and a durable marker
	// shows that the agent's own `compose up` was left unfinished: retag to the
	// prior image, `compose up`, gate the prior image, verify. Owner decision of
	// 2026-11-24. Never starts the target.
	actV2RestorePrior
	// actV2Adopt: the verified target is live under the tag and answers ready.
	// No Docker change.
	actV2Adopt
	// actV2RecoveryRequired: evidence is insufficient or contradicts the
	// journal. Nothing is changed; the operator is told.
	actV2RecoveryRequired
	// actV2Defer: Docker could not be read. Nothing is changed and the attempt
	// is not counted; the next start decides again.
	actV2Defer
)

func (a reconcileActionV2) String() string {
	switch a {
	case actV2Noop:
		return "noop"
	case actV2Realign:
		return "realign"
	case actV2FinishRollback:
		return "finish_rollback"
	case actV2RestorePrior:
		return "restore_prior"
	case actV2Adopt:
		return "adopt"
	case actV2RecoveryRequired:
		return "recovery_required"
	case actV2Defer:
		return "defer"
	default:
		return "unknown"
	}
}

// mutatesDocker reports whether the action changes Docker state.
func (a reconcileActionV2) mutatesDocker() bool {
	return a == actV2Realign || a == actV2FinishRollback || a == actV2RestorePrior
}

// probeState is the result of the fresh readiness probe the caller runs only
// when reconcileNeedsProbe says an adopt is otherwise possible.
type probeState int

const (
	probeNotRun   probeState = iota // no probe was run (fail-closed: never adopts)
	probeReady                      // health.Result.ReadyOK
	probeNotReady                   // any other outcome, including a timeout
)

// reconcileInputsV2 is the fully resolved fact set for one record. Image ids
// are compared with any `sha256:` prefix removed. "" always means "not known",
// never "matches nothing in particular".
type reconcileInputsV2 struct {
	// From the journal record.
	Kind  string
	Mode  string
	Phase journal.Phase
	// RefValid is validateReconcileRefs on the record. TargetRefPresent and
	// PriorRefPresent say which references the record carries; they are
	// meaningful only when RefValid is true.
	RefValid         bool
	TargetRefPresent bool
	PriorRefPresent  bool
	TargetDigest     string // record's bare target manifest digest
	TargetImageID    string // record; trusted only at PhaseVerified
	PriorImageID     string // record; captured from the running container before the op
	RollbackArmed    bool   // record; inline rollback was about to move the tag
	Attempts         int    // reconcile attempts already made for this record
	MaxAttempts      int    // cap; 0 disables

	// From Docker, read by the caller. DockerReadable=false means the daemon
	// could not be read (compose ps, container inspect or pinned-tag inspect
	// failed); every other Docker field is then ignored.
	DockerReadable   bool
	RunningImageID   string   // "" = no proxy container
	ContainerRunning bool     // the proxy container's State is "running"
	RunningDigests   []string // RepoDigests of the running image (repo@sha256:… or bare)
	TagImageID       string   // id culvert/proxy:pinned resolves to
	TargetLocalID    string   // `docker image inspect <TargetRef>`.Id, "" when not local or not inspected
	PriorLocalID     string   // `docker image inspect <PriorRef>`.Id, "" when not local or not inspected

	Probe probeState

	// UpInterrupted: this agent process found, at its start, a readable
	// mutation marker that names nothing but `compose up`
	// (journal.MutationLog), and has not cleared it. It is the evidence that a
	// proxy that is down is down because the agent's own recreate was cut, and
	// not because an operator took the stack down. Read from disk by the
	// caller; not a Docker fact.
	UpInterrupted bool
}

// reconcileVerdictV2 is the decision plus the audit reason.
type reconcileVerdictV2 struct {
	Action reconcileActionV2
	Reason string
}

func rr(reason string) reconcileVerdictV2 {
	return reconcileVerdictV2{actV2RecoveryRequired, reason}
}

// v2ids is the normalized identity view of an input.
type v2ids struct {
	run, tag, target, prior, priorLocal, tid string
}

func normID(s string) string { return strings.TrimPrefix(s, "sha256:") }

func idsOf(in *reconcileInputsV2) v2ids {
	ids := v2ids{
		run:        normID(in.RunningImageID),
		tag:        normID(in.TagImageID),
		prior:      normID(in.PriorImageID),
		priorLocal: normID(in.PriorLocalID),
		tid:        normID(in.TargetImageID),
	}
	// A target id is only meaningful for a validated record that names a target.
	if in.RefValid && in.TargetRefPresent {
		ids.target = normID(in.TargetLocalID)
	}
	return ids
}

// reconcileDecisionV2 is the total, pure V2 decision. Ordered first match.
func reconcileDecisionV2(in reconcileInputsV2) reconcileVerdictV2 {
	imageKind := (in.Kind == ops.KindUpgradeApply && in.Mode == "") ||
		(in.Kind == ops.KindRollbackCreate && in.Mode == "image")
	switch {
	case in.Kind == ops.KindRollbackCreate && in.Mode == "data":
		// Never touches Docker; the existing manual data-recovery report applies.
		return rr("data_window_manual")
	case !imageKind:
		return rr("unknown_kind_or_mode")
	case !in.DockerReadable:
		return reconcileVerdictV2{actV2Defer, "docker_unavailable"}
	case in.MaxAttempts > 0 && in.Attempts >= in.MaxAttempts:
		return rr("reconcile_exhausted")
	}
	ids := idsOf(&in)
	if ids.run != "" && !in.ContainerRunning {
		return rr("container_not_running")
	}
	if in.Kind == ops.KindRollbackCreate {
		return decideStandaloneRollbackV2(&in, ids)
	}
	if safeBoundary(in.Phase) {
		return decideSafePhaseV2(ids)
	}
	return decideDangerPhaseV2(&in, ids)
}

// decideSafePhaseV2: the fsynced write-ahead barrier precedes every tag move, so
// at admitted..pulled the journal vouches that the agent did not move the tag.
// Docker must agree before the record counts as converged (N9: an unvalidated
// reference at a safe phase is not fatal, because no reference reaches Docker).
func decideSafePhaseV2(ids v2ids) reconcileVerdictV2 {
	if ids.target != "" && ids.target != ids.prior && (ids.tag == ids.target || ids.run == ids.target) {
		// Only an elided fsync can put the target under the tag or in the
		// container at a safe phase (design crash-F4).
		return rr("journal_contradicts_docker")
	}
	if ids.run == "" {
		return rr("stack_down_unverifiable")
	}
	if ids.tag != ids.run {
		return rr("tag_differs_from_running")
	}
	if ids.prior != "" && ids.run != ids.prior {
		return rr("running_not_prior")
	}
	return reconcileVerdictV2{actV2Noop, "safe_boundary_unchanged"}
}

// decideDangerPhaseV2 handles an upgrade at restarting / restarted / verified.
func decideDangerPhaseV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	if !in.RefValid {
		return rr("invalid_record_ref")
	}
	if ids.run == "" {
		return stackDownV2(in, ids)
	}
	p, t := ids.prior, ids.target
	if p != "" && ids.run == p && ids.tag == p {
		return reconcileVerdictV2{actV2Noop, "already_on_prior"}
	}
	if t == "" {
		return rr("target_not_identifiable")
	}
	if t == p {
		// The target resolves to the prior image but tag/container are not both
		// on it: nothing distinguishes "upgraded" from "not upgraded".
		return rr("target_equals_prior_ambiguous")
	}
	return decideByIdentityV2(in, ids)
}

// stackDownV2 decides an upgrade in the danger window with no proxy container
// running. Until the owner decision of 2026-11-24 this was always
// recovery_required: an outage until an operator acted.
//
// The prior image is restored only when every one of these holds. Each is a
// reason the agent may start a container on its own:
//
//   - UpInterrupted: the outage is attributable to the agent's own `compose
//     up` having been cut. Without the marker the stack may be down because an
//     operator took it down, and starting it would undo that.
//   - The upgrade had not been verified. At phase verified (and no rollback
//     armed) the target passed its gate and digest check before the crash;
//     going back to the prior image would silently undo a good upgrade, and
//     starting the target is never done here. Reported instead.
//   - The prior image is restorable: a validated PriorRef that resolves
//     locally to the image id recorded before the operation.
//   - The fixed tag is on the prior or on the target, the only two places this
//     operation can have left it. Anywhere else, someone else moved it.
//
// What is started is the image that was serving before the operation began;
// the caller health-gates and verifies it by id before the record is retired.
func stackDownV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	switch {
	case !in.UpInterrupted:
		return rr("stack_down")
	case in.Phase == journal.PhaseVerified && !in.RollbackArmed:
		return rr("stack_down_after_verified")
	case !priorRestorable(in, ids):
		return rr("prior_not_restorable")
	case ids.tag != ids.prior && (ids.target == "" || ids.tag != ids.target):
		return rr("stack_down_tag_unrecognised")
	}
	return reconcileVerdictV2{actV2RestorePrior, "stack_down_up_interrupted"}
}

// decideByIdentityV2 picks the action from the (container, tag) identity pair
// once prior and target are known to be distinct images.
func decideByIdentityV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	p, t := ids.prior, ids.target
	switch {
	case p != "" && ids.run == p && ids.tag == t:
		// Crash between `docker tag` and `compose up` (A5), or `up` that did not
		// recreate (A8, F1). Retag only; AGT-002 precedent.
		return realignV2(in, ids)
	case ids.run == t && ids.tag == t:
		return adoptV2(in, ids)
	case p != "" && ids.run == t && ids.tag == p:
		return finishRollbackV2(in, ids)
	}
	return rr("docker_state_unrecognised")
}

func priorRestorable(in *reconcileInputsV2, ids v2ids) bool {
	return in.PriorRefPresent && ids.prior != "" && ids.priorLocal == ids.prior
}

func realignV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	if !priorRestorable(in, ids) {
		return rr("prior_not_restorable")
	}
	return reconcileVerdictV2{actV2Realign, "tag_ahead_container_on_prior"}
}

func adoptV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	switch {
	case in.RollbackArmed:
		// The agent had already decided the target failed (N3).
		return rr("rollback_armed_target_live")
	case in.Phase != journal.PhaseVerified:
		// The target is live but never passed the gate (A6/A7).
		return rr("target_live_ungated")
	case ids.tid != ids.target:
		return rr("verified_target_id_mismatch")
	case !digestListed(in.RunningDigests, in.TargetDigest):
		return rr("target_digest_unverified")
	}
	switch in.Probe {
	case probeReady:
		return reconcileVerdictV2{actV2Adopt, "verified_target_live"}
	case probeNotReady:
		return rr("verified_target_not_ready")
	default:
		return rr("readiness_not_probed")
	}
}

func finishRollbackV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	if !in.RollbackArmed {
		// Without the durable marker nothing proves the agent moved the tag;
		// it may have been an operator.
		return rr("tag_on_prior_rollback_unproven")
	}
	if !priorRestorable(in, ids) {
		return rr("prior_not_restorable")
	}
	return reconcileVerdictV2{actV2FinishRollback, "rollback_interrupted"}
}

// decideStandaloneRollbackV2 handles rollbacks.create mode=image. The record
// names only the rollback target and stays at PhaseAdmitted (standalone
// rollback writes no progress), so the journal proves nothing about how far it
// got: only "the tag never moved" can be accepted without an operator.
func decideStandaloneRollbackV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	if !in.RefValid {
		return rr("invalid_record_ref")
	}
	if ids.run == "" {
		return rr("stack_down")
	}
	if ids.target != "" && (ids.tag == ids.target || ids.run == ids.target) {
		// S2/S3: the rollback moved the tag or the container, and nothing
		// says it was health-gated.
		return rr("rollback_target_partially_applied")
	}
	if ids.tag != ids.run {
		return rr("tag_differs_from_running")
	}
	return reconcileVerdictV2{actV2Noop, "rollback_never_moved_tag"}
}

// digestListed reports whether bare digest d (with or without `sha256:`) is
// the digest of one of refs (`repo@sha256:<hex>`, `sha256:<hex>` or bare hex).
func digestListed(refs []string, d string) bool {
	d = normID(d)
	if d == "" {
		return false
	}
	for _, r := range refs {
		if i := strings.LastIndexByte(r, '@'); i >= 0 {
			r = r[i+1:]
		}
		if normID(r) == d {
			return true
		}
	}
	return false
}

// reconcileNeedsProbe reports whether the verdict would be adopt if the fresh
// readiness probe answered ready. The caller runs the probe only then, so a
// probe is never run for a record that could not be adopted anyway.
func reconcileNeedsProbe(in reconcileInputsV2) bool {
	in.Probe = probeReady
	return reconcileDecisionV2(in).Action == actV2Adopt
}
