// Pure decision core, version 2, for the opt-in startup reconcile in `converge`
// mode (contract AGT-900; owner decision 1 of the AGT-900 recovery proposal).
//
// THIS FILE HAS NO SIDE EFFECTS. It runs no docker command and touches no disk;
// startup_reconcile.go executes its verdicts. The original reconcileDecision
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
//     caller then health-gates and verifies by id ("T/P armed").
//     finish_rollback_retag — the journal records the armed rollback but the
//     agent died before the rollback's own `docker tag`: container AND tag are
//     still on the target that failed its gate ("T/T armed"). Retag to the
//     validated PriorRef, then the finish_rollback steps. Each mutation is
//     preceded by a fresh read that must decide the expected verdict
//     (reconcilePlan), so `up` runs only once the tag is provably on the
//     validated prior image.
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
//   - RollbackArmed is acted on only from an upgrade record whose references
//     validated, in the danger window and before phase `verified`: the agent
//     writes it only after a post-restart failure, so an armed record at
//     `verified` contradicts itself. An unarmed record, including one from an
//     agent that predates the field, is never finished as a rollback.
//   - Container and tag on the prior image with an armed record means a
//     rollback `up` ran (the inline rollback's or this reconcile's) whose gate
//     is not durable: the record is retired only on a fresh ReadyOK, so a crash
//     during the gate, or a gate that failed, is never retired as converged.
//     The same holds after a realign of an armed record (retag only, no
//     restart, so no gate): its plan ends with a fresh probe (stepProbe). No
//     armed record is ever retired without a fresh ReadyOK of the prior.
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
	// actV2RetagFinishRollback: inline rollback was durably armed but the tag
	// never moved back (container and tag on the target): retag to the
	// validated PriorRef, re-read, then the actV2FinishRollback steps.
	actV2RetagFinishRollback
	// actV2Adopt: the verified target is live under the tag and answers ready.
	// No Docker change.
	actV2Adopt
	// actV2RecoveryRequired: evidence is insufficient or contradicts the
	// journal. Nothing is changed; the operator is told.
	actV2RecoveryRequired
	// actV2RestorePrior: no proxy container is running, the record is an
	// upgrade in the danger window that never reached verified, THIS agent
	// start found that the previous process died inside a `compose up` of the
	// record's own operation (UpInterrupted), and Docker's live state matches
	// the record: the recorded prior image is local and identical, and the
	// fixed tag is on the prior or on the target. Retag to the validated
	// PriorRef, `up`, `up` once more if nothing runs, gate; then verify by id.
	// Owner decision of 2026-11-24, ADR-0062 slice 4.
	actV2RestorePrior
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
	case actV2RetagFinishRollback:
		return "finish_rollback_retag"
	case actV2Adopt:
		return "adopt"
	case actV2RecoveryRequired:
		return "recovery_required"
	case actV2RestorePrior:
		return "restore_prior"
	case actV2Defer:
		return "defer"
	default:
		return "unknown"
	}
}

// mutatesDocker reports whether the action changes Docker state.
func (a reconcileActionV2) mutatesDocker() bool {
	return a == actV2Realign || a == actV2FinishRollback || a == actV2RetagFinishRollback || a == actV2RestorePrior
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

	// UpInterrupted: THIS agent start found that the previous agent process
	// died inside a `compose up` of this record's own operation (the command
	// intent of ADR-0062 slice 3, taken at startup and handed to the reconcile
	// once). Not a Docker fact. It only ever widens what may be done when no
	// proxy container is running, and never on its own: Docker's live state
	// must also match the record (stackDownV2). The command name can be the
	// earlier of two commands of the operation when the journal was unwritable
	// across both, so it is read as "a compose command of this operation".
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
	case in.Kind == ops.KindRestoreCommit:
		// An interrupted restore.commit: the same stages as a data rollback and
		// the same answer. The record says how far the restore got (interrupted
		// report); nothing here starts the stack it may have left down, because
		// nothing here can know what the data directory holds. Named separately
		// from unknown_kind_or_mode so that "a restore the agent knows and
		// deliberately leaves alone" is not reported as "a kind it does not
		// know". Decided before DockerReadable: Docker is never read for it.
		return rr("restore_window_manual")
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
		if in.RollbackArmed {
			return armedOnPriorV2(in)
		}
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

// decideByIdentityV2 picks the action from the (container, tag) identity pair
// once prior and target are known to be distinct images.
func decideByIdentityV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	p, t := ids.prior, ids.target
	switch {
	case p != "" && ids.run == p && ids.tag == t:
		// Crash between `docker tag` and `compose up` (A5), or `up` that did not
		// recreate (A8, F1). Retag only; AGT-002 precedent.
		return realignV2(in, ids)
	case ids.run == t && ids.tag == t && in.RollbackArmed:
		// The rollback was armed and the agent died before its `docker tag`
		// (T/T armed). Never adopted (N3); finished only from proof.
		return finishRollbackV2(in, ids, actV2RetagFinishRollback, "rollback_armed_tag_not_moved")
	case ids.run == t && ids.tag == t:
		return adoptV2(in, ids)
	case p != "" && ids.run == t && ids.tag == p:
		if !in.RollbackArmed {
			// Without the durable marker nothing proves the agent moved the
			// tag; it may have been an operator.
			return rr("tag_on_prior_rollback_unproven")
		}
		return finishRollbackV2(in, ids, actV2FinishRollback, "rollback_interrupted")
	}
	return rr("docker_state_unrecognised")
}

// stackDownV2 decides an upgrade in the danger window with no proxy container
// running. Until the owner decision of 2026-11-24 this was always
// recovery_required: safe, and an outage until an operator acted. The prior
// image is now restored when every one of these holds; each is a reason the
// agent may start a container on its own:
//
//   - UpInterrupted: the outage is attributable to a `compose up` of this
//     record's operation in which the previous agent process died. Without it
//     the stack may be down because an operator took it down.
//   - The upgrade had not reached verified (armed or not, as #2051 refuses an
//     armed record at verified). Restoring the prior would undo a good
//     upgrade; starting the target is never done here.
//   - The recorded prior is still local and identical (priorRestorable): the
//     image started is the one that was serving before the operation.
//   - The fixed tag is on the prior or on the target: anywhere else, something
//     other than this operation moved it.
//
// The kind and the phase are those of an upgrade (decideDangerPhaseV2 is only
// reached for one); a restore, a data rollback or a standalone rollback never
// gets here.
func stackDownV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	switch {
	case !in.UpInterrupted:
		return rr("stack_down")
	case in.Phase == journal.PhaseVerified:
		return rr("stack_down_after_verified")
	case !priorRestorable(in, ids):
		return rr("prior_not_restorable")
	case ids.tag != ids.prior && (ids.target == "" || ids.tag != ids.target):
		return rr("stack_down_tag_unrecognised")
	}
	return verdictRestorePrior
}

// verdictRestorePrior is what restore_prior decides, before and after its own
// retag (the tag on the prior is one of the two positions it accepts).
var verdictRestorePrior = reconcileVerdictV2{actV2RestorePrior, "stack_down_up_interrupted"}

func priorRestorable(in *reconcileInputsV2, ids v2ids) bool {
	return in.PriorRefPresent && ids.prior != "" && ids.priorLocal == ids.prior
}

func realignV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	if !priorRestorable(in, ids) {
		return rr("prior_not_restorable")
	}
	if in.RollbackArmed {
		// The armed rollback never restarted the prior: the retag alone is safe, but
		// the record is retired only on a fresh ReadyOK of the prior (reconcilePlan's
		// stepProbe), exactly like an armed record found on the prior.
		return verdictRealignArmed
	}
	return reconcileVerdictV2{actV2Realign, "tag_ahead_container_on_prior"}
}

// verdictRealignArmed: realign an armed record. Its plan ends with stepProbe.
var verdictRealignArmed = reconcileVerdictV2{actV2Realign, "armed_tag_ahead_container_on_prior"}

// verdictArmedPriorReady is what an armed record with container and tag on the
// prior image decides on a fresh ReadyOK: the only state stepProbe accepts.
var verdictArmedPriorReady = reconcileVerdictV2{actV2Noop, "armed_rollback_prior_ready"}

func adoptV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	switch {
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

// finishRollbackV2 finishes an armed inline rollback; the caller checked
// RollbackArmed and that the container runs the target. The agent writes the
// marker only after a post-restart failure, so at phase `verified` (gate and
// verify passed) it contradicts the journal and nothing is done.
func finishRollbackV2(in *reconcileInputsV2, ids v2ids, act reconcileActionV2, reason string) reconcileVerdictV2 {
	if in.Phase == journal.PhaseVerified {
		return rr("rollback_armed_at_verified")
	}
	if !priorRestorable(in, ids) {
		return rr("prior_not_restorable")
	}
	return reconcileVerdictV2{act, reason}
}

// armedOnPriorV2: container and tag are on the prior image and the record is
// armed, so a rollback `up` ran (the inline rollback's, or a reconcile finish
// killed after its `up`) and no gate result is durable. Nothing is changed
// either way; the record is retired only on a fresh ReadyOK.
func armedOnPriorV2(in *reconcileInputsV2) reconcileVerdictV2 {
	switch in.Probe {
	case probeReady:
		return verdictArmedPriorReady
	case probeNotReady:
		return rr("armed_rollback_prior_not_ready")
	default:
		return rr("readiness_not_probed")
	}
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

// reconcileNeedsProbe reports whether the fresh readiness probe can change the
// verdict (adopt, or retiring an armed rollback found on the prior image). The
// caller runs the probe only then, so a probe is never run for a record whose
// verdict it could not change.
func reconcileNeedsProbe(in reconcileInputsV2) bool {
	in.Probe = probeNotRun
	without := reconcileDecisionV2(in)
	in.Probe = probeReady
	return reconcileDecisionV2(in) != without
}

// reconcileStepOp is one step of an acting verdict.
type reconcileStepOp int

const (
	// stepTagPrior: `docker tag <the record's validated PriorRef>
	// culvert/proxy:pinned`. There is no other tag step: the reconcile never
	// names any other reference.
	stepTagPrior reconcileStepOp = iota
	// stepUp: `docker compose up -d`.
	stepUp
	// stepGate: a fresh health gate (ReadyOK) of what the `up` started.
	stepGate
	// stepProbe: changes nothing. A fresh read of Docker plus, where
	// reconcileNeedsProbe asks for it, a fresh readiness probe; the decision on
	// them must be exactly the step's expect (verdictArmedPriorReady: container
	// and tag on the recorded prior, which answers ready). The last step of an
	// armed realign, which restarts nothing and so has no gate.
	stepProbe
	// stepUpAgain: Compose, after a recreate interrupted between its stop and
	// its delete, answers the next `up` by only tidying up (exit 0, nothing
	// started; measured on real Docker, see upAgainIfNothingRuns). A fresh
	// read: if a proxy container is running, nothing. Otherwise the decision
	// on fresh facts must still be the step's expect, and `up` runs once more.
	stepUpAgain
)

func (o reconcileStepOp) String() string {
	switch o {
	case stepTagPrior:
		return "tag:prior"
	case stepUp:
		return "up"
	case stepGate:
		return "gate"
	case stepProbe:
		return "probe"
	case stepUpAgain:
		return "up_again"
	}
	return "unknown"
}

// mutates reports whether the step changes Docker.
// mutates reports whether act must recheck the decision on fresh facts before
// the step. stepUpAgain is not included: it may run `up`, but only after a
// fresh read shows nothing running, and then rechecks itself (upAgainStep);
// a generic recheck before it would stop a plan whose first `up` worked.
func (o reconcileStepOp) mutates() bool { return o == stepTagPrior || o == stepUp }

// mayMutate reports whether the step can change Docker at all. The plan
// properties count these, so a restore_prior plan's second `up` is counted.
func (o reconcileStepOp) mayMutate() bool { return o.mutates() || o == stepUpAgain }

// reconcileStep is one step of an acting verdict. Immediately before a step
// that changes Docker the caller re-reads Docker and requires the decision on
// the fresh facts (same record, same attempt count) to be exactly expect.
// Anything else, including a change this reconcile's own earlier steps do not
// explain, stops the reconcile with nothing further changed.
type reconcileStep struct {
	op     reconcileStepOp
	expect reconcileVerdictV2 // meaningful for a mutating step and for stepProbe
}

// verdictFinishRollback is what a T/P-armed record decides. It is the recheck
// in front of every `up`: it requires the tag on the validated prior image.
var verdictFinishRollback = reconcileVerdictV2{actV2FinishRollback, "rollback_interrupted"}

// reconcilePlan returns the ordered steps of an acting verdict, nil for a
// verdict that changes nothing. Pure. Every `up` is guarded by a recheck that
// decides verdictFinishRollback and is followed by the gate; an armed realign
// ends with stepProbe. The caller then verifies container and tag by image id.
// So no acting plan on an armed record retires it without a fresh ReadyOK.
func reconcilePlan(v reconcileVerdictV2) []reconcileStep {
	switch {
	case v == verdictRealignArmed:
		// After the retag the state is the armed P/P one: retired only as
		// armedOnPriorV2 retires it, on a fresh ReadyOK.
		return []reconcileStep{{stepTagPrior, v}, {stepProbe, verdictArmedPriorReady}}
	case v.Action == actV2Realign:
		return []reconcileStep{{stepTagPrior, v}}
	}
	switch v.Action {
	case actV2FinishRollback:
		return []reconcileStep{{stepUp, v}, {op: stepGate}}
	case actV2RetagFinishRollback:
		// After the retag, the only state this reconcile explains is T/P
		// armed, which decides exactly verdictFinishRollback.
		return []reconcileStep{{stepTagPrior, v}, {stepUp, verdictFinishRollback}, {op: stepGate}}
	case actV2RestorePrior:
		// After the retag: still no container, tag on the prior, which
		// decides restore_prior again. The same holds before the second `up`.
		return []reconcileStep{{stepTagPrior, v}, {stepUp, v}, {stepUpAgain, v}, {op: stepGate}}
	}
	return nil
}
