package server

import (
	"context"
	"log"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// Forward resumption of an interrupted health gate (ADR-0062 slice 7; owner
// decision 4 and the owner decision of 2026-11-25 to cover a gate that never
// began).
//
// An upgrade's agent died while gating, or before gating, the target it had
// just started: container and tag are on the target, no rollback was armed,
// the record is at `restarted`. Without this the record is reported
// (recovery_required/target_live_ungated) and the ungated target keeps
// serving until an operator acts. With resume_interrupted_gate the converge
// reconcile runs that gate now, on fresh facts, and either adopts the target
// or hands the record to #2051's armed-rollback finish. It never replays the
// original `tag` or `up`.

// resumeMaxGateRuns caps the gate runs begun for one record: an interrupted
// original plus one resumption (a gate that never began gets two, as none had
// begun).
const resumeMaxGateRuns = 2

// ckFacts is the record's checkpoint as the decision sees it. The record is
// content from a file: the image id is shape-checked before it gets here.
type ckFacts struct {
	Present  bool
	Step     string
	Result   string
	Attempts int
	Epoch    int
	ImageID  string
}

func ckFactsOf(c *journal.Checkpoint) ckFacts {
	if c == nil {
		return ckFacts{}
	}
	return ckFacts{Present: true, Step: c.Step, Result: c.Result, Attempts: c.Attempts,
		Epoch: c.Epoch, ImageID: reportImageID(c.ImageID)}
}

// The resume verdicts.
var (
	verdictResumeInterrupted = reconcileVerdictV2{actV2ResumeGate, "target_gate_interrupted"}
	verdictResumeNotBegun    = reconcileVerdictV2{actV2ResumeGate, "target_gate_not_begun"}
	// verdictResumeRetire: a previous start resumed the gate, passed it, wrote
	// the succeeded `:resumed` entry and was killed before removing the record.
	// Only the removal is left; no gate is run again and no attempt is spent.
	verdictResumeRetire = reconcileVerdictV2{actV2ResumeGate, "resumed_not_retired"}
)

// resumeGateV2 decides whether an ungated live target (container and tag on
// the target, not armed, below verified) may have its gate resumed. ok=false
// means "no": the caller reports target_live_ungated exactly as before. Every
// condition is a reason the agent may vouch for an image it has not gated:
//
//   - the owner switched it on (resume_interrupted_gate, converge only);
//   - an upgrade at `restarted`: the restart recorded the target's id, and
//     did so only after checking the captured image carries the pinned digest
//     (restartWithBarrier, F1). At `restarting` that write was lost: the
//     identity is unknown and nothing is resumed;
//   - container and tag are both, freshly read, on that id, which is also the
//     id the validated TargetRef resolves to locally;
//   - this start did not find the agent dead inside a `compose up` of this
//     operation: the restart itself is then in doubt (slice 4's ground);
//   - no start but this one has seen the record since the gate began, and the
//     cap is not reached. With a checkpoint: an open gate:target on the same
//     id, epoch == interrupted_seen - 1 (the start counted before deciding),
//     attempts below the cap. With none (the gate never began):
//     interrupted_seen == 1.
//
// rollback_armed never gets here (decideByIdentityV2 decides it first).
func resumeGateV2(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
	switch {
	case !in.ResumeEnabled, in.Kind != ops.KindUpgradeApply, in.Mode != "",
		in.Phase != journal.PhaseRestarted, in.UpInterrupted, in.RollbackArmed:
		return reconcileVerdictV2{}, false
	case ids.tid == "" || ids.tid != ids.target || ids.run != ids.tid || ids.tag != ids.tid || !in.ContainerRunning:
		return reconcileVerdictV2{}, false
	case in.ResumeAudited:
		return verdictResumeRetire, true
	}
	c := in.Ck
	if !c.Present {
		if in.Seen != 1 {
			return reconcileVerdictV2{}, false
		}
		return verdictResumeNotBegun, true
	}
	switch {
	case c.Step != journal.StepGateTarget, c.Result != "", normID(c.ImageID) != ids.tid,
		c.Epoch != in.Seen-1, c.Attempts < 1, c.Attempts >= resumeMaxGateRuns:
		return reconcileVerdictV2{}, false
	}
	return verdictResumeInterrupted, true
}

// resumeGate runs a resume_gate verdict. Nothing in Docker changes until the
// gate has failed:
//
//  1. the checkpoint is written ahead, FAIL-CLOSED: gate:target on the
//     target id, attempts raised, epoch = this start's interrupted_seen. No
//     durable attempt, no gate;
//  2. a fresh read that must still decide resume_gate, then a fresh
//     production gate;
//  3. a fresh read again, then container and tag by image id and the running
//     digest against the record's target digest;
//  4. passed: retire with one `upgrades.apply:resumed` entry, through the
//     usual settle-and-ready check. The original operation stays
//     failed(agent_restart_interrupted).
//
// A failed gate or verify goes to resumeFailed.
func (s *Server) resumeGate(ctx context.Context, c *reconcileCase, v reconcileVerdictV2) ReconcileRecord {
	c.auditSuffix = ":resumed"
	if v == verdictResumeRetire {
		c.out.DockerReconciled = true
		return s.retireIfServing(ctx, c)
	}
	now := time.Now().UTC()
	c.rec.BeginCheckpoint(journal.StepGateTarget, c.in.TargetImageID, now)
	c.rec.LastReconcileAt = &now
	c.rec.ReconcileDecision = v.Action.String() + "/" + v.Reason
	if err := s.opts.Journal.Write(*c.rec); err != nil {
		c.out.Reason = "resume_checkpoint_unwritable"
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	c.out.Actions = append(c.out.Actions, "gate")
	if !s.stillDecides(ctx, c, v) {
		c.out.Reason = "docker_changed_before_gate"
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	if s.probeReadiness(ctx) != probeReady {
		return s.resumeFailed(ctx, c, "unhealthy")
	}
	if !s.stillDecides(ctx, c, v) {
		c.out.Reason = "docker_changed_before_verify"
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	if !s.verifiedOnTarget(ctx, c) {
		return s.resumeFailed(ctx, c, "verify")
	}
	c.out.DockerReconciled = true
	return s.retireIfServing(ctx, c)
}

// verifiedOnTarget re-reads Docker after a resumed gate passed: container and
// fixed tag on the recorded target id, which the validated TargetRef still
// resolves to, and the running image carries the record's target digest.
func (s *Server) verifiedOnTarget(ctx context.Context, c *reconcileCase) bool {
	after := c.in
	s.readReconcileFacts(ctx, c.rec, &after, false)
	t := normID(after.TargetImageID)
	c.out.RunningImage, c.out.PinnedTag = classOf(&after, after.RunningImageID), classOf(&after, after.TagImageID)
	return after.DockerReadable && after.ContainerRunning && t != "" &&
		normID(after.RunningImageID) == t && normID(after.TagImageID) == t && normID(after.TargetLocalID) == t &&
		digestListed(after.RunningDigests, after.TargetDigest)
}

// resumeFailed: the resumed gate (or its verify) failed. The result and
// rollback_armed are written FAIL-CLOSED, then the record is decided again in
// this start: converge runs only at startup, so leaving the rollback for the
// next start would leave a target that failed its gate serving until some
// later restart. The new decision is #2051's T/T-armed finish, run by act on
// the same executor within the persisted attempt cap. If the writes fail the
// record keeps its open checkpoint with an attempt spent and is reported.
func (s *Server) resumeFailed(ctx context.Context, c *reconcileCase, detail string) ReconcileRecord {
	now := time.Now().UTC()
	c.rec.EndCheckpoint(journal.StepGateTarget, journal.CheckpointFailedPrefix+detail, now)
	c.rec.RollbackArmed = true
	if err := s.opts.Journal.Write(*c.rec); err != nil {
		c.out.Reason = "resume_failed_unarmed"
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	c.out.Reason = "resumed_gate_failed_" + detail
	if err := s.auditReconciled(c, audit.OutcomeFailed); err != nil {
		// Best effort: the rollback must not wait on the audit log.
		log.Printf("culvert-maint: WARN: op %s: could not audit the failed resumed gate: %v", c.rec.OpID, err)
	}
	c.auditSuffix = ""
	c.in.RollbackArmed = true
	c.in.Ck = ckFactsOf(c.rec.Checkpoint)
	s.readReconcileFacts(ctx, c.rec, &c.in, true)
	next := reconcileDecisionV2(c.in)
	c.out.Decision, c.out.Reason = next.Action.String(), next.Reason
	if !next.Action.mutatesDocker() {
		return s.keepRecord(c, OutcomeRecoveryRequired)
	}
	return s.act(ctx, c, next)
}
