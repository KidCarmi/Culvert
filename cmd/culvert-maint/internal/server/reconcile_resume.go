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
// the record is at `restarted`, or still at `restarting` when the agent died
// after `compose up` returned and before it recorded the restart. Without this the record is reported
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
//   - an upgrade at `restarted` or `restarting`, with the image identified on
//     fresh facts (resumeIdentity): container, tag and the validated
//     TargetRef on one id whose RepoDigests list the pinned digest, the check
//     the restart itself makes before it records the id (F1). At `restarted`
//     the recorded id must be that id; at `restarting` none is recorded yet;
//   - if this start found the agent dead inside a `compose up` of this
//     operation (owner decision of 2026-11-26): only once Compose is shown to
//     have finished that recreate: the container runs (above) and `compose ps
//     -a` lists no never-started proxy container (UpEvidence absent). Left
//     behind, unreadable or not read: the restart is in doubt and nothing is
//     resumed. The settle window is over before any of this is read;
//   - no start but this one has seen the record since the gate began, and the
//     cap is not reached. With a checkpoint: an open gate:target on the same
//     id, epoch == interrupted_seen - 1 (the start counted before deciding),
//     attempts below the cap. With none (the gate never began):
//     interrupted_seen == 1.
//
// rollback_armed never gets here (decideByIdentityV2 decides it first).
func resumeGateV2(in *reconcileInputsV2, ids v2ids) (reconcileVerdictV2, bool) {
	if !in.ResumeEnabled || in.Kind != ops.KindUpgradeApply || in.Mode != "" || in.RollbackArmed ||
		(in.UpInterrupted && in.UpEvidence != upEvidenceAbsent) {
		return reconcileVerdictV2{}, false
	}
	id, ok := resumeIdentity(in, ids)
	if !ok {
		return reconcileVerdictV2{}, false
	}
	if in.ResumeAudited {
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
	case c.Step != journal.StepGateTarget, c.Result != "", normID(c.ImageID) != id,
		c.Epoch != in.Seen-1, c.Attempts < 1, c.Attempts >= resumeMaxGateRuns:
		return reconcileVerdictV2{}, false
	}
	return verdictResumeInterrupted, true
}

// resumeIdentity is the image a resumed gate may vouch for, from fresh facts:
// the container runs it, the fixed tag is on it, the validated TargetRef
// resolves to it locally, it is not the prior image, and its RepoDigests list
// the record's pinned digest. At `restarted` the restart recorded it (and only
// after that same digest check); at `restarting` the restart's write was lost,
// so nothing may be recorded yet. Any other phase: none.
func resumeIdentity(in *reconcileInputsV2, ids v2ids) (string, bool) {
	t := ids.target
	switch {
	case t == "" || ids.run != t || ids.tag != t || t == ids.prior || !in.ContainerRunning:
		return "", false
	case !digestListed(in.RunningDigests, in.TargetDigest):
		return "", false
	case in.Phase == journal.PhaseRestarted && ids.tid == t:
		return t, true
	case in.Phase == journal.PhaseRestarting && ids.tid == "":
		return t, true
	}
	return "", false
}

// resumeGate runs a resume_gate verdict. Nothing in Docker changes until the
// gate has failed:
//
//  1. the checkpoint is written ahead, FAIL-CLOSED: gate:target on the
//     resumeIdentity id, attempts raised, epoch = this start's
//     interrupted_seen. No durable attempt, no gate. The record's phase and
//     TargetImageID are not rewritten;
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
	id, _ := resumeIdentity(&c.in, idsOf(&c.in)) // decided resume_gate on these facts
	c.resumeID = id
	now := time.Now().UTC()
	c.rec.BeginCheckpoint(journal.StepGateTarget, "sha256:"+id, now)
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

// verifiedOnTarget re-reads Docker after a resumed gate passed: the same
// resumeIdentity holds on the fresh facts, on the id the gate ran on.
func (s *Server) verifiedOnTarget(ctx context.Context, c *reconcileCase) bool {
	after := c.in
	s.readReconcileFacts(ctx, c.rec, &after, false)
	c.out.RunningImage, c.out.PinnedTag = classOf(&after, after.RunningImageID), classOf(&after, after.TagImageID)
	id, ok := resumeIdentity(&after, idsOf(&after))
	return after.DockerReadable && ok && c.resumeID != "" && id == c.resumeID
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
