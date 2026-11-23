// Inline auto-rollback helpers for upgrades.apply (#375). The apply flow
// appends the SHARED image-rollback core (rollback_stages.go) as recovery
// stages; these helpers decide WHEN they fire, emit the
// upgrades.apply:rollback audit sub-action, and compute the structured
// result. The agent stays a low-level executor: the rollback target is the
// prior digest the agent itself captured — no release/channel awareness.
package server

import (
	"context"
	"fmt"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/ops"
)

// auditKindRollback is the audit sub-action for an inline rollback. It is
// part of the single upgrades.apply op (OpID = the apply op_id), not a
// second operation.
const auditKindRollback = "upgrades.apply:rollback"

// deriveRollbackTarget validates the captured prior image into a usable
// rollback target, applying the SAME strict gate as standalone rollback
// (repo@sha256:<digest> + image_allowlist). On any ambiguity it records a
// priorCaptureReason and leaves priorRef empty so rollback is skipped
// rather than guessing.
//
// candidates are the running image's RepoDigests (sorted, as captured). They
// all name the SAME image — the distinct-digest check above the gate guarantees
// it — so the target is the first one that passes the gate, not blindly the
// first one. The containerd image store lists a `culvert/proxy@sha256:…` entry
// for the image carrying the fixed local tag, and it sorts before the registry
// repo: taking element 0 unconditionally would fail the allowlist on that
// local-only entry and silently disable inline rollback on every such host.
func (s *Server) deriveRollbackTarget(acc *upgradeApplyAccumulator, candidates []string) {
	distinct := uniqueDigests(acc.priorDigests)
	switch {
	case len(distinct) == 0:
		acc.priorCaptureReason = "no_prior_digest"
	case len(distinct) > 1:
		acc.priorCaptureReason = "ambiguous_prior_digest"
	default:
		for _, ref := range candidates {
			if rollbackDigestRefRE.MatchString(ref) &&
				s.opts.Cfg.ImageAllowlist != nil && s.opts.Cfg.ImageAllowlist.MatchString(ref) {
				acc.priorRef = ref
				return
			}
		}
		acc.priorCaptureReason = "no_prior_digest"
	}
}

// rollbackDecision answers, for a rollback recovery stage, whether to
// attempt the rollback and (if not) the post-restart skip reason. A skip
// reason is returned ONLY for post-restart failures; success and
// pre-restart failures return ("", false) and are classified by the
// result computer.
func (acc *upgradeApplyAccumulator) rollbackDecision(rollbackOnFailure bool) (attempt bool, skipReason string) {
	if !acc.upgradeFailedPostRestart {
		return false, "" // success OR pre-restart failure — no rollback
	}
	if !rollbackOnFailure {
		return false, "disabled"
	}
	if acc.priorRef == "" {
		if acc.priorCaptureReason != "" {
			return false, acc.priorCaptureReason
		}
		return false, "no_prior_digest"
	}
	return true, ""
}

// inlineRollbackStages returns the SHARED image-rollback core decorated as
// recovery stages for apply: ContinueOnError so they run after the upgrade
// failed, PromoteReasonOnFailure so a failed rollback step promotes the op
// reason to rollback_failed, and each wrapped with the skip guard so they
// only DO work on a post-restart failure with a valid target and
// rollback_on_failure set (#375 §2/§8).
func (s *Server) inlineRollbackStages(acc *upgradeApplyAccumulator, racc *rollbackAccumulator, rollbackOnFailure bool) []ops.FlowStage {
	core := s.imageRollbackStages(func() string { return acc.priorRef }, racc)
	out := make([]ops.FlowStage, 0, len(core))
	for i := range core {
		step := core[i]
		inner := step.Run
		step.ContinueOnError = true
		step.PromoteReasonOnFailure = true // a failed rollback step → rollback_failed
		step.FailureReason = ops.ReasonRollbackFailed
		step.Run = s.guardInlineRollback(acc, racc, rollbackOnFailure, step.Name, inner)
		out = append(out, step)
	}
	return out
}

// guardInlineRollback wraps a shared rollback step so it only runs when a
// rollback should be attempted, short-circuits once a rollback step has
// failed, and emits the upgrades.apply:rollback audit lifecycle.
func (s *Server) guardInlineRollback(acc *upgradeApplyAccumulator, racc *rollbackAccumulator, rollbackOnFailure bool, name string, inner stageRun) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		attempt, skipReason := acc.rollbackDecision(rollbackOnFailure)
		if !attempt {
			if skipReason != "" {
				acc.rollbackSkipReason = skipReason
			}
			note := skipReason
			if note == "" {
				note = "no post-restart failure"
			}
			return []byte(name + ": skipped (" + note + ")"), nil, nil
		}
		if acc.rollbackFailed {
			return []byte(name + ": skipped (rollback already failed upstream)"), nil, nil
		}
		if !acc.rollbackAttempted {
			acc.rollbackAttempted = true
			s.emitRollbackAudit(acc, audit.OutcomeStarted, "")
		}
		if name == "rollback_restart" {
			// Durable evidence, written BEFORE the tag moves back, that the agent
			// decided the target failed (RollbackArmed). Fail-closed: without it a
			// crash inside the restart would leave a record a startup reconcile
			// cannot tell apart from an operator's retag.
			if aerr := s.armRollbackInJournal(acc); aerr != nil {
				acc.rollbackFailed = true
				s.emitRollbackAudit(acc, audit.OutcomeFailed, name)
				return []byte(name + ": journal write failed, refusing to move the tag"), nil,
					fmt.Errorf("rollback_restart: could not record the armed rollback in the journal, refusing to move the tag: %w", aerr)
			}
		}
		out, errout, err := inner(ctx)
		if err != nil {
			acc.rollbackFailed = true
			s.emitRollbackAudit(acc, audit.OutcomeFailed, name)
			return out, errout, err
		}
		switch name {
		case "rollback_restart":
			acc.rollbackRestarted = true
		case "rollback_verify":
			acc.rollbackSucceeded = true
			acc.runningAfterDigests = racc.runningAfterDigests
			s.emitRollbackAudit(acc, audit.OutcomeSucceeded, "")
		}
		return out, errout, err
	}
}

// emitRollbackAudit writes one upgrades.apply:rollback audit entry. The
// object is the apply op_id; the actor is the apply caller (inherited).
func (s *Server) emitRollbackAudit(acc *upgradeApplyAccumulator, outcome audit.Outcome, failedStage string) {
	ev := audit.Event{
		Actor:   acc.actor,
		OpID:    acc.opID,
		Kind:    auditKindRollback,
		Params:  map[string]interface{}{"target_digest": acc.rollbackTargetDigest(), "target_ref": acc.priorRef},
		Outcome: outcome,
	}
	if outcome == audit.OutcomeSucceeded || outcome == audit.OutcomeFailed {
		now := time.Now().UTC()
		ev.OutcomeAt = &now
	}
	if outcome == audit.OutcomeFailed {
		ev.FailureReason = string(ops.ReasonRollbackFailed)
		if failedStage != "" {
			ev.Params["failed_stage"] = failedStage
		}
	}
	_ = s.opts.Audit.Write(ev)
}

// rollbackTargetDigest is the bare sha256 of the rollback target, or ""
// when no valid prior target was captured.
func (acc *upgradeApplyAccumulator) rollbackTargetDigest() string {
	return digestRE.FindString(acc.priorRef)
}

// captureFinalEvidence makes the one bounded, read-only final capture of option C: only when
// the evidence is stale (a `compose up` ran after the last capture) or missing. It never
// mutates Docker. A failure leaves the evidence as it was, so the result reports unverified.
// It returns a note for the report line. Bounded by the report stage's context (stage
// timeout); after an operation timeout that context is already done, so the capture fails
// and the state is correctly unverified.
func (s *Server) captureFinalEvidence(ctx context.Context, acc *upgradeApplyAccumulator) string {
	if acc.evidence.current() {
		return ""
	}
	ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx)
	if err != nil {
		return " (final capture failed: " + errString(err) + ")"
	}
	acc.evidence.noteCapture(ri)
	return " (final capture)"
}

// resolvedSkipReason classifies why no rollback was attempted, for the
// result payload. Empty when rollback ran or was unnecessary.
func (acc *upgradeApplyAccumulator) resolvedSkipReason(upgradeOK bool) string {
	if acc.rollbackAttempted || upgradeOK {
		return ""
	}
	if acc.upgradeFailedPostRestart {
		if acc.rollbackSkipReason != "" {
			return acc.rollbackSkipReason
		}
		return "no_prior_digest"
	}
	return "pre_restart_failure"
}

// upgradeApplyResult is the structured result payload (#375 §5). Called by
// the orchestrator at terminal time with the final op state.
func (s *Server) upgradeApplyResult(acc *upgradeApplyAccumulator, state ops.State) map[string]interface{} {
	upgradeOK := state == ops.StateSucceeded
	fr := s.finalRunningFrom(&acc.evidence)
	return map[string]interface{}{
		"upgrade_succeeded":       upgradeOK,
		"rollback_attempted":      acc.rollbackAttempted,
		"rollback_succeeded":      acc.rollbackSucceeded,
		"rollback_skipped_reason": acc.resolvedSkipReason(upgradeOK),
		"upgrade_digest":          acc.pinnedDigest,
		"rollback_digest":         acc.rollbackTargetDigest(),
		// Evidence-based (running_evidence.go): verified only by a capture after the last
		// `compose up`; never inferred. final_running_digest stays a registry digest.
		"final_running_digest":   fr.digest,
		"final_running_state":    fr.state,
		"final_running_image_id": fr.imageID,
	}
}

// rollbackTargetNote summarises the capture_before rollback-target outcome
// for the op log.
func rollbackTargetNote(acc *upgradeApplyAccumulator) string {
	if acc.priorRef != "" {
		return "valid"
	}
	if acc.priorCaptureReason != "" {
		return acc.priorCaptureReason
	}
	return "none"
}

// uniqueDigests returns the distinct members of a bare-digest slice,
// preserving order.
func uniqueDigests(digests []string) []string {
	seen := make(map[string]struct{}, len(digests))
	out := make([]string, 0, len(digests))
	for _, d := range digests {
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		out = append(out, d)
	}
	return out
}

// orDash renders an empty report-line value as "-".
func orDash(v string) string {
	if v == "" {
		return "-"
	}
	return v
}
