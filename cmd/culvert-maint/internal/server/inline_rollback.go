// Inline auto-rollback helpers for upgrades.apply (#375). The apply flow
// appends the SHARED image-rollback core (rollback_stages.go) as recovery
// stages; these helpers decide WHEN they fire, emit the
// upgrades.apply:rollback audit sub-action, and compute the structured
// result. The agent stays a low-level executor: the rollback target is the
// prior digest the agent itself captured — no release/channel awareness.
package server

import (
	"context"
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
func (s *Server) deriveRollbackTarget(acc *upgradeApplyAccumulator, priorRef string) {
	distinct := uniqueDigests(acc.priorDigests)
	switch {
	case len(distinct) == 0:
		acc.priorCaptureReason = "no_prior_digest"
	case len(distinct) > 1:
		acc.priorCaptureReason = "ambiguous_prior_digest"
	default:
		if rollbackDigestRefRE.MatchString(priorRef) &&
			s.opts.Cfg.ImageAllowlist != nil && s.opts.Cfg.ImageAllowlist.MatchString(priorRef) {
			acc.priorRef = priorRef
		} else {
			acc.priorCaptureReason = "no_prior_digest"
		}
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

// finalRunningDigests is the best-effort set of digests actually running
// at op end (used for final_running_digest + the report summary).
func (acc *upgradeApplyAccumulator) finalRunningDigests(racc *rollbackAccumulator) []string {
	switch {
	case acc.rollbackSucceeded:
		return racc.runningAfterDigests // prior image now running (verified)
	case acc.rollbackRestarted:
		// Restarted to prior, but health/verify failed → prior image runs.
		if d := acc.rollbackTargetDigest(); d != "" {
			return []string{d}
		}
		return racc.runningAfterDigests
	case acc.rollbackAttempted:
		// Rollback pull failed before any restart → the unhealthy NEW
		// image is still running.
		if acc.pinnedDigest != "" {
			return []string{acc.pinnedDigest}
		}
	case acc.upgradeFailedPostRestart:
		// Post-restart failure, rollback skipped → unhealthy new image runs.
		if acc.pinnedDigest != "" {
			return []string{acc.pinnedDigest}
		}
	}
	if len(acc.runningAfterDigests) > 0 {
		return acc.runningAfterDigests // upgrade verify succeeded
	}
	return acc.priorDigests
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
func (s *Server) upgradeApplyResult(acc *upgradeApplyAccumulator, racc *rollbackAccumulator, state ops.State) map[string]interface{} {
	upgradeOK := state == ops.StateSucceeded
	return map[string]interface{}{
		"upgrade_succeeded":       upgradeOK,
		"rollback_attempted":      acc.rollbackAttempted,
		"rollback_succeeded":      acc.rollbackSucceeded,
		"rollback_skipped_reason": acc.resolvedSkipReason(upgradeOK),
		"upgrade_digest":          acc.pinnedDigest,
		"rollback_digest":         acc.rollbackTargetDigest(),
		"final_running_digest":    firstOrEmpty(acc.finalRunningDigests(racc)),
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

// firstOrEmpty returns the first element or "".
func firstOrEmpty(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	return ss[0]
}
