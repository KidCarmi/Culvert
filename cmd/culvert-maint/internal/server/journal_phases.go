// Crash-recovery journal phase advancement (RISK-022, Tier 1 + PR-E P0-F).
// The admission write (handlers_d16b.go) records PhaseAdmitted; this file
// advances the record through an op's lifecycle so the on-disk record reflects
// HOW FAR the op got — which the startup reconciler (reconcile_startup.go)
// needs to choose between a no-op, an adopt, and a surfaced recovery.
//
// The generic core (advanceJournalPhaseFor / writeBarrierFor) is keyed on an
// op_id + a journalFold that copies whatever identifiers the flow knows into
// the record. It is shared by the upgrade-apply flow (fold = foldIdentifiers
// over the apply accumulator) AND the shared image-rollback core (P0-F: a
// standalone or inline rollback moves the pinned tag too, so it carries the
// same write-ahead barrier — otherwise a crash during a rollback's tag advance
// left the record at a "safe boundary" while the tag had actually moved).
//
// Two disciplines:
//   - Progress phases (captured/resolved/pulled/restarted/verified) are
//     BEST-EFFORT breadcrumbs: advanceJournalPhaseBestEffort swallows write
//     errors AND a missing record so a flaky journal never fails an
//     otherwise-good op.
//   - The PhaseRestarting write-ahead barrier (writeBarrier) is FAIL-CLOSED:
//     it is fsync'd immediately BEFORE the fixed-tag advance, so a crash in the
//     danger window always leaves a durable record. It fails closed on a read /
//     write error AND on a MISSING record (which it re-establishes) — a barrier
//     that silently proceeds without a durable record would reopen exactly the
//     RISK-022 window it exists to close.
package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// journalFold copies a flow's known identifiers (target/prior refs, digests,
// image ids, mode) into rec. It must be idempotent and must never clear a
// field it does not know (a later phase may know less than an earlier one).
type journalFold func(rec *journal.Record)

// foldIdentifiers copies the target / prior identifiers acc knows by this point
// into rec. Record digests are bare hex — the acc digests carry the sha256:
// prefix (bareDigests is a misnomer that keeps the prefix).
func foldIdentifiers(rec *journal.Record, acc *upgradeApplyAccumulator) {
	if acc.pinnedRef != "" {
		rec.TargetRef = acc.pinnedRef
		rec.TargetDigest = strings.TrimPrefix(acc.pinnedDigest, "sha256:")
	}
	if acc.priorRef != "" {
		rec.PriorRef = acc.priorRef
		if len(acc.priorDigests) > 0 {
			rec.PriorDigest = strings.TrimPrefix(acc.priorDigests[0], "sha256:")
		}
	}
	// Class-invariant image config digests (design §0 P0-A/B). Captured
	// incrementally: priorImageID at capture_before, the target's config digest
	// (runningAfterID) only after the post-restart verify. Stored in the `sha256:`
	// form docker reports so it compares directly to a live capture.
	if acc.priorImageID != "" {
		rec.PriorImageID = acc.priorImageID
	}
	if acc.runningAfterID != "" {
		rec.TargetImageID = acc.runningAfterID
	}
}

// applyFold adapts the apply accumulator to the generic fold.
func applyFold(acc *upgradeApplyAccumulator) journalFold {
	return func(rec *journal.Record) { foldIdentifiers(rec, acc) }
}

// advanceJournalPhaseFor read-modify-writes opID's record to `phase`, folding
// in whatever identifiers the flow knows. It is a read-modify-write so the
// immutable admission fields (kind, mode, actor, started_at) are preserved.
//
// Returns found=false (nil error) when the record is ABSENT — the caller decides
// whether that is benign (progress) or must fail closed (the barrier). A nil
// journal / empty opID is likewise (false, nil): a non-journaled build has no
// record to advance.
func (s *Server) advanceJournalPhaseFor(opID string, fold journalFold, phase journal.Phase) (found bool, err error) {
	if s.opts.Journal == nil || opID == "" {
		return false, nil
	}
	rec, found, err := s.opts.Journal.Read(opID)
	if err != nil {
		return false, fmt.Errorf("journal read: %w", err)
	}
	if !found {
		return false, nil
	}
	rec.Phase = phase
	rec.UpdatedAt = time.Now().UTC()
	if fold != nil {
		fold(rec)
	}
	if werr := s.opts.Journal.Write(*rec); werr != nil {
		return true, werr
	}
	return true, nil
}

// writeBarrierFor writes the PhaseRestarting write-ahead barrier FAIL-CLOSED.
// It updates the existing record when present (preserving admission fields)
// and RE-CREATES it when absent: a missing record right before the danger
// window must NOT silently proceed (a crash after the tag advance would then
// leave nothing for the reconciler). Any read / write error — or a failed
// re-create — is returned so the restart stage aborts BEFORE advancing the
// tag. A nil journal / empty opID is a no-op by design (non-journaled build).
func (s *Server) writeBarrierFor(opID, kind, actor string, fold journalFold) error {
	if s.opts.Journal == nil || opID == "" {
		return nil
	}
	found, err := s.advanceJournalPhaseFor(opID, fold, journal.PhaseRestarting)
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	// The durable admission record vanished before the barrier — re-establish it
	// so a crash after the imminent tag advance is still reconcilable. StartedAt
	// is approximate (the original is lost); the reconciler keys on phase +
	// digests, not on StartedAt.
	now := time.Now().UTC()
	rec := journal.Record{
		OpID: opID, Kind: kind, Phase: journal.PhaseRestarting,
		Actor: actor, StartedAt: now, UpdatedAt: now,
	}
	if fold != nil {
		fold(&rec)
	}
	return s.opts.Journal.Write(rec)
}

// advanceJournalPhase is the apply-flow form of advanceJournalPhaseFor.
func (s *Server) advanceJournalPhase(acc *upgradeApplyAccumulator, phase journal.Phase) (found bool, err error) {
	return s.advanceJournalPhaseFor(acc.opID, applyFold(acc), phase)
}

// advanceJournalPhaseBestEffort advances the phase and swallows any error or
// missing record — a failed progress breadcrumb must never fail an
// otherwise-successful op. The write-ahead barrier is the only phase that must
// fail closed.
func (s *Server) advanceJournalPhaseBestEffort(acc *upgradeApplyAccumulator, phase journal.Phase) {
	_, _ = s.advanceJournalPhase(acc, phase)
}

// writeBarrier is the apply-flow form of writeBarrierFor.
func (s *Server) writeBarrier(acc *upgradeApplyAccumulator) error {
	return s.writeBarrierFor(acc.opID, ops.KindUpgradeApply, acc.actor, applyFold(acc))
}

// restartWithBarrier is the apply `restart` stage body: it writes the
// PhaseRestarting write-ahead barrier, then advances the fixed tag + restarts.
// Extracted from buildUpgradeApplyStages so that function stays under the
// cognitive-complexity budget, and so the barrier ordering lives next to the
// rest of the phase machinery.
//
// If the barrier cannot be written we refuse to advance the tag — aborting
// leaves the pulled-but-not-restarted stack on the OLD tag, the safe state.
// PhaseRestarted is recorded best-effort AFTER a successful `up` (the mutation
// already happened, so a write failure there must not undo it).
func (s *Server) restartWithBarrier(acc *upgradeApplyAccumulator) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		if err := s.writeBarrier(acc); err != nil {
			return nil, nil, fmt.Errorf("restart: write-ahead journal barrier failed, refusing to advance tag: %w", err)
		}
		out, errOut, uerr := s.tagAndUp(ctx, acc.pinnedRef, &acc.upgradeFailedPostRestart)
		if uerr == nil {
			// Capture the target's config digest NOW (best-effort) — the container
			// is running the target after `up`. Without this, a crash between here
			// and the verify stage would leave PhaseRestarted with an empty
			// TargetImageID, forcing reconcile onto the false-rollback-prone
			// manifest comparison for exactly the multi-arch case the config digest
			// protects (Codex P1). verifyRunningImage re-captures + hard-verifies.
			if ri, cerr := s.opts.Runner.CaptureRunningProxyImage(ctx); cerr == nil {
				acc.runningAfterID = ri.RunningImageID
			}
			s.advanceJournalPhaseBestEffort(acc, journal.PhaseRestarted)
		}
		return out, errOut, uerr
	}
}
