// Crash-recovery journal phase advancement for the upgrade-apply flow
// (RISK-022, Tier 1). The admission write (handlers_d16b.go) records
// PhaseAdmitted; this file advances the record through the apply lifecycle so
// the on-disk record reflects HOW FAR the op got — which the startup
// reconciler (a later, sign-off-gated slice) needs to choose between a no-op,
// a resume, and a fail-safe rollback.
//
// Two disciplines:
//   - Progress phases (captured/resolved/pulled/restarted/verified) are
//     BEST-EFFORT breadcrumbs: advanceJournalPhaseBestEffort swallows write
//     errors AND a missing record so a flaky journal never fails an
//     otherwise-good upgrade.
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
}

// advanceJournalPhase read-modify-writes the in-flight op's record to `phase`,
// folding in whatever identifiers acc knows. It is a read-modify-write so the
// immutable admission fields (kind, mode, actor, started_at) are preserved.
//
// Returns found=false (nil error) when the record is ABSENT — the caller decides
// whether that is benign (progress) or must fail closed (the barrier). A nil
// journal / empty opID is likewise (false, nil): a non-journaled build has no
// record to advance.
func (s *Server) advanceJournalPhase(acc *upgradeApplyAccumulator, phase journal.Phase) (found bool, err error) {
	if s.opts.Journal == nil || acc.opID == "" {
		return false, nil
	}
	rec, found, err := s.opts.Journal.Read(acc.opID)
	if err != nil {
		return false, fmt.Errorf("journal read: %w", err)
	}
	if !found {
		return false, nil
	}
	rec.Phase = phase
	rec.UpdatedAt = time.Now().UTC()
	foldIdentifiers(rec, acc)
	if werr := s.opts.Journal.Write(*rec); werr != nil {
		return true, werr
	}
	return true, nil
}

// advanceJournalPhaseBestEffort advances the phase and swallows any error or
// missing record — a failed progress breadcrumb must never fail an
// otherwise-successful op. The write-ahead barrier is the only phase that must
// fail closed.
func (s *Server) advanceJournalPhaseBestEffort(acc *upgradeApplyAccumulator, phase journal.Phase) {
	_, _ = s.advanceJournalPhase(acc, phase)
}

// writeBarrier writes the PhaseRestarting write-ahead barrier FAIL-CLOSED. It
// updates the existing record when present (preserving admission fields) and
// RE-CREATES it when absent: a missing record right before the danger window
// must NOT silently proceed (a crash after the tag advance would then leave
// nothing for the reconciler). Any read / write error — or a failed re-create —
// is returned so the restart stage aborts BEFORE advancing the tag. A nil
// journal / empty opID is a no-op by design (non-journaled build).
func (s *Server) writeBarrier(acc *upgradeApplyAccumulator) error {
	if s.opts.Journal == nil || acc.opID == "" {
		return nil
	}
	found, err := s.advanceJournalPhase(acc, journal.PhaseRestarting)
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
		OpID: acc.opID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting,
		Actor: acc.actor, StartedAt: now, UpdatedAt: now,
	}
	foldIdentifiers(&rec, acc)
	return s.opts.Journal.Write(rec)
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
			s.advanceJournalPhaseBestEffort(acc, journal.PhaseRestarted)
		}
		return out, errOut, uerr
	}
}
