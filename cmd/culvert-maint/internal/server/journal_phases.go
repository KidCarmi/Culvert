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
//     errors so a flaky journal never fails an otherwise-good upgrade.
//   - The PhaseRestarting write-ahead barrier is FAIL-CLOSED
//     (advanceJournalPhase returns the error): it is fsync'd immediately
//     BEFORE the fixed-tag advance, so a crash in the danger window always
//     leaves a durable record. If it cannot be written, the op aborts BEFORE
//     crossing into the danger window — exactly the ENOSPC/IO condition the
//     journal exists to survive.
package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"culvert-maint/internal/journal"
)

// restartWithBarrier is the apply `restart` stage body: it writes the
// PhaseRestarting write-ahead barrier, then advances the fixed tag + restarts.
// Extracted from buildUpgradeApplyStages so that function stays under the
// cognitive-complexity budget, and so the barrier ordering lives next to the
// rest of the phase machinery.
//
// The barrier is FAIL-CLOSED: it is fsync'd immediately BEFORE the tag advance,
// so a crash in the danger window always leaves a durable record. If it cannot
// be written we refuse to advance the tag — aborting leaves the
// pulled-but-not-restarted stack on the OLD tag, the safe state (a crash between
// an un-recorded tag advance and a healthy restart would otherwise be
// unrecoverable: the reconciler would have no record to act on). PhaseRestarted
// is recorded best-effort AFTER a successful `up` (the mutation already
// happened, so a write failure there must not undo it).
func (s *Server) restartWithBarrier(acc *upgradeApplyAccumulator) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		if err := s.advanceJournalPhase(acc, journal.PhaseRestarting); err != nil {
			return nil, nil, fmt.Errorf("restart: write-ahead journal barrier failed, refusing to advance tag: %w", err)
		}
		out, errOut, uerr := s.tagAndUp(ctx, acc.pinnedRef, &acc.upgradeFailedPostRestart)
		if uerr == nil {
			s.advanceJournalPhaseBestEffort(acc, journal.PhaseRestarted)
		}
		return out, errOut, uerr
	}
}

// advanceJournalPhase updates the in-flight op's journal record to `phase`,
// folding in whatever target/prior identifiers acc knows by this point. It is a
// read-modify-write, so the immutable admission fields (kind, mode, actor,
// started_at) are preserved. A nil journal (non-journaled build / most tests)
// or an already-retired / absent record is a no-op returning nil.
//
// Returns an error only for the fail-closed caller (the write-ahead barrier);
// progress callers use advanceJournalPhaseBestEffort.
func (s *Server) advanceJournalPhase(acc *upgradeApplyAccumulator, phase journal.Phase) error {
	if s.opts.Journal == nil || acc.opID == "" {
		return nil
	}
	rec, found, err := s.opts.Journal.Read(acc.opID)
	if err != nil {
		return fmt.Errorf("journal read: %w", err)
	}
	if !found {
		return nil
	}
	rec.Phase = phase
	rec.UpdatedAt = time.Now().UTC()
	// Fold in identifiers known by this point. Record digests are bare hex
	// (the acc digests carry the sha256: prefix — bareDigests is a misnomer).
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
	return s.opts.Journal.Write(*rec)
}

// advanceJournalPhaseBestEffort advances the phase and swallows any error — a
// failed progress breadcrumb must never fail an otherwise-successful op. The
// write-ahead barrier is the only phase that must fail closed.
func (s *Server) advanceJournalPhaseBestEffort(acc *upgradeApplyAccumulator, phase journal.Phase) {
	_ = s.advanceJournalPhase(acc, phase)
}
