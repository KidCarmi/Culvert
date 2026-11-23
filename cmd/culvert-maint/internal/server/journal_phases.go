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

// armRollbackInJournal records, FAIL-CLOSED, that inline rollback is about to
// move the fixed tag back to the prior image (journal.Record.RollbackArmed).
// It changes nothing else in the record: the phase stays where the forward flow
// left it (rollback stages write no phase), and no identifier is folded in. A
// missing record is re-established like the write-ahead barrier does, so a crash
// in the rollback restart still leaves a reconcilable record. A nil journal or
// an empty op id is a no-op (non-journaled build).
func (s *Server) armRollbackInJournal(acc *upgradeApplyAccumulator) error {
	if s.opts.Journal == nil || acc.opID == "" {
		return nil
	}
	rec, found, err := s.opts.Journal.Read(acc.opID)
	if err != nil {
		return fmt.Errorf("journal read: %w", err)
	}
	now := time.Now().UTC()
	if !found {
		rec = &journal.Record{
			OpID: acc.opID, Kind: ops.KindUpgradeApply, Phase: journal.PhaseRestarting,
			Actor: acc.actor, StartedAt: now,
		}
		foldIdentifiers(rec, acc)
	}
	rec.RollbackArmed = true
	rec.UpdatedAt = now
	return s.opts.Journal.Write(*rec)
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
		out, errOut, uerr := s.tagAndUp(ctx, acc.pinnedRef, &acc.upgradeFailedPostRestart, &acc.evidence)
		if uerr == nil {
			// Capture the target's config digest NOW (best-effort) — the container
			// is running the target after `up`. Without this, a crash between here
			// and the verify stage would leave PhaseRestarted with an empty
			// TargetImageID, forcing reconcile onto the false-rollback-prone
			// manifest comparison for exactly the multi-arch case the config digest
			// protects (Codex P1). verifyRunningImage re-captures + hard-verifies.
			//
			// F1 (ADR-0061): `up` exiting 0 does not prove the proxy was recreated
			// on the target (a compose override can pin another image). The id is
			// recorded as the TARGET's only when the captured RepoDigests contain
			// the pinned digest (the check verifyRunningImage makes), so the
			// journal can never name the prior image as the target.
			if ri, cerr := s.opts.Runner.CaptureRunningProxyImage(ctx); cerr == nil {
				acc.evidence.noteCapture(ri)
				if acc.pinnedDigest != "" && containsString(bareDigests(ri.RepoDigests), acc.pinnedDigest) {
					acc.runningAfterID = ri.RunningImageID
				}
			}
			s.advanceJournalPhaseBestEffort(acc, journal.PhaseRestarted)
		} else if acc.upgradeFailedPostRestart {
			// The tag advanced and `up` failed (a tag failure never sets the
			// flag). Do not leave the tag ahead of a container that never moved.
			out = append(out, s.realignPinnedTagAfterFailedUp(ctx, acc)...)
		}
		return out, errOut, uerr
	}
}

// realignPinnedTagAfterFailedUp undoes the fixed-tag advance when the apply
// `restart` stage's `docker compose up -d` failed WITHOUT recreating the proxy
// container. It returns an op-log note (never an error: the stage is already
// failing with the `up` error, and that is the error the operator must see).
//
// Why: `up` can fail before it touches the proxy — the compose/override file no
// longer loads, another service's image cannot be pulled, the daemon or the
// sudo boundary refuses the call. The old container then keeps running while
// culvert/proxy:pinned already names the new image. Inline rollback would move
// the tag back, but it does not always run (rollback_on_failure=false, no
// usable prior target) and can fail before its own retag (rollback pull). The
// op then went terminal — journal record retired — with the tag ahead: the
// `cli` backup/restore service and the next `docker compose up -d` (any later
// restore, rollback, or operator command) would resolve an image that was never
// health-gated. Restoring the tag here returns Docker to the exact pre-restart
// state on every one of those paths.
//
// It acts ONLY on proof, never on a guess:
//   - the post-failure capture must succeed and report the SAME image config
//     digest that capture_before recorded. No running proxy, or a different
//     image, means `up` got as far as replacing the container: the tag then
//     already matches the container and is left alone. No capture_before image
//     (stack was down) means there is nothing known to restore to;
//   - the prior image must have a ref that passed the rollback gate (priorRef).
//     That ref is the only way to name the prior image at the sudo boundary
//     (`tag` accepts `<proxy_repo>@sha256:<digest>` only). The image is local —
//     a container is running it — so no pull is needed. Without such a ref the
//     tag stays on the target and the note says so.
//
// Crash consistency: this runs inside the PhaseRestarting write-ahead window
// (the record is retired only at terminal). An agent death before the restore
// leaves record + tag-on-target + container-on-prior, after it record +
// tag-on-prior + container-on-prior; reconcileDecision already distinguishes
// the two (tag_advanced_container_stale vs already_on_prior). No new phase.
//
// upgradeFailedPostRestart is deliberately left set: whether inline rollback
// fires for a failed `up` is unchanged.
func (s *Server) realignPinnedTagAfterFailedUp(ctx context.Context, acc *upgradeApplyAccumulator) []byte {
	ri, cerr := s.opts.Runner.CaptureRunningProxyImage(ctx)
	if cerr == nil {
		acc.evidence.noteCapture(ri)
	}
	if cerr != nil {
		return []byte("\nrestart: `up` failed and no running proxy could be captured afterwards — container state is indeterminate; culvert/proxy:pinned left at the target")
	}
	if acc.priorImageID == "" {
		return []byte("\nrestart: `up` failed; no running proxy was captured before the upgrade, so there is no prior image to restore; culvert/proxy:pinned left at the target")
	}
	if ri.RunningImageID != acc.priorImageID {
		return []byte("\nrestart: `up` failed after the proxy container was replaced (running image differs from the one captured before); culvert/proxy:pinned left at the target")
	}
	acc.restartLeftPrior = true
	if acc.priorRef == "" {
		return []byte("\nrestart: WARNING `up` failed before recreating the proxy (it still runs the prior image " + acc.priorImageID +
			") but the prior image has no restorable reference (" + rollbackTargetNote(acc) +
			"); culvert/proxy:pinned LEFT at the target — the next `docker compose up -d` or cli run will use the new image")
	}
	if _, terr := s.opts.Runner.ComposeTagPinned(ctx, acc.priorRef); terr != nil {
		return []byte("\nrestart: WARNING `up` failed before recreating the proxy (it still runs the prior image " + acc.priorImageID +
			") and restoring the tag failed (" + errString(terr) +
			"); culvert/proxy:pinned LEFT at the target — the next `docker compose up -d` or cli run will use the new image")
	}
	return []byte("\nrestart: `up` failed before recreating the proxy (it still runs the prior image " + acc.priorImageID +
		"); culvert/proxy:pinned restored to prior " + acc.priorRef)
}
