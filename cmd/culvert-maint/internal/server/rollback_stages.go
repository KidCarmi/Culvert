// Shared image-rollback stages — the single source of truth for the
// pull → restart → health → verify sequence used by BOTH the standalone
// rollback handler (POST /v1/rollbacks, mode=image), apply's inline
// auto-rollback (#375 §8), and the explicit reconcile resolver
// (handlers_reconcile.go). Keeping one builder is the anti-drift
// guarantee: manual, automatic and reconcile-issued rollback cannot diverge.
//
// Two RISK-022 PR-E properties live HERE so every caller inherits them:
//
//   - Local-first (design §4, the no-offline floor): rollback_pull skips the
//     registry when the exact pinned digest is already in the local image
//     store (content-addressed, so the skip cannot change what tag+up resolve).
//     A rollback therefore survives the registry/network outage that most
//     often caused the failure it is recovering from.
//   - Journal phases (design §0 P0-F): the shared core advances the op's
//     journal record — pulled after the pull, the FAIL-CLOSED PhaseRestarting
//     barrier immediately before the tag advance, restarted after `up`,
//     verified after the post-rollback verify — so an interruption during a
//     rollback is classifiable at the next boot exactly like one during apply.
//
// The four core stages are pinned to a target read at RUN time via
// targetRefFn — the standalone handler supplies a constant
// (repo@sha256:<digest> from the request); apply's inline path supplies
// a closure over the prior digest captured at capture_before (which is
// only known once the op is running). Callers decorate the returned
// stages as needed (the inline path renames-by-note, sets ContinueOnError
// + PromoteReasonOnFailure, and wraps each with its skip guard).
package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// rollbackAccumulator carries parsed digests + the health summary across
// the shared rollback stages. Parsed identifiers only — never raw inspect
// JSON. priorDigests is used by the standalone handler's capture_before +
// report; targetDigest / runningAfterDigests are set by the core stages.
//
// The journal fields bind the core to the op's crash-recovery record: opID
// (set by the admission hook), kind + actor (for a barrier re-create), and
// fold (what identifiers to write). A standalone rollback uses
// standaloneFold; the inline path overrides fold with the apply
// accumulator's foldIdentifiers because the record it advances is the
// APPLY op's (target = new image, prior = old) and that identity must not
// change just because the tag is now moving back.
type rollbackAccumulator struct {
	priorRef            string // repo@sha256:<digest> of what ran before (standalone only)
	priorImageID        string // config digest of what ran before (standalone only)
	priorDigests        []string
	targetDigest        string
	targetImageID       string // config digest captured after rollback_restart's `up`
	runningAfterDigests []string
	healthSummary       string
	pullSkippedLocal    bool // rollback_pull found the target locally and skipped the registry
	// preserved (inline rollback only) is the upgrade's pre-restart
	// baseline. Checked REPORT-ONLY: a rollback restores service and must
	// not be failed by a row the operator still needs to look at.
	preserved []string

	opID  string
	kind  string
	actor string
	mode  string
	fold  journalFold
}

// standaloneFold is the journal fold for a rollbacks.create (mode=image)
// record: target = the rollback target, prior = what was running before.
func (acc *rollbackAccumulator) standaloneFold(targetRef string) journalFold {
	return func(rec *journal.Record) {
		if acc.mode != "" {
			rec.Mode = acc.mode
		}
		if targetRef != "" {
			rec.TargetRef = targetRef
			rec.TargetDigest = strings.TrimPrefix(digestRE.FindString(targetRef), "sha256:")
		}
		if acc.priorRef != "" {
			rec.PriorRef = acc.priorRef
			rec.PriorDigest = strings.TrimPrefix(digestRE.FindString(acc.priorRef), "sha256:")
		}
		if acc.priorImageID != "" {
			rec.PriorImageID = acc.priorImageID
		}
		if acc.targetImageID != "" {
			rec.TargetImageID = acc.targetImageID
		}
	}
}

// advancePhase is the best-effort progress breadcrumb for the rollback core.
func (s *Server) rollbackAdvancePhase(acc *rollbackAccumulator, phase journal.Phase) {
	_, _ = s.advanceJournalPhaseFor(acc.opID, acc.fold, phase)
}

// tagAndUp runs the P1.4 retag-then-restart pair: `docker tag <ref>
// culvert/proxy:pinned`, then `docker compose up -d`. Keeping the retag
// ADJACENT to `up` (one stage) means the fixed tag is advanced only when the
// restart it belongs to is actually running — a timeout between pull and
// restart can never strand the tag ahead of the daemon. A tag failure aborts
// BEFORE `up` (nothing recreated, tag unchanged → safe, NOT post-restart); an
// `up` failure is indeterminate and sets *failedPostRestart (when non-nil) so
// the caller's inline rollback fires. Shared by apply's `restart` stage and
// the rollback core's `rollback_restart` stage (which passes a nil flag — a
// rollback IS the recovery, never its own trigger).
func (s *Server) tagAndUp(ctx context.Context, ref string, failedPostRestart *bool) (stdout, stderr []byte, err error) {
	tres, terr := s.opts.Runner.ComposeTagPinned(ctx, ref)
	if terr != nil {
		if tres != nil {
			return tres.Stdout, tres.Stderr, terr
		}
		return nil, nil, terr
	}
	out := append([]byte(nil), tres.Stdout...)
	errOut := append([]byte(nil), tres.Stderr...)
	ures, uerr := s.opts.Runner.ComposeUp(ctx)
	if uerr != nil && failedPostRestart != nil {
		*failedPostRestart = true
	}
	if ures != nil {
		out = append(out, ures.Stdout...)
		errOut = append(errOut, ures.Stderr...)
	}
	return out, errOut, uerr
}

// imageRollbackStages builds the four core image-rollback steps pinned to
// targetRefFn() (resolved at run time). Stage names are the bare step
// names ("rollback_pull" … "rollback_verify"); ordering is fixed and is
// what the stage-parity drift guard pins.
func (s *Server) imageRollbackStages(targetRefFn func() string, acc *rollbackAccumulator) []ops.FlowStage {
	return []ops.FlowStage{
		{
			// P1.4: pull the repo-bound prior digest — LOCAL-FIRST: when the
			// exact digest is already in the local store the registry is not
			// consulted (no-offline floor). The retag is deferred to
			// rollback_restart (adjacent to `up`) so a timeout between the two
			// never advances the fixed tag ahead of the daemon.
			Name:          "rollback_pull",
			FailureReason: ops.ReasonCommandError,
			Run:           s.rollbackPull(targetRefFn, acc),
		},
		{
			// P1.4: retag the prior digest to culvert/proxy:pinned and
			// recreate the stack in one stage (nil flag — a rollback never
			// triggers itself), behind the FAIL-CLOSED write-ahead barrier.
			Name:          "rollback_restart",
			FailureReason: ops.ReasonCommandError,
			Run:           s.rollbackRestart(targetRefFn, acc),
		},
		{
			Name:          "rollback_health",
			FailureReason: ops.ReasonHealthFailed,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				probe := s.opts.HealthProbeFactory()
				probe.Preserve, probe.PreserveReportOnly = acc.preserved, true
				hr, herr := probe.Run(ctx)
				if herr != nil {
					return nil, nil, herr
				}
				acc.healthSummary = fmt.Sprintf("ready=%v ready_detail=%q health=%v health_detail=%q not_restored=[%s] duration=%s",
					hr.ReadyOK, hr.ReadyDetail, hr.HealthOK, hr.HealthDetail, strings.Join(hr.Regressed, ","), hr.TotalDuration)
				if hr.Failed() {
					return []byte(acc.healthSummary), nil, errors.New(hr.ReadyDetail)
				}
				return []byte(acc.healthSummary), nil, nil
			},
		},
		{
			Name:          "rollback_verify",
			FailureReason: ops.ReasonHealthFailed,
			Run:           s.rollbackVerify(targetRefFn, acc),
		},
	}
}

// rollbackPull is the rollback_pull stage body: local-first, then pull.
func (s *Server) rollbackPull(targetRefFn func() string, acc *rollbackAccumulator) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		ref := targetRefFn()
		if s.imagePresentLocally(ctx, ref) {
			acc.pullSkippedLocal = true
			s.rollbackAdvancePhase(acc, journal.PhasePulled)
			return []byte("rollback_pull: skipped (image present locally)"), nil, nil
		}
		res, rerr := s.opts.Runner.ComposePullDigest(ctx, ref)
		if res == nil {
			return nil, nil, rerr
		}
		if rerr == nil {
			s.rollbackAdvancePhase(acc, journal.PhasePulled)
		}
		return res.Stdout, res.Stderr, rerr
	}
}

// rollbackRestart is the rollback_restart stage body: barrier → tag+up →
// best-effort capture of the now-running config digest → PhaseRestarted.
func (s *Server) rollbackRestart(targetRefFn func() string, acc *rollbackAccumulator) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		if err := s.writeBarrierFor(acc.opID, acc.kind, acc.actor, acc.fold); err != nil {
			return nil, nil, fmt.Errorf("rollback_restart: write-ahead journal barrier failed, refusing to advance tag: %w", err)
		}
		out, errOut, uerr := s.tagAndUp(ctx, targetRefFn(), nil)
		if uerr == nil {
			if ri, cerr := s.opts.Runner.CaptureRunningProxyImage(ctx); cerr == nil {
				acc.targetImageID = ri.RunningImageID
			}
			s.rollbackAdvancePhase(acc, journal.PhaseRestarted)
		}
		return out, errOut, uerr
	}
}

// rollbackVerify is the rollback_verify stage body.
func (s *Server) rollbackVerify(targetRefFn func() string, acc *rollbackAccumulator) stageRun {
	return func(ctx context.Context) ([]byte, []byte, error) {
		targetDigest := digestRE.FindString(targetRefFn())
		acc.targetDigest = targetDigest
		ri, err := s.opts.Runner.CaptureRunningProxyImage(ctx)
		if err != nil {
			return []byte("verify: post-rollback capture failed"), nil,
				fmt.Errorf("post-rollback capture failed: %w", err)
		}
		acc.runningAfterDigests = bareDigests(ri.RepoDigests)
		if targetDigest != "" && !containsString(acc.runningAfterDigests, targetDigest) {
			return []byte(fmt.Sprintf("verify: running digests=%s do NOT include target %s",
					joinDigests(acc.runningAfterDigests), targetDigest)), nil,
				fmt.Errorf("post-rollback running image does not match target digest %s", targetDigest)
		}
		acc.targetImageID = ri.RunningImageID
		s.rollbackAdvancePhase(acc, journal.PhaseVerified)
		return []byte("verify: running_digests=" + joinDigests(acc.runningAfterDigests)), nil, nil
	}
}
