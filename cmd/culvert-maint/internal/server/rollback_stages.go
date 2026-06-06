// Shared image-rollback stages — the single source of truth for the
// pull → restart → health → verify sequence used by BOTH the standalone
// rollback handler (POST /v1/rollbacks, mode=image) and apply's inline
// auto-rollback (#375 §8). Keeping one builder is the anti-drift
// guarantee: manual and automatic rollback cannot diverge.
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

	"culvert-maint/internal/ops"
)

// rollbackAccumulator carries parsed digests + the health summary across
// the shared rollback stages. Parsed identifiers only — never raw inspect
// JSON. priorDigests is used by the standalone handler's capture_before +
// report; targetDigest / runningAfterDigests are set by the core stages.
type rollbackAccumulator struct {
	priorDigests        []string
	targetDigest        string
	runningAfterDigests []string
	healthSummary       string
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
			// P1.4: pull the repo-bound prior digest. The retag is deferred
			// to rollback_restart (adjacent to `up`) so a timeout between the
			// two never advances the fixed tag ahead of the daemon.
			Name:          "rollback_pull",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				res, rerr := s.opts.Runner.ComposePullDigest(ctx, targetRefFn())
				if res == nil {
					return nil, nil, rerr
				}
				return res.Stdout, res.Stderr, rerr
			},
		},
		{
			// P1.4: retag the prior digest to culvert/proxy:pinned and
			// recreate the stack in one stage (nil flag — a rollback never
			// triggers itself).
			Name:          "rollback_restart",
			FailureReason: ops.ReasonCommandError,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				return s.tagAndUp(ctx, targetRefFn(), nil)
			},
		},
		{
			Name:          "rollback_health",
			FailureReason: ops.ReasonHealthFailed,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
				hr, herr := s.opts.HealthProbeFactory().Run(ctx)
				if herr != nil {
					return nil, nil, herr
				}
				acc.healthSummary = fmt.Sprintf("ready=%v ready_detail=%q health=%v health_detail=%q duration=%s",
					hr.ReadyOK, hr.ReadyDetail, hr.HealthOK, hr.HealthDetail, hr.TotalDuration)
				if hr.Failed() {
					return []byte(acc.healthSummary), nil, errors.New(hr.ReadyDetail)
				}
				return []byte(acc.healthSummary), nil, nil
			},
		},
		{
			Name:          "rollback_verify",
			FailureReason: ops.ReasonHealthFailed,
			Run: func(ctx context.Context) ([]byte, []byte, error) {
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
				return []byte("verify: running_digests=" + joinDigests(acc.runningAfterDigests)), nil, nil
			},
		},
	}
}
