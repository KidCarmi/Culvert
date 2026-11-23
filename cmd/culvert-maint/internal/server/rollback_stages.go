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
	// evidence, when non-nil, receives every capture and `up` of the shared core so the
	// caller can report the final running image from evidence (inline rollback inside
	// upgrades.apply). The standalone rollback handler leaves it nil: unchanged behaviour.
	evidence *runningEvidence
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
//
// An `up` failure does NOT mean the container changed: `up` can fail before it
// touches the proxy, leaving the old container running under an advanced tag.
// tagAndUp only reports the failure; apply's restart stage follows it with
// realignPinnedTagAfterFailedUp (journal_phases.go), which moves the tag back
// when the container provably never moved (contract AGT-002).
//
// ev (may be nil) is marked stale immediately before `up`, whatever `up` returns: from then
// on an earlier capture no longer proves what runs.
func (s *Server) tagAndUp(ctx context.Context, ref string, failedPostRestart *bool, ev *runningEvidence) (stdout, stderr []byte, err error) {
	// Before anything is moved: let a container stop an interrupted image
	// change may have left in dockerd run out (settle.go).
	note, serr := s.settleInterrupted(ctx)
	if serr != nil {
		return nil, nil, serr
	}
	tres, terr := s.opts.Runner.ComposeTagPinned(ctx, ref)
	if terr != nil {
		if tres != nil {
			note = append(note, tres.Stdout...)
			return note, tres.Stderr, terr
		}
		return note, nil, terr
	}
	out := append([]byte(nil), note...)
	out = append(out, tres.Stdout...)
	errOut := append([]byte(nil), tres.Stderr...)
	ev.noteUp()
	ures, uerr := s.composeUp(ctx)
	if uerr != nil && failedPostRestart != nil {
		*failedPostRestart = true
	}
	if ures != nil {
		out = append(out, ures.Stdout...)
		errOut = append(errOut, ures.Stderr...)
	}
	if uerr == nil {
		out, errOut, uerr = s.upAgainIfNothingRuns(ctx, out, errOut)
		if uerr != nil && failedPostRestart != nil {
			*failedPostRestart = true
		}
	}
	return out, errOut, uerr
}

// upRetryBudget is how many more times `compose up` is run when the one before
// it reported success and left no proxy container running.
const upRetryBudget = 1

// upAgainIfNothingRuns closes the gap between "`up` exited 0" and "the proxy is
// up". It is decided on what Docker says, not on the exit status.
//
// Measured on real Docker: after a recreate interrupted between Compose's stop
// and its delete (the old container exited, the replacement created under a
// temporary name), the next `docker compose up -d` only tidies up — it removes
// a leftover and exits 0 with nothing started. The one after that starts the
// proxy. Without this, the first rollback after such a crash failed its health
// gate and left the proxy down until an operator submitted a second one.
//
// It applies only while an operation interrupted by an agent death is on
// record: that is when Compose can have been left in the middle of a recreate,
// and an ordinary upgrade keeps exactly the docker calls it always made.
//
// The retry is bounded and is the same command; it runs only when Docker was
// read and shows no running proxy container. If Docker cannot be read, nothing
// is assumed and the health gate decides. The health gate and the verify stage
// that follow are unchanged: this never turns a failure into a success, it
// only gives `up` the second pass it sometimes needs.
func (s *Server) upAgainIfNothingRuns(ctx context.Context, out, errOut []byte) (stdout, stderr []byte, err error) {
	if !s.mayBeMidRecreate() {
		return out, errOut, nil
	}
	for attempt := 1; attempt <= upRetryBudget; attempt++ {
		pc, rerr := s.opts.Runner.ReadProxyContainer(ctx)
		if rerr != nil {
			out = append(out, "\nrestart: could not read the proxy container after `up`; not retrying, the health gate decides\n"...)
			return out, errOut, nil
		}
		if pc.Running {
			return out, errOut, nil
		}
		out = append(out, fmt.Sprintf("\nrestart: `up` exited 0 but no proxy container is running (present=%v); running `up` again (%d/%d)\n",
			pc.Present, attempt, upRetryBudget)...)
		ures, uerr := s.composeUp(ctx)
		if ures != nil {
			out = append(out, ures.Stdout...)
			errOut = append(errOut, ures.Stderr...)
		}
		if uerr != nil {
			return out, errOut, uerr
		}
	}
	return out, errOut, nil
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
				return s.tagAndUp(ctx, targetRefFn(), nil, acc.evidence)
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
				acc.evidence.noteCapture(ri) // valid evidence even when it contradicts the target
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

// recoveringFromInterruption reports whether the journal holds a record that a
// previous agent process left behind (marked at startup, no operation of this
// process behind it). An unreadable journal counts as no: nothing is retried on
// a guess.
// mayBeMidRecreate reports whether Compose can have been left in the middle of
// a recreate by an earlier agent process: an interrupted record is on file, or
// this process found the marker of an unfinished compose up/down at its start.
// The marker covers an `up` that was cut with no record left to say so (its
// operation failed and retired its own record before the agent ended).
//
// A compose command of THIS process that ended in an error is deliberately not
// a trigger: the inline rollback that follows a failed `up` keeps exactly the
// docker calls the lifecycle model was reviewed with.
func (s *Server) mayBeMidRecreate() bool {
	return s.startMarker || s.recoveringFromInterruption()
}

func (s *Server) recoveringFromInterruption() bool {
	if s.opts.Journal == nil {
		return false
	}
	recs, err := s.opts.Journal.List()
	if err != nil {
		return false
	}
	for i := range recs {
		if recs[i].InterruptedAt != nil && !s.opts.Ops.IsRunning(recs[i].OpID) {
			return true
		}
	}
	return false
}
