package ops

import (
	"context"
	"errors"
	"fmt"
	"time"

	"culvert-maint/internal/audit"
)

// FlowStage is one step in an operation flow. The orchestrator runs
// FlowStages in declaration order, capturing each stage's outcome to
// the per-op log file and as a Stage progress record on the op
// (note: ops.Stage is a different, persisted type — FlowStage is the
// orchestrator's input, Stage is the orchestrator's output).
//
// Run returns (stdout, stderr, err). The first two are the (already-
// bounded) captures from the underlying command — they are appended
// verbatim to the op-log so operators reading
// GET /v1/operations/{id}/logs see exactly what the CLI emitted. err
// is non-nil iff the stage failed.
//
// FailureReason classifies err for the audit record. Empty defaults to
// ReasonCLIError — sensible for runner-level failures. Stage-specific
// reasons (e.g. ReasonHealthFailed for the post-up health check)
// override.
//
// ContinueOnError, when true, instructs the orchestrator to keep
// running subsequent stages even if Run returned an error. The op is
// still marked failed at the end (the FIRST failure wins for
// FailureReason), but later "best-effort" stages — like
// `compose up -d` after a failed `cli --restore --confirm` — get a
// chance to recover the stack.
type FlowStage struct {
	Name            string
	Run             func(ctx context.Context) (stdout, stderr []byte, err error)
	FailureReason   FailureReason
	ContinueOnError bool

	// PromoteReasonOnFailure, when true, makes this stage's
	// FailureReason OVERRIDE the op's final failure_reason if this stage
	// returns an error — even though an earlier stage already set the
	// first reason. This is the NARROW final-reason override the inline
	// auto-rollback plan (#375 §10) requires: a failed recovery-rollback
	// stage promotes the reason to rollback_failed so the worst case is
	// visible, WITHOUT introducing a generic "last failure wins" rule.
	// Only stages explicitly flagged here promote; operation timeout
	// still wins over a promoted reason.
	PromoteReasonOnFailure bool
}

// ResultFn computes the structured op result at terminal time, given the
// final state and (post-promotion) failure reason. Optional per flow;
// when set, its map is merged into the op result the orchestrator writes
// via Manager.Finish (timeout metadata, if any, is overlaid on top).
type ResultFn func(finalState State, finalReason FailureReason) map[string]interface{}

// OrchestratorDeps bundles the dependencies the orchestrator goroutine
// needs to run a flow to completion. All fields are required.
type OrchestratorDeps struct {
	Manager *Manager
	Audit   *audit.Logger
	OpLog   *OpLog // owned by the orchestrator; closed on completion
}

// Validate ensures every dependency is present. Called by Run before
// any goroutine work; returns immediately on misconfiguration.
func (d OrchestratorDeps) Validate() error {
	if d.Manager == nil {
		return errors.New("orchestrator: Manager required")
	}
	if d.Audit == nil {
		return errors.New("orchestrator: Audit required")
	}
	if d.OpLog == nil {
		return errors.New("orchestrator: OpLog required")
	}
	return nil
}

// Run executes stages sequentially against the op record opID. The
// op MUST already be admitted via Manager.BeginIdempotent (or
// Manager.Begin) — Run does NOT admit ops. On completion, Run calls
// Manager.Finish with the terminal state and emits a terminal audit
// event.
//
// Cancellation: if ctx is cancelled mid-flight, the in-flight stage's
// runner-level ctx is also cancelled (via standard context propagation
// from the runner's runWithEnv timeout), and the orchestrator records
// the partial outcome before exiting.
//
// This function BLOCKS until all stages complete (or the first abort
// + best-effort tail). Handlers run it in a goroutine so the HTTP
// response with op_id can return to the caller immediately.
//
// op-log lifecycle: the OpLog is closed unconditionally on Run's exit,
// regardless of success / failure / panic.
//
//nolint:cyclop,funlen,gocognit // single-pass orchestration; splitting hides the start→stages→finish ordering
func Run(ctx context.Context, deps OrchestratorDeps, opID, kind, actor string, params map[string]interface{}, idempotencyKey string, stages []FlowStage, resultFn ResultFn) {
	if err := deps.Validate(); err != nil {
		// Configuration error — should be unreachable in production
		// (handlers validate at construction time). Best-effort:
		// flip the op to failed with a generic reason.
		if deps.Manager != nil {
			_ = deps.Manager.Finish(opID, StateFailed, ReasonValidation, map[string]interface{}{"orchestrator_error": err.Error()})
		}
		return
	}
	defer func() { _ = deps.OpLog.Close() }()

	// Started audit event. Params are passed through verbatim — the
	// caller is responsible for stripping secrets (passphrase_ref,
	// not the value).
	startEvent := audit.Event{
		Actor:          actor,
		OpID:           opID,
		Kind:           kind,
		Params:         params,
		Outcome:        audit.OutcomeStarted,
		IdempotencyKey: idempotencyKey,
	}
	if err := deps.Audit.Write(startEvent); err != nil {
		_ = deps.OpLog.Note("agent", "warn: started audit emit failed: "+err.Error())
	}
	_ = deps.OpLog.Note("agent", fmt.Sprintf("op_id=%s kind=%s actor=%s — started", opID, kind, actor))

	// Stage loop.
	var (
		firstErr      error
		firstErrStage string
		firstReason   FailureReason
		// promotedReason is set by the FIRST stage flagged
		// PromoteReasonOnFailure that returns an error; it overrides
		// firstReason for the terminal failure_reason (narrow override).
		promotedReason FailureReason
	)
	// recordFailure folds a stage error into the first-failure and the
	// (narrow) promoted-reason tracking. Extracted so the stage loop stays
	// flat.
	recordFailure := func(st FlowStage, runErr error) {
		if firstErr == nil {
			firstErr = runErr
			firstErrStage = st.Name
			firstReason = st.FailureReason
			if firstReason == "" {
				firstReason = ReasonCLIError
			}
		}
		// A recovery stage explicitly flagged PromoteReasonOnFailure
		// promotes the terminal reason (e.g. a failed inline rollback →
		// rollback_failed), even though firstReason was already set.
		if st.PromoteReasonOnFailure && promotedReason == "" {
			promotedReason = st.FailureReason
			if promotedReason == "" {
				promotedReason = ReasonCLIError
			}
		}
	}
	for i := range stages {
		s := stages[i]
		// Skip if a non-recoverable failure already occurred AND this
		// stage is not flagged ContinueOnError.
		if firstErr != nil && !s.ContinueOnError {
			_ = deps.OpLog.Note(s.Name, "skipped (earlier failure)")
			continue
		}

		started := time.Now().UTC()
		// If a previous stage already failed and we're proceeding
		// only because this stage is ContinueOnError-tagged, mark
		// the run as "recovery" in the op log. Operators reading
		// /v1/operations/{id}/logs after a failure can immediately
		// see which stages ran for diagnostic / recovery reasons
		// vs. as the original happy-path flow.
		if firstErr != nil && s.ContinueOnError {
			_ = deps.OpLog.Note(s.Name, fmt.Sprintf("recovery: running after earlier failure at stage=%s", firstErrStage))
		}
		_ = deps.OpLog.StageStart(s.Name)

		stdout, stderr, runErr := s.Run(ctx)
		if len(stdout) > 0 {
			_ = deps.OpLog.Capture(s.Name, "out", stdout, 64*1024)
		}
		if len(stderr) > 0 {
			_ = deps.OpLog.Capture(s.Name, "err", stderr, 64*1024)
		}

		ended := time.Now().UTC()
		// One Stage record per actual stage, populated with the
		// terminal outcome. The per-op log file carries the
		// fine-grained START/END markers; the structured Op.Progress
		// list is the operator-facing summary.
		if runErr != nil {
			_ = deps.OpLog.StageEnd(s.Name, StateFailed, runErr.Error())
			_ = deps.Manager.AddStage(opID, Stage{Name: s.Name, State: StateFailed, Started: started, Ended: ended, Output: runErr.Error()})
			recordFailure(s, runErr)
		} else {
			_ = deps.OpLog.StageEnd(s.Name, StateSucceeded, "")
			_ = deps.Manager.AddStage(opID, Stage{Name: s.Name, State: StateSucceeded, Started: started, Ended: ended})
		}
	}

	// Terminal transition + audit.
	finalState := StateSucceeded
	if firstErr != nil {
		finalState = StateFailed
	}

	finalReason := FailureReason("")
	timedOut := false
	if finalState == StateFailed {
		finalReason = firstReason
		// Narrow override: a promoted recovery-stage reason (rollback_failed)
		// wins over the original first reason. Timeout still wins over this
		// (handled below).
		if promotedReason != "" {
			finalReason = promotedReason
		}
		// Operation-level timeout overrides any stage-level
		// failure reason. cfg.OperationTimeout is enforced by the
		// caller via context.WithTimeout(ctx, cfg.OperationTimeout);
		// when the deadline fires, every in-flight stage's
		// runner-level ctx is also cancelled. We promote that to
		// ReasonTimeout here so the audit trail makes the cause
		// unambiguous (rather than blaming whichever stage's
		// runner.Run happened to return DeadlineExceeded first).
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			finalReason = ReasonTimeout
			timedOut = true
			_ = deps.OpLog.Note("agent", "operation_timeout reached; promoting failure reason to timeout")
		}
	}

	// Result map: the per-flow ResultFn (if any) computes the structured
	// payload from the final state/reason, and timeout metadata is
	// overlaid on top so an operator inspecting `/v1/operations/{id}`
	// sees the timeout flag without cross-referencing the audit trail.
	var result map[string]interface{}
	if resultFn != nil {
		result = resultFn(finalState, finalReason)
	}
	if timedOut {
		if result == nil {
			result = map[string]interface{}{}
		}
		result["timed_out"] = true
		result["timed_out_at_stage"] = firstErrStage
		result["original_failure_reason"] = string(firstReason)
	}

	_ = deps.Manager.Finish(opID, finalState, finalReason, result)

	now := time.Now().UTC()
	endEvent := audit.Event{
		Actor:          actor,
		OpID:           opID,
		Kind:           kind,
		Params:         params,
		Outcome:        audit.OutcomeSucceeded,
		OutcomeAt:      &now,
		IdempotencyKey: idempotencyKey,
	}
	if finalState == StateFailed {
		endEvent.Outcome = audit.OutcomeFailed
		endEvent.FailureReason = string(finalReason)
	}
	if err := deps.Audit.Write(endEvent); err != nil {
		_ = deps.OpLog.Note("agent", "warn: terminal audit emit failed: "+err.Error())
	}
	if finalState == StateFailed {
		_ = deps.OpLog.Note("agent", fmt.Sprintf("op finished failed at stage=%s reason=%s err=%v", firstErrStage, finalReason, firstErr))
	} else {
		_ = deps.OpLog.Note("agent", "op finished succeeded")
	}
}
