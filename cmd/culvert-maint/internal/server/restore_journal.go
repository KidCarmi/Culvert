// Crash-recovery journal progress for the restore flow (restore.commit, and
// rollbacks.create mode=data, which runs the same stages).
//
// The flow stops the proxy, replaces the data directory and starts the proxy
// again. An agent that dies between those steps leaves the proxy down, and
// before this file existed it left nothing else: the operation answered 404
// after the restart, status listed nothing, and the audit log ended at
// `started`. The record written here is what the next start reports from
// (interrupted.go). It is evidence for a report and nothing more: no code path
// reads a restore stage to decide a Docker action (ADR-0061, addendum of
// 2026-11-24).
//
// Disciplines, mirroring journal_phases.go:
//
//   - WRITE-AHEAD and FAIL-CLOSED before the two steps that cannot be taken
//     back by not doing them: `stopping` before `compose down` and `committing`
//     before the commit command. No durable record, no step.
//   - `committed` after the commit command returned success is fail-closed in
//     the other direction: the data HAS changed, so the write cannot prevent
//     anything, but an operation that cannot say durably that it replaced the
//     data directory must not report plain success. It fails, with a reason
//     and a stage output that say the data changed, and still starts the stack.
//   - Everything else (`preflight`, `commit_failed`, `starting`, `started`) is
//     a best-effort breadcrumb. A lost one leaves the record at an EARLIER
//     stage whose report claims less, never more: `committing` (result unknown)
//     instead of `commit_failed`, `committed` instead of `starting`.
//
// `starting` and `started` are written only after a recorded-successful
// commit. On every other path that reaches `compose up` (the stop failed, the
// commit failed or was refused) the stage is left where it was, because it is
// the only durable statement of what happened to the data and the next value
// would overwrite it.
package server

import (
	"context"
	"fmt"
	"time"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
)

// restoreFlow carries one restore-class operation's identity to its stages and
// collects what they observed. A nil *restoreFlow, an empty opID or a server
// without a journal makes every method a no-op, so the stages run unchanged in
// a build or a test that does not journal.
type restoreFlow struct {
	opID  string // set by the op-id hook before any stage runs
	kind  string // ops.KindRestoreCommit or ops.KindRollbackCreate
	mode  string // journal Record.Mode: "" for restore.commit, "data" for a data rollback
	actor string

	// committed: the commit command returned success. The data directory was
	// replaced, whether or not that could be recorded.
	committed bool
	// healthPassed: the health check after the restart passed.
	healthPassed bool
}

// newRestoreFlow returns the flow for kind. mode is the journal mode ("" or
// "data"), not the restore mode.
func newRestoreFlow(kind, mode, actor string) *restoreFlow {
	return &restoreFlow{kind: kind, mode: mode, actor: actor}
}

// established reports whether the operation left the data directory committed
// and the proxy serving on it. It is what lets a later restore retire the
// records of earlier, interrupted ones (journal_retire.go).
func (f *restoreFlow) established() bool {
	return f != nil && f.committed && f.healthPassed
}

// advanceRestoreStage read-modify-writes the operation's record to stage,
// keeping every other field. A missing record is re-created, as the upgrade's
// write-ahead barrier does: a record that vanished must not let a destructive
// step run unrecorded.
func (s *Server) advanceRestoreStage(f *restoreFlow, stage journal.RestoreStage) error {
	if f == nil || f.opID == "" || s.opts.Journal == nil {
		return nil
	}
	rec, found, err := s.opts.Journal.Read(f.opID)
	if err != nil {
		return fmt.Errorf("journal read: %w", err)
	}
	now := time.Now().UTC()
	if !found {
		rec = &journal.Record{
			OpID: f.opID, Kind: f.kind, Mode: f.mode, Phase: journal.PhaseAdmitted,
			Actor: f.actor, StartedAt: now,
		}
	}
	rec.RestoreStage = stage
	rec.UpdatedAt = now
	return s.opts.Journal.Write(*rec)
}

// advanceRestoreStageBestEffort records a breadcrumb and ignores a failure.
func (s *Server) advanceRestoreStageBestEffort(f *restoreFlow, stage journal.RestoreStage) {
	_ = s.advanceRestoreStage(f, stage) //nolint:errcheck // a lost breadcrumb leaves an earlier stage, whose report claims less
}

// recordRestoreCommitResult records how the commit command ended. cmdErr is the
// command's own error and is returned unchanged when there is one. When the
// command succeeded and `committed` cannot be written, the returned error fails
// the stage: see the file comment.
//
// The reason for that failure is command_error, not the stage's own cli_error.
// cli_error on this stage has always meant "the restore command refused or
// failed", which a consumer may read as "the data is as it was" and answer by
// submitting the restore again — over data that WAS replaced. command_error is
// the existing reason for "a step of the agent's own failed" (it is what a
// failed `compose down` or `compose up` in this same flow reports) and promises
// nothing about the data. health_failed was not used: on this flow it means
// "committed, and the proxy did not come up healthy", and the proxy may be
// perfectly healthy here. No existing reason says "the data changed"; the stage
// output and the operation result (restore_committed) do.
func (s *Server) recordRestoreCommitResult(f *restoreFlow, cmdErr error) error {
	if cmdErr != nil {
		s.advanceRestoreStageBestEffort(f, journal.RestoreStageCommitFailed)
		return cmdErr
	}
	if f != nil {
		f.committed = true
	}
	if jerr := s.advanceRestoreStage(f, journal.RestoreStageCommitted); jerr != nil {
		return &ops.ReasonError{
			Reason: ops.ReasonCommandError,
			Err: fmt.Errorf("the restore COMMITTED — the data directory WAS replaced and the previous content is kept in the restore's backup directory — "+
				"but the agent could not record that in its journal (%w); the stack is started and health-checked next. "+
				"Do not submit this restore again on the strength of this failure", jerr),
		}
	}
	return nil
}

// noteHealthPassed records that the health check after the restart passed.
func (f *restoreFlow) noteHealthPassed() {
	if f != nil {
		f.healthPassed = true
	}
}

// restoreStopStack is the stop_stack stage body. *stackTouched is set once the
// operation has asked Docker to stop the stack, and not before.
func (s *Server) restoreStopStack(ctx context.Context, f *restoreFlow, stackTouched *bool) (stdout, stderr []byte, err error) {
	// Write-ahead, fail-closed: an agent death after this point leaves the
	// proxy down, and the record is the only thing that will say why. Not
	// recorded, not stopped.
	if jerr := s.advanceRestoreStage(f, journal.RestoreStageStopping); jerr != nil {
		return nil, nil, fmt.Errorf("stop_stack: could not record the restore's progress in the journal, refusing to stop the stack (nothing was changed): %w", jerr)
	}
	*stackTouched = true
	res, rerr := s.composeDown(ctx) // marks the in-flight mutation and notes a cut (mutation.go)
	if res == nil {
		return nil, nil, rerr
	}
	return res.Stdout, res.Stderr, rerr
}

// restoreRunCommit is the run_cli_restore_commit stage body around commit, the
// restore's commit command.
func (s *Server) restoreRunCommit(ctx context.Context, f *restoreFlow, commit func(context.Context) (*runner.Result, error)) (stdout, stderr []byte, err error) {
	// Write-ahead, fail-closed. The record stays at `stopping` (the stack was
	// stopped, the data was not touched) and the start_stack stage that follows
	// brings the stack back.
	if jerr := s.advanceRestoreStage(f, journal.RestoreStageCommitting); jerr != nil {
		return nil, nil, fmt.Errorf("run_cli_restore_commit: could not record the restore's progress in the journal, refusing to run the commit (the data directory was not changed): %w", jerr)
	}
	res, rerr := commit(ctx)
	rerr = s.recordRestoreCommitResult(f, rerr)
	if res == nil {
		return nil, nil, rerr
	}
	return res.Stdout, res.Stderr, rerr
}

// restoreStartStack is the start_stack stage body for a stack this operation
// stopped. `starting` and `started` are recorded only after a commit: on the
// recovery paths the stage must keep saying what happened to the data.
func (s *Server) restoreStartStack(ctx context.Context, f *restoreFlow) (stdout, stderr []byte, err error) {
	committed := f != nil && f.committed
	if committed {
		s.advanceRestoreStageBestEffort(f, journal.RestoreStageStarting)
	}
	res, rerr := s.composeUp(ctx) // marks the in-flight mutation and notes a cut (mutation.go)
	if rerr == nil && committed {
		s.advanceRestoreStageBestEffort(f, journal.RestoreStageStarted)
	}
	if res == nil {
		return nil, nil, rerr
	}
	return res.Stdout, res.Stderr, rerr
}

// isRestoreRecord reports whether a journal record of this kind and mode is a
// restore-class record: one whose operation stops the stack and replaces the
// data directory, and moves no image tag.
func isRestoreRecord(kind, mode string) bool {
	return kind == ops.KindRestoreCommit || (kind == ops.KindRollbackCreate && mode == "data")
}
