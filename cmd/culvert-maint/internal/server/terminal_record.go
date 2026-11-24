// Keeping an operation's journal record until the state it left is proven
// safe, and making its terminal audit entry crash-safe (ADR-0062 slice 1).
//
// Before this file, the orchestrator removed an operation's record at every
// terminal state and only then wrote the terminal audit entry. Two gaps
// followed. A failed operation that left Docker in doubt — the fixed tag left
// at the target, a container state the flow itself calls indeterminate, a
// stack it stopped — lost its only durable trace at the end: after a restart
// there was no record and no status entry. And an agent killed between the
// removal and the audit write left an audit trail that ended at `started`.
//
// The sequence is now (ops/terminal.go): record the outcome on the record,
// write the audit entry, then remove the record only when the end state is
// proven safe, and otherwise keep it marked audited. Whether a failure proved
// its end state safe is judged here, per operation class, from what the flow
// knows in memory when it ends:
//
//	upgrades.apply           safe when the write-ahead barrier (PhaseRestarting)
//	                         was never written — the fixed tag moves only after
//	                         it — or when the op's own inline rollback passed
//	                         its health gate AND its digest verify.
//	rollbacks.create image   safe only when it failed before rollback_restart,
//	                         the stage that moves the tag and recreates the
//	                         proxy (its phase stays admitted throughout, so the
//	                         phase proves nothing).
//	restore.commit,          safe while the restore stage never reached
//	rollbacks.create data    `stopping` (nothing was stopped), or when it
//	                         committed and the health check after the restart
//	                         passed.
//	anything else            not proven: kept.
//
// A kept record is reported exactly like an interrupted one (status, every
// start), with the operation's real failure reason, and leaves only the way an
// interrupted record does: a later successful operation (journal_retire.go) or
// a verified converge (startup_reconcile.go), which decides it with the same
// table. The operation's own outcome is never rewritten.
package server

import (
	"fmt"
	"log"
	"time"

	"culvert-maint/internal/audit"
	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// terminalJournal is the server's ops.TerminalJournal: the journal operations
// the orchestrator's terminal sequence needs.
type terminalJournal struct{ j *journal.Journal }

// RecordTerminal stamps the outcome on the op's record before the audit entry.
// An absent record stays absent.
func (t terminalJournal) RecordTerminal(opID string, tm ops.Terminal) error {
	rec, found, err := t.j.Read(opID)
	if err != nil || !found {
		return err
	}
	stampTerminal(rec, tm)
	return t.j.Write(*rec)
}

// SettleTerminal runs after the audit entry is durable: remove when the end
// state is proven safe, otherwise keep the record marked audited. It never
// creates a record.
func (t terminalJournal) SettleTerminal(opID string, tm ops.Terminal) (kept bool, err error) {
	if tm.Safe {
		return false, t.j.Remove(opID)
	}
	rec, found, err := t.j.Read(opID)
	if err != nil || !found {
		return false, err
	}
	// Stamped again: RecordTerminal may have failed (the audit entry is
	// written regardless), and a kept record must say it ended.
	stampTerminal(rec, tm)
	rec.TerminalAudited = true
	return true, t.j.Write(*rec)
}

// stampTerminal copies tm onto rec. The phase, restore stage and identifiers
// are left as the flow recorded them: they are the evidence a later start and
// the converge decision read.
func stampTerminal(rec *journal.Record, tm ops.Terminal) {
	at := tm.At
	rec.TerminalOutcome = tm.Outcome()
	rec.TerminalAt = &at
	rec.TerminalSafe = tm.Safe
	rec.UpdatedAt = tm.At
}

// applyEndStateSafe is the upgrades.apply judge. Both facts are in-memory
// evidence the flow records as it goes: barrierWritten is set only when the
// fail-closed write-ahead barrier is durable, immediately before the tag move;
// rollbackSucceeded only when the inline rollback's rollback_verify passed,
// which runs only after its rollback_health passed.
func applyEndStateSafe(acc *upgradeApplyAccumulator) ops.EndStateJudge {
	return func(string) bool {
		return !acc.barrierWritten || acc.rollbackSucceeded
	}
}

// imageRollbackSafeStages are the standalone image rollback's stages that run
// before it moves the fixed tag: a failure in one of them changed no tag and no
// container. rollback_pull may have added an image to the local store, which
// changes nothing that runs.
var imageRollbackSafeStages = map[string]bool{"capture_before": true, "rollback_pull": true}

// imageRollbackEndStateSafe is the rollbacks.create mode=image judge.
func imageRollbackEndStateSafe(failedStage string) bool {
	return imageRollbackSafeStages[failedStage]
}

// restoreEndStateSafe is the restore-class judge (restore.commit and
// rollbacks.create mode=data). stopRecorded is set when the `stopping` restore
// stage has been written (fail-closed, immediately before `compose down`), so
// "not set" is exactly "the record's RestoreStage is still admitted or
// preflight". established is "committed and the health check passed".
func restoreEndStateSafe(f *restoreFlow) ops.EndStateJudge {
	return func(string) bool {
		return f == nil || !f.stopRecorded || f.established()
	}
}

// --- startup and retirement: finishing a terminal sequence that was cut short

// terminalAuditPresent reports whether the audit log already holds the op's
// terminal entry. A read error answers false: a duplicated entry is
// acceptable, a lost one is not.
func terminalAuditPresent(auditPath, opID, kind string) bool {
	ev, err := audit.FindTerminal(auditPath, opID, kind)
	if err != nil {
		log.Printf("culvert-maint: WARN: could not read the audit log for op %s's terminal entry; writing it: %v", opID, err)
		return false
	}
	return ev != nil
}

// ensureTerminalAudited makes sure the terminal audit entry of a record that
// carries a terminal outcome is durable, writing it from the record when the
// audit log has none. It changes only rec in memory (TerminalAudited); the
// caller persists or removes the record. It returns an error when the entry
// could not be written: the record must then stay as it is.
func ensureTerminalAudited(al *audit.Logger, rec *journal.Record, proxyRepo string) error {
	if rec.TerminalAudited {
		return nil
	}
	state, reason, ok := ops.ParseTerminalOutcome(rec.TerminalOutcome)
	if !ok {
		return fmt.Errorf("op %s: unreadable terminal outcome", rec.OpID)
	}
	desc := DescribeInterrupted(rec, proxyRepo)
	if !terminalAuditPresent(al.Path(), rec.OpID, desc.Kind) {
		if err := al.Write(terminalRepairEvent(rec, &desc, state, reason)); err != nil {
			return fmt.Errorf("op %s: terminal audit: %w", rec.OpID, err)
		}
	}
	rec.TerminalAudited = true
	return nil
}

// terminalRepairEvent is the terminal audit entry written on behalf of an
// operation whose process was killed before it wrote its own. Its params are
// the report's identifiers and classes (the request's own params never reach
// the journal) and say that it was written late.
func terminalRepairEvent(rec *journal.Record, desc *InterruptedOperation, state ops.State, reason ops.FailureReason) audit.Event {
	actor := desc.Actor
	if actor == "" {
		actor = AuditActorStartup
	}
	at := time.Now().UTC()
	if rec.TerminalAt != nil {
		at = *rec.TerminalAt
	}
	params := desc.AuditParams()
	params["terminal_audit_repaired"] = true
	ev := audit.Event{Actor: actor, OpID: rec.OpID, Kind: desc.Kind, Params: params, Outcome: audit.OutcomeSucceeded, OutcomeAt: &at}
	if state == ops.StateFailed {
		ev.Outcome, ev.FailureReason = audit.OutcomeFailed, string(reason)
	}
	return ev
}

// AdoptAuditedTerminal covers the one window the record cannot: the
// operation's process wrote its terminal audit entry but could not stamp the
// outcome on the record (the record write failed, then so did the settle), or
// a previous start wrote the interruption entry and died before the record
// remembered it. For a record with no outcome and no interruption entry on
// file, it looks the op's terminal entry up in the audit log:
//
//   - an "agent_restart_interrupted" entry is a previous start's interruption
//     entry: the record is marked InterruptAudited so it is not written again;
//   - any other terminal entry is the operation's own: its outcome is adopted
//     onto the record, marked audited, and the record is then settled like
//     any terminal record (kept unless it succeeded: TerminalSafe is unknown).
//
// It changes only rec in memory and writes nothing.
func AdoptAuditedTerminal(auditPath string, rec *journal.Record) {
	if rec.TerminalOutcome != "" || rec.InterruptAudited || rec.FromNewerAgent() {
		return
	}
	ev, err := audit.FindTerminal(auditPath, rec.OpID, reportKind(rec.Kind))
	if err != nil || ev == nil {
		return
	}
	if ev.FailureReason == string(ops.ReasonAgentRestartInterrupted) {
		rec.InterruptAudited = true
		return
	}
	tm := ops.Terminal{State: ops.StateSucceeded}
	if ev.Outcome != audit.OutcomeSucceeded {
		tm.State, tm.Reason = ops.StateFailed, ops.FailureReason(ev.FailureReason)
	}
	if _, _, ok := ops.ParseTerminalOutcome(tm.Outcome()); !ok {
		return // a reason this build would not write: leave the record interrupted
	}
	rec.TerminalOutcome = tm.Outcome()
	if ev.OutcomeAt != nil {
		at := *ev.OutcomeAt
		rec.TerminalAt = &at
	}
	rec.TerminalAudited = true
}

// removeEndedRecord removes the record of an ended operation whose terminal
// audit entry is durable, and reports whether it is gone.
func removeEndedRecord(jnl *journal.Journal, rec *journal.Record) bool {
	if err := jnl.Remove(rec.OpID); err != nil {
		log.Printf("culvert-maint: WARN: could not remove the journal record of ended op %s: %v", rec.OpID, err)
		return false
	}
	log.Printf("culvert-maint: op %s had ended (%s) before the last stop; its terminal audit entry is on file and its record was removed",
		rec.OpID, rec.TerminalOutcome)
	return true
}

// SettleTerminalAtStartup finishes, at agent start, the terminal sequence of a
// record whose operation ended (it carries a terminal outcome). It runs no
// docker command.
//
//  1. Unless the record says its entry is durable, the terminal audit entry is
//     written — only if the audit log does not already hold it.
//  2. A success, or a failure the operation proved safe, is removed (audit
//     first). Anything else is kept, marked audited, and reported.
//
// report is false when the record was removed, and for a success (a success is
// never reported as a failed operation, even when its record could not be
// removed). The returned op carries the operation's real failure reason.
// handled is false when the record's outcome is not one this build wrote; the
// caller then reports it as an interrupted operation.
func SettleTerminalAtStartup(jnl *journal.Journal, al *audit.Logger, rec *journal.Record, proxyRepo string, seenCap int) (op ops.InterruptedOp, report, handled bool) {
	state, reason, ok := ops.ParseTerminalOutcome(rec.TerminalOutcome)
	if !ok || rec.FromNewerAgent() {
		return ops.InterruptedOp{}, false, false
	}
	if err := ensureTerminalAudited(al, rec, proxyRepo); err != nil {
		// Not durable, so nothing is removed or marked: the next start retries.
		log.Printf("culvert-maint: WARN: could not write the terminal audit entry of op %s (will retry at the next start); record kept: %v", rec.OpID, err)
	} else if (state == ops.StateSucceeded || rec.TerminalSafe) && removeEndedRecord(jnl, rec) {
		return ops.InterruptedOp{}, false, true
	}
	if rec.InterruptedSeen < seenCap {
		rec.InterruptedSeen++
	}
	if werr := jnl.Write(*rec); werr != nil {
		log.Printf("culvert-maint: WARN: could not update the journal record of ended op %s: %v", rec.OpID, werr)
	}
	if state == ops.StateSucceeded {
		return ops.InterruptedOp{}, false, true
	}
	desc := DescribeInterrupted(rec, proxyRepo)
	actor := desc.Actor
	if actor == "" {
		actor = AuditActorStartup
	}
	log.Printf("culvert-maint: op %s kind=%s ended failed(%s) and left a state it could not prove safe; record kept (journal_phase=%s docker_state=%s starts_seen=%d)",
		rec.OpID, desc.Kind, reason, desc.JournalPhase, desc.DockerState, rec.InterruptedSeen)
	return ops.InterruptedOp{OpID: rec.OpID, Kind: desc.Kind, Actor: actor, Started: rec.StartedAt, Result: desc.ResultMap(), FailureReason: reason}, true, true
}
