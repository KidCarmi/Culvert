package ops

// Crash-safe terminal transition (ADR-0062 slice 1).
//
// When a journaled operation ends, three durable things happen, in this
// order, before the operation becomes terminal in memory (Manager.Finish,
// which releases the maintenance lock):
//
//  1. RecordTerminal stamps the journal record with the outcome, when it was
//     reached and whether the operation proved its end state safe. A kill
//     after this leaves a record that the next start recognises as ended,
//     not interrupted.
//  2. The terminal audit entry is written (fsync'd by the audit logger).
//  3. SettleTerminal removes the record when the end state is proven safe
//     (every success, and a failure the per-class judge accepts), and
//     otherwise keeps it, marked audited, so status and the next start keep
//     reporting it until a later success or a verified converge retires it.
//
// A kill between 1 and 2 leaves a record with an outcome and no audit entry:
// the next start finds no terminal entry for the op id and kind in the audit
// log and writes it (exactly once), then applies step 3. A kill between 2 and
// 3 leaves the same record with the entry present: the start finds it and
// does not write it again. So the terminal entry is never lost and never
// duplicated, and a record is never removed before it.

import (
	"strings"
	"time"
)

// Terminal is an operation's end as the orchestrator hands it to the journal.
type Terminal struct {
	State       State
	Reason      FailureReason
	FailedStage string
	At          time.Time
	// Safe is true when the record may be removed after the audit: always for
	// a success; for a failure only when the flow's EndStateJudge proved it.
	Safe bool
}

// TerminalOutcomeSucceeded and terminalOutcomeFailedPrefix spell the durable
// outcome (journal Record.TerminalOutcome).
const (
	TerminalOutcomeSucceeded    = "succeeded"
	terminalOutcomeFailedPrefix = "failed:"
)

// Outcome renders t as the journal's terminal_outcome value.
func (t Terminal) Outcome() string {
	if t.State == StateSucceeded {
		return TerminalOutcomeSucceeded
	}
	return terminalOutcomeFailedPrefix + string(t.Reason)
}

// ParseTerminalOutcome reads a journal terminal_outcome value. ok is false for
// anything this build did not write: an empty value, or a failure whose reason
// is not a plain lower-case identifier (the record is unauthenticated content,
// and the reason is copied into the op and the audit log).
func ParseTerminalOutcome(s string) (state State, reason FailureReason, ok bool) {
	if s == TerminalOutcomeSucceeded {
		return StateSucceeded, "", true
	}
	r, found := strings.CutPrefix(s, terminalOutcomeFailedPrefix)
	if !found || r == "" || len(r) > 64 {
		return "", "", false
	}
	for _, c := range r {
		if (c < 'a' || c > 'z') && c != '_' {
			return "", "", false
		}
	}
	return StateFailed, FailureReason(r), true
}

// TerminalJournal is the journal surface the orchestrator needs to end an op
// crash-safely. Implemented by the server, which owns the journal; kept as an
// interface so this package does not depend on the journal package. Optional:
// nil means the flow is not journaled.
type TerminalJournal interface {
	// RecordTerminal stamps the op's record with t BEFORE the terminal audit
	// entry is written. An absent record is not an error (nothing to keep).
	RecordTerminal(opID string, t Terminal) error
	// SettleTerminal runs once the terminal audit entry is durable: it removes
	// the record when t.Safe, and otherwise keeps it marked audited. It never
	// creates a record; kept reports whether a record was kept.
	SettleTerminal(opID string, t Terminal) (kept bool, err error)
}

// EndStateJudge reports whether a FAILED op proved that the state it left is
// safe, so that its journal record may be removed. failedStage is the first
// stage that failed (the stage that panicked, for a panic). It is consulted
// only for failures, must not block or mutate anything, and is supplied per
// flow by the server, which knows what each flow did in memory. A nil judge
// keeps the record of every failed journaled op.
type EndStateJudge func(failedStage string) bool
