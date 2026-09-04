package execution

// recovery.go — orphan-attempt recovery from durable evidence
// (First Controlled Canary review §10).
//
// An ORPHAN is defined exactly, and only, as:
//
//	a durable PhaseSendIntent exists
//	AND no valid terminal PhaseOutcome exists for the same AttemptID
//
// It is NOT inferred from process startup, from a missing in-memory handle, or
// from elapsed time. Those are all statements about Culvert's own liveness; the
// question that matters is what the durable record says.
//
// There is deliberately NO second ledger. Recovery reads the SAME committed event
// stream the execution path writes, through a narrow read seam, so the evidence
// cannot drift from a competing source of truth. Any index built on top of this
// must be fully reconstructable by re-running it.
//
// The recovered state is `reconciliation_required`, which is WEAKER than
// `may_have_been_sent`. That distinction is load-bearing: a surviving execution
// path knows the call began, so may_have_been_sent is a justified claim. A process
// that died knows only that an intent was committed — the crash may have preceded
// or followed the physical send — so it must not assert the stronger statement.

import (
	"sort"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// AttemptState is the derived disposition of one attempt as the durable ledger
// describes it.
type AttemptState string

const (
	// AttemptReconciliationRequired — an intent with no valid terminal outcome. Only
	// an authoritative independent witness can resolve it.
	AttemptReconciliationRequired AttemptState = "reconciliation_required"
	// AttemptSettled — an intent with exactly one valid, consistent terminal outcome.
	AttemptSettled AttemptState = "settled"
)

// RecoveredAttempt is the reconstructed identity of one attempt. Every field comes
// from the durable intent; recovery NEVER mints a new AttemptID, because a new
// identity would be unmatchable against a witness that recorded the original.
type RecoveredAttempt struct {
	AttemptID            string
	ReservationID        string
	ActivationGeneration uint64
	State                AttemptState
	// TerminalSendState is the committed physical-send state when State is
	// AttemptSettled, and the zero value otherwise. It is never synthesized for an
	// orphan.
	TerminalSendState model.PhysicalSendState
	// Reconciliation is the DERIVED knowledge from append-only witness evidence. It
	// is ReconRequired for an unreconciled orphan and empty for a settled attempt.
	// It never changes execution authority — only what is known.
	Reconciliation model.ReconciliationResult
}

// RecoveryReport is the result of one derivation over the durable stream.
type RecoveryReport struct {
	// Orphans require reconciliation. They consume their original allowance
	// permanently and are never re-executed.
	Orphans []RecoveredAttempt
	// Settled attempts reached a valid terminal outcome.
	Settled []RecoveredAttempt
}

// EvidenceReader is the narrow read seam over the authoritative committed event
// stream. *spool.Spool satisfies it; tests supply deterministic fixtures.
type EvidenceReader interface {
	CommittedForExport(part model.Partition, afterSeq uint64, maxRecords int) ([]model.Event, []uint64, uint64, error)
}

// recoveryScanPartitions are the partitions attempt evidence can land in. Denial
// events carry no attempt and are excluded.
var recoveryScanPartitions = []model.Partition{model.PartCrit, model.PartOrd}

// recoveryPageSize bounds one read so recovery cannot be turned into an unbounded
// allocation by a large spool.
const recoveryPageSize = 512

// RecoverAttempts derives every attempt's disposition from the durable event
// stream.
//
// It FAILS CLOSED on any ambiguity rather than choosing the newest record. A ledger
// that describes one attempt two different ways is not a ledger to pick a winner
// from — the ambiguity is itself unsafe evidence, and silently resolving it is how
// a duplicate physical effect would disappear from the record.
func RecoverAttempts(r EvidenceReader) (RecoveryReport, error) {
	if r == nil {
		return RecoveryReport{}, mcperr.New(mcperr.ReasonEventEvidenceMissing, "execution.recovery", "no evidence reader")
	}
	intents := map[string]*model.OutcomeEvidence{}
	outcomes := map[string]*model.OutcomeEvidence{}
	recon := map[string]model.ReconciliationResult{}

	for _, part := range recoveryScanPartitions {
		var after uint64
		for {
			evs, _, cursor, err := r.CommittedForExport(part, after, recoveryPageSize)
			if err != nil {
				// Unreadable evidence is NOT an empty ledger. Reporting no orphans here
				// would silently convert corruption into "nothing to reconcile".
				return RecoveryReport{}, mcperr.New(mcperr.ReasonEventEvidenceMissing,
					"execution.recovery", "durable evidence unreadable")
			}
			for i := range evs {
				if err := indexAttemptEvent(&evs[i], intents, outcomes, recon); err != nil {
					return RecoveryReport{}, err
				}
			}
			if len(evs) == 0 || cursor <= after {
				break
			}
			after = cursor
		}
	}

	var rep RecoveryReport
	for id, intent := range intents {
		out, settled := outcomes[id]
		if !settled {
			// An orphan's knowledge state comes from append-only reconciliation
			// evidence when any exists. Its EXECUTION state is unchanged either way:
			// reconciliation changes knowledge, never authority.
			known := model.ReconRequired
			if r, ok := recon[id]; ok {
				known = r
			}
			rep.Orphans = append(rep.Orphans, RecoveredAttempt{
				AttemptID:            intent.AttemptID,
				ReservationID:        intent.ReservationID,
				ActivationGeneration: intent.ActivationGeneration,
				State:                AttemptReconciliationRequired,
				Reconciliation:       known,
			})
			continue
		}
		// The terminal outcome must describe the SAME authorization as the intent.
		// A mismatch means the ledger binds one physical effect to two different
		// grants or generations, which no later reasoning can safely repair.
		if out.ReservationID != intent.ReservationID {
			return RecoveryReport{}, mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "attempt reservation mismatch between intent and outcome")
		}
		if out.ActivationGeneration != intent.ActivationGeneration {
			return RecoveryReport{}, mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "attempt generation mismatch between intent and outcome")
		}
		if !out.PhysicalSendState.Valid() {
			return RecoveryReport{}, mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "terminal outcome with unknown physical send state")
		}
		rep.Settled = append(rep.Settled, RecoveredAttempt{
			AttemptID:            intent.AttemptID,
			ReservationID:        intent.ReservationID,
			ActivationGeneration: intent.ActivationGeneration,
			State:                AttemptSettled,
			TerminalSendState:    out.PhysicalSendState,
		})
	}
	// A terminal outcome with no intent means a physical effect was recorded that no
	// durable authorization covers. That is the most serious ledger fault of all.
	for id := range outcomes {
		if _, ok := intents[id]; !ok {
			return RecoveryReport{}, mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "terminal outcome without a matching send intent")
		}
	}

	// Deterministic order so repeated recovery is byte-stable and idempotent.
	sort.Slice(rep.Orphans, func(i, j int) bool { return rep.Orphans[i].AttemptID < rep.Orphans[j].AttemptID })
	sort.Slice(rep.Settled, func(i, j int) bool { return rep.Settled[i].AttemptID < rep.Settled[j].AttemptID })
	return rep, nil
}

// indexAttemptEvent folds one event into the intent/outcome indexes, failing closed
// on duplicates and on malformed attempt evidence.
func indexAttemptEvent(e *model.Event, intents, outcomes map[string]*model.OutcomeEvidence, recon map[string]model.ReconciliationResult) error {
	if e.Phase == model.PhaseReconciliation {
		return indexReconciliationEvent(e, recon)
	}
	if e.Phase != model.PhaseSendIntent && e.Phase != model.PhaseOutcome {
		return nil
	}
	if e.Outcome == nil || e.Outcome.AttemptID == "" {
		if e.Phase == model.PhaseSendIntent {
			return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery", "send intent without attempt identity")
		}
		// A PhaseOutcome with no attempt evidence predates attempt accounting (or is
		// a non-attempt outcome); it names no attempt and so cannot settle one.
		return nil
	}
	if !validAttemptID(e.Outcome.AttemptID) {
		return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery", "malformed attempt identity in evidence")
	}
	id := e.Outcome.AttemptID
	switch e.Phase {
	case model.PhaseSendIntent:
		if _, dup := intents[id]; dup {
			// Two intents for one attempt id: either the identity was reused (which
			// the minting contract forbids) or the ledger is corrupt. Either way the
			// attempt count is no longer trustworthy.
			return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery", "duplicate send intent for one attempt")
		}
		ev := *e.Outcome
		intents[id] = &ev
	case model.PhaseOutcome:
		if _, dup := outcomes[id]; dup {
			return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery", "multiple terminal outcomes for one attempt")
		}
		ev := *e.Outcome
		outcomes[id] = &ev
	}
	return nil
}

// indexReconciliationEvent folds append-only witness evidence into the knowledge
// index.
//
// Repeating the SAME result is idempotent — re-running reconciliation with the same
// authoritative observation must not be an error, and must not produce a second
// authoritative record's worth of meaning. A LATER CONTRADICTORY result is a
// different matter entirely: a ledger that first proves an attempt was not received
// and later proves it was is broken, and silently preferring either record would
// hide a real physical effect. That fails closed, loudly.
func indexReconciliationEvent(e *model.Event, recon map[string]model.ReconciliationResult) error {
	if e.Reconciliation == nil || e.Reconciliation.AttemptID == "" {
		return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery", "reconciliation without attempt identity")
	}
	if !validAttemptID(e.Reconciliation.AttemptID) {
		return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery", "malformed attempt identity in reconciliation")
	}
	if !e.Reconciliation.Result.Valid() {
		return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery", "reconciliation with unknown result")
	}
	id := e.Reconciliation.AttemptID
	prev, seen := recon[id]
	if !seen {
		recon[id] = e.Reconciliation.Result
		return nil
	}
	if prev == e.Reconciliation.Result {
		return nil // idempotent re-run of the same authoritative observation
	}
	// An unresolved earlier record may be superseded by a resolving one; anything
	// else is a contradiction between two authoritative claims.
	if prev == model.ReconRequired {
		recon[id] = e.Reconciliation.Result
		return nil
	}
	return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery",
		"contradictory reconciliation results for one attempt")
}
