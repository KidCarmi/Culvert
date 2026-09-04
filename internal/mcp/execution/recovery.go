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

// ReservationBreach names one budget slot that authorized MORE THAN ONE physical
// attempt. It is the review-blocker-#6 invariant breach expressed in the ledger:
//
//	one accepted execution reservation  =>  at most one physical tool invocation
//
// It is REPORTED rather than raised as an error, deliberately. Failing the whole
// derivation closed would leave the operator with no report at all — including no
// account of the very attempts that need reconciling — so the breach is named,
// carried alongside a usable report, and impossible to overlook.
type ReservationBreach struct {
	ReservationID string
	AttemptIDs    []string
}

// RecoveryReport is the result of one derivation over the durable stream.
type RecoveryReport struct {
	// Orphans require reconciliation. They consume their original allowance
	// permanently and are never re-executed.
	Orphans []RecoveredAttempt
	// Settled attempts reached a valid terminal outcome.
	Settled []RecoveredAttempt
	// ReservationBreaches names every slot bound to more than one attempt. A
	// non-empty slice means N accepted reservations produced more than N potential
	// physical invocations.
	//
	// Surfacing this was a red-team finding. Recovery previously listed such
	// attempts individually — VISIBLE, but not the same as DETECTED: nothing
	// distinguished "two attempts" from "two attempts that one slot paid for".
	ReservationBreaches []ReservationBreach
}

// HasReservationBreach reports whether any slot authorized more than one attempt.
func (r RecoveryReport) HasReservationBreach() bool { return len(r.ReservationBreaches) > 0 }

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

// attemptIndex is the folded view of the durable stream: what was intended, what
// settled, and what an independent witness has since reported.
type attemptIndex struct {
	intents  map[string]*model.OutcomeEvidence
	outcomes map[string]*model.OutcomeEvidence
	// recon retains the FULL evidence, not just the derived result, because the
	// reservation and generation it names must be checked against the intent — a
	// record can be perfectly well-formed and still describe a different
	// authorization (Codex round 1, P1).
	recon map[string]*model.ReconciliationEvidence
}

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
	idx, err := scanAttemptEvidence(r)
	if err != nil {
		return RecoveryReport{}, err
	}
	rep, err := deriveAttempts(idx)
	if err != nil {
		return RecoveryReport{}, err
	}
	// Deterministic order so repeated recovery is byte-stable and idempotent.
	sort.Slice(rep.Orphans, func(i, j int) bool { return rep.Orphans[i].AttemptID < rep.Orphans[j].AttemptID })
	sort.Slice(rep.Settled, func(i, j int) bool { return rep.Settled[i].AttemptID < rep.Settled[j].AttemptID })
	rep.ReservationBreaches = deriveReservationBreaches(rep)
	return rep, nil
}

// indexAttemptEvent folds one event into the intent/outcome indexes, failing closed
// on duplicates and on malformed attempt evidence.
func indexAttemptEvent(e *model.Event, intents, outcomes map[string]*model.OutcomeEvidence, recon map[string]*model.ReconciliationEvidence) error {
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
func indexReconciliationEvent(e *model.Event, recon map[string]*model.ReconciliationEvidence) error {
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
		ev := *e.Reconciliation
		recon[id] = &ev
		return nil
	}
	// IDENTITY BEFORE RESULT (Codex round 5, P2). Idempotence was keyed on Result
	// ALONE, so a second record agreeing on the verdict but naming a DIFFERENT
	// reservation or generation was discarded here — before orphanFrom or
	// settledReconOK could ever see it. Two records under one attempt id describing
	// two authorizations is the ledger fault, whatever verdict they happen to share,
	// and dropping the second one is precisely how it would go unnoticed.
	if prev.ReservationID != e.Reconciliation.ReservationID ||
		prev.ActivationGeneration != e.Reconciliation.ActivationGeneration {
		return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery",
			"reconciliation records for one attempt name different authorizations")
	}
	if prev.Result == e.Reconciliation.Result {
		return nil // idempotent re-run of the same authoritative observation
	}
	// An unresolved earlier record may be superseded by a resolving one; anything
	// else is a contradiction between two authoritative claims.
	if prev.Result == model.ReconRequired {
		ev := *e.Reconciliation
		recon[id] = &ev
		return nil
	}
	return mcperr.New(mcperr.ReasonEventInvalid, "execution.recovery",
		"contradictory reconciliation results for one attempt")
}

// deriveReservationBreaches groups every recovered attempt by the reservation that
// authorized it and names each slot bound to more than one.
//
// An EMPTY reservation id is excluded: it identifies no slot, so grouping by it
// would fabricate a breach out of legacy or non-metered evidence. That is the one
// direction this report must not err in — a false breach would discredit the signal
// that exists to catch the real one.
func deriveReservationBreaches(rep RecoveryReport) []ReservationBreach {
	byRes := map[string][]string{}
	collect := func(as []RecoveredAttempt) {
		for _, a := range as {
			if a.ReservationID != "" {
				byRes[a.ReservationID] = append(byRes[a.ReservationID], a.AttemptID)
			}
		}
	}
	collect(rep.Orphans)
	collect(rep.Settled)

	var out []ReservationBreach
	for res, ids := range byRes {
		if len(ids) < 2 {
			continue
		}
		sort.Strings(ids)
		out = append(out, ReservationBreach{ReservationID: res, AttemptIDs: ids})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReservationID < out[j].ReservationID })
	return out
}

// scanAttemptEvidence folds every attempt-bearing event in the durable stream into
// one index, paging through each partition.
func scanAttemptEvidence(r EvidenceReader) (attemptIndex, error) {
	idx := attemptIndex{
		intents:  map[string]*model.OutcomeEvidence{},
		outcomes: map[string]*model.OutcomeEvidence{},
		recon:    map[string]*model.ReconciliationEvidence{},
	}
	for _, part := range recoveryScanPartitions {
		var after uint64
		for {
			evs, _, cursor, err := r.CommittedForExport(part, after, recoveryPageSize)
			if err != nil {
				// Unreadable evidence is NOT an empty ledger. Reporting no orphans here
				// would silently convert corruption into "nothing to reconcile".
				return attemptIndex{}, mcperr.New(mcperr.ReasonEventEvidenceMissing,
					"execution.recovery", "durable evidence unreadable")
			}
			for i := range evs {
				if err := indexAttemptEvent(&evs[i], idx.intents, idx.outcomes, idx.recon); err != nil {
					return attemptIndex{}, err
				}
			}
			if len(evs) == 0 || cursor <= after {
				break
			}
			after = cursor
		}
	}
	return idx, nil
}

// deriveAttempts turns the folded index into the report, classifying each attempt
// as an orphan or a settled one and failing closed on any contradiction.
func deriveAttempts(idx attemptIndex) (RecoveryReport, error) {
	var rep RecoveryReport
	for id, intent := range idx.intents {
		out, settled := idx.outcomes[id]
		if !settled {
			orphan, err := orphanFrom(intent, idx.recon[id])
			if err != nil {
				return RecoveryReport{}, err
			}
			rep.Orphans = append(rep.Orphans, orphan)
			continue
		}
		rec, err := settledFrom(intent, out, idx.recon[id])
		if err != nil {
			return RecoveryReport{}, err
		}
		rep.Settled = append(rep.Settled, rec)
	}
	// RETENTION PRECONDITION for both sweeps below (Codex round 7, P2).
	//
	// Both rules read an unmatched record as a ledger fault. That is sound only for a
	// COMPLETE ledger, and the spool does not guarantee one: send intents, terminal
	// outcomes and reconciliation records are all CritOrdinary, so all three land in
	// P-ORD, and reclamation (internal/mcp/events/spool/reclaim.go) deletes whole
	// SEALED P-ORD segments oldest-first with no relational retention — it does not
	// co-retain later records belonging to an attempt whose intent it is dropping. A
	// legitimately retained SUFFIX can therefore hold an outcome or a reconciliation
	// record whose intent was reclaimed, and these sweeps would call that corruption.
	//
	// The two cases are NOT equally exposed, and the reconciliation one is the safer
	// of the pair today: nothing in production commits a PhaseReconciliation event
	// (the authoritative witness adapter is unwired — blocker #8), whereas outcomes
	// have a producer on every executed attempt. The outcome sweep is the reachable
	// one.
	//
	// This is DELIBERATELY not resolved here. Distinguishing "reclaimed" from
	// "unauthorized" needs information the read seam does not carry — a retention
	// floor or a tombstone — and reclamation removes a PREFIX, so no in-band ordering
	// argument recovers it: if an intent was reclaimed then every surviving record is
	// newer than it, which is consistent with both explanations. Adding that capability
	// is spool work belonging to the witness integration (blockers #1/#8), and
	// weakening these rules to a report would trade a detection that catches an
	// invocation with no durable authorization for an availability property no caller
	// needs yet: RecoverAttempts has NO production caller. So the fail-closed rules
	// stand, and the precondition is recorded rather than assumed.
	//
	// WIRING RecoverAttempts INTO PRODUCTION REQUIRES CLOSING THIS FIRST: either
	// relational retention (never reclaim an intent while later records for its
	// attempt survive) or a retention floor on EvidenceReader that lets these sweeps
	// tell a reclaimed prefix from a missing authorization. Pinned by
	// TestRecovery_UnmatchedRecordRulesAssumeAnUnreclaimedLedger.
	//
	// A terminal outcome with no intent means a physical effect was recorded that no
	// durable authorization covers. That is the most serious ledger fault of all.
	for id := range idx.outcomes {
		if _, ok := idx.intents[id]; !ok {
			return RecoveryReport{}, mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "terminal outcome without a matching send intent")
		}
	}
	// The SAME rule for reconciliation evidence, for the same reason. The loop above
	// iterates INTENTS, so a reconciliation record whose AttemptID matches no intent
	// was never examined by anything: recovery returned a clean, empty report while
	// the ledger held an authoritative claim about an invocation that no durable
	// authorization covers. Silence there is the failure mode this whole file exists
	// to remove — an unmatched witness claim is either a defect in whatever produced
	// it or evidence of an invocation Culvert never authorized, and both are reasons
	// to stop, not to report nothing.
	for id := range idx.recon {
		if _, ok := idx.intents[id]; !ok {
			return RecoveryReport{}, mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "reconciliation evidence without a matching send intent")
		}
	}
	return rep, nil
}

// orphanFrom builds the record for an intent with no terminal outcome.
//
// An orphan's KNOWLEDGE state comes from append-only reconciliation evidence when
// any exists; with none it rests at ReconRequired. Its EXECUTION state is unchanged
// either way: reconciliation changes knowledge, never authority.
//
// The evidence must describe the SAME AUTHORIZATION as the intent. An attempt id
// alone is not enough — a well-formed `reconciled_not_received` record naming a
// different reservation or generation would DOWNGRADE this orphan's uncertainty on
// the strength of a claim about some other execution. That is the same binding rule
// already enforced for terminal outcomes, and its absence here was a real gap
// (Codex round 1, P1). A mismatch fails CLOSED rather than being ignored: silently
// discarding it would leave an unexplained record in the ledger.
func orphanFrom(intent *model.OutcomeEvidence, ev *model.ReconciliationEvidence) (RecoveredAttempt, error) {
	known := model.ReconRequired
	if ev != nil {
		if ev.ReservationID != intent.ReservationID {
			return RecoveredAttempt{}, mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "reconciliation reservation mismatch against the send intent")
		}
		if ev.ActivationGeneration != intent.ActivationGeneration {
			return RecoveredAttempt{}, mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "reconciliation generation mismatch against the send intent")
		}
		known = ev.Result
	}
	if known == "" {
		known = model.ReconRequired
	}
	return RecoveredAttempt{
		AttemptID:            intent.AttemptID,
		ReservationID:        intent.ReservationID,
		ActivationGeneration: intent.ActivationGeneration,
		State:                AttemptReconciliationRequired,
		Reconciliation:       known,
	}, nil
}

// settledFrom builds the record for an intent that reached a terminal outcome.
//
// The outcome must describe the SAME authorization as the intent. A mismatch means
// the ledger binds one physical effect to two different grants or generations, which
// no later reasoning can safely repair.
//
// Reconciliation evidence for a settled attempt is UNUSUAL but reachable — a late
// terminal outcome racing an orphan reconciliation leaves both in the stream — and
// it was previously ignored entirely, because only the orphan branch consulted the
// index (Codex round 4, P2). Ignoring it discards one of two authoritative claims
// about the same physical effect and reports the attempt as cleanly settled, so a
// witness saying "never received" alongside an outcome saying the peer ANSWERED
// would vanish from the report. Both claims are checked here instead.
func settledFrom(intent, out *model.OutcomeEvidence, recon *model.ReconciliationEvidence) (RecoveredAttempt, error) {
	if out.ReservationID != intent.ReservationID {
		return RecoveredAttempt{}, mcperr.New(mcperr.ReasonEventInvalid,
			"execution.recovery", "attempt reservation mismatch between intent and outcome")
	}
	if out.ActivationGeneration != intent.ActivationGeneration {
		return RecoveredAttempt{}, mcperr.New(mcperr.ReasonEventInvalid,
			"execution.recovery", "attempt generation mismatch between intent and outcome")
	}
	if !out.PhysicalSendState.Valid() {
		return RecoveredAttempt{}, mcperr.New(mcperr.ReasonEventInvalid,
			"execution.recovery", "terminal outcome with unknown physical send state")
	}
	if err := settledReconOK(intent, out, recon); err != nil {
		return RecoveredAttempt{}, err
	}
	return RecoveredAttempt{
		AttemptID:            intent.AttemptID,
		ReservationID:        intent.ReservationID,
		ActivationGeneration: intent.ActivationGeneration,
		State:                AttemptSettled,
		TerminalSendState:    out.PhysicalSendState,
	}, nil
}

// settledReconOK fails CLOSED when reconciliation evidence cannot stand beside the
// terminal outcome for the same attempt.
//
// Three ways it cannot. The binding rule is the same one the orphan path enforces:
// evidence naming a different reservation or generation describes some other
// execution. A witness-observed DUPLICATE is the blocker-#6 invariant breach itself
// and must never be reported as a clean settled attempt. And a witness asserting the
// invocation was never received, against an outcome recording that the peer may have
// or demonstrably did receive it, is a direct contradiction about one physical
// effect — exactly the case where picking a winner would be manufacturing certainty.
//
// ReconRequired asserts nothing and is therefore never a contradiction, and
// ReconReceived agreeing with a send state that reached the peer is simply
// corroboration.
func settledReconOK(intent, out *model.OutcomeEvidence, recon *model.ReconciliationEvidence) error {
	if recon == nil {
		return nil
	}
	if recon.ReservationID != intent.ReservationID {
		return mcperr.New(mcperr.ReasonEventInvalid,
			"execution.recovery", "reconciliation reservation mismatch against a settled attempt")
	}
	if recon.ActivationGeneration != intent.ActivationGeneration {
		return mcperr.New(mcperr.ReasonEventInvalid,
			"execution.recovery", "reconciliation generation mismatch against a settled attempt")
	}
	switch recon.Result {
	case model.ReconConflict:
		return mcperr.New(mcperr.ReasonEventInvalid,
			"execution.recovery", "witness reported a duplicate invocation for a settled attempt")
	case model.ReconNotReceived:
		if out.PhysicalSendState.MayHaveReachedPeer() {
			return mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "witness reported not-received against an outcome that reached the peer")
		}
	case model.ReconReceived:
		// TWO states positively prove the peer was not reached, not one (Codex round
		// 5, P2): definitely_not_sent and reconciled_not_received. Testing only the
		// former let a ledger asserting BOTH receipt and definitive non-receipt pass
		// as cleanly settled. MayHaveReachedPeer is the predicate that owns this
		// distinction, and a settled outcome always carries a valid state — an
		// invalid one is rejected above — so its false branch is exactly "proven not
		// reached" rather than "unknown".
		if !out.PhysicalSendState.MayHaveReachedPeer() {
			return mcperr.New(mcperr.ReasonEventInvalid,
				"execution.recovery", "witness reported received against an outcome that proves the peer was not reached")
		}
	}
	return nil
}
