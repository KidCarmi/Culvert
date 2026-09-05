package execution

// reconcile.go — typed independent-witness reconciliation by AttemptID
// (First Controlled Canary review §11).
//
// The whole point of this file is that Culvert cannot answer, from its own
// records alone, whether a crashed attempt reached the peer. Only an independently
// controlled observer can. So the contract is built to make the OBSERVER supply
// facts and the ENGINE derive the verdict — never the other way round.
//
// There is deliberately no API shaped like Reconcile(attemptID, received bool):
// that would turn an operator or client assertion into execution truth, which is
// exactly the property the First Canary must not have.

import (
	"context"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// WitnessObservation is what an independently controlled witness REPORTS. It is
// facts only: how many matching invocations it saw, what it can prove about the
// completeness of its own view, and what binding metadata it recorded. It carries
// no verdict, because a verdict from the witness would be an assertion this engine
// must not simply trust.
type WitnessObservation struct {
	// Count is the number of physical invocations the witness recorded for this
	// AttemptID. Retained verbatim: >1 is a physical-effect breach, not a duplicate
	// to be normalized away.
	Count int
	// Complete reports whether the witness can PROVE its observation set is complete
	// for the relevant interval. Absence from an incomplete log proves nothing.
	Complete bool
	// CompletenessWatermark is the evidence backing Complete — a durable monotonic
	// watermark, closed window, or authoritative sequence boundary. Required for a
	// definitive "not received".
	CompletenessWatermark string
	// Binding metadata the witness observed, used to confirm the observation really
	// belongs to this attempt rather than merely sharing its id.
	ServerID      string
	Method        string
	ReservationID string
	// Source identifies the witness, so an audit can tell whose evidence this was.
	Source string
	// WindowStartUnixNano / WindowEndUnixNano bound the observed interval.
	WindowStartUnixNano int64
	WindowEndUnixNano   int64
	ObservedAtUnixNano  int64
	// EvidenceDigest is a bounded, non-reversible reference to the underlying record.
	EvidenceDigest string
}

// Witness is the narrow authoritative lookup seam. The PRODUCTION implementation
// belongs to the controlled-upstream work (review blocker #1) and is deliberately
// unwired here; this PR establishes the contract and proves it against controlled
// infrastructure.
type Witness interface {
	LookupAttempt(ctx context.Context, attemptID string) (WitnessObservation, error)
}

// ReconcileOrphan derives authoritative knowledge about one recovered orphan.
//
// It never manufactures certainty. A witness that is unavailable, times out,
// returns malformed data, or cannot prove completeness leaves the attempt at
// reconciliation_required — the resting state — rather than producing a verdict the
// evidence does not support.
func ReconcileOrphan(ctx context.Context, w Witness, orphan RecoveredAttempt, expectServer, expectMethod string, now int64) (model.ReconciliationEvidence, error) {
	if !orphan.NeedsReconciliation() {
		// The gate is UNRESOLVED KNOWLEDGE, not the absence of a terminal outcome
		// (Codex round 8, P1). It used to be `State != AttemptReconciliationRequired`,
		// which reads "settled" as "known" — and those are different questions. An
		// upstream POST that ended without a response is SETTLED as to execution
		// authority and records may_have_been_sent, whose own ReconciliationRequired()
		// answers true; gating on State made the single most important case a witness
		// exists for permanently unreconcilable.
		//
		// It refuses in the other direction too, and that direction is a safety
		// property rather than a convenience: once a witness has RESOLVED an attempt,
		// asking again can only move knowledge backwards — a witness outage answers
		// reconciliation_required, and the append-only ledger rightly refuses that
		// downgrade, so the query would turn a healthy resolved attempt into a recovery
		// failure.
		return model.ReconciliationEvidence{}, mcperr.New(mcperr.ReasonEventInvalid,
			"execution.reconcile", "attempt does not require reconciliation")
	}
	ev := model.ReconciliationEvidence{
		AttemptID:            orphan.AttemptID,
		ReservationID:        orphan.ReservationID,
		ActivationGeneration: orphan.ActivationGeneration,
		Result:               model.ReconRequired,
		ReconciledAtUnixNano: now,
	}
	if w == nil {
		// No witness wired ⇒ no knowledge gained. This is the shipped posture.
		return ev, nil
	}
	obs, err := w.LookupAttempt(ctx, orphan.AttemptID)
	if err != nil {
		// Unavailable / timeout / malformed. Knowledge is unchanged, and that is the
		// correct outcome — not "not received".
		return ev, nil
	}
	ev.WitnessSource = obs.Source
	// A NEGATIVE count is not an observation, it is malformed input — and the durable
	// validator rejects it for every verdict, so copying it verbatim produced a
	// fail-closed record that could not be committed to the append-only ledger at all
	// (Codex round 8, P2). The count is omitted rather than recorded as a falsehood;
	// what the record still says is exactly what is true — a witness was consulted
	// (WitnessSource, EvidenceDigest) and resolved nothing (ReconRequired).
	if obs.Count > 0 {
		ev.ObservationCount = obs.Count
	}
	ev.WindowStartUnixNano, ev.WindowEndUnixNano = obs.WindowStartUnixNano, obs.WindowEndUnixNano
	ev.ObservedAtUnixNano = obs.ObservedAtUnixNano
	ev.EvidenceDigest = obs.EvidenceDigest
	if obs.Complete {
		ev.CompletenessWatermark = obs.CompletenessWatermark
	}
	ev.Result = deriveReconResult(obs, orphan, expectServer, expectMethod)
	return ev, nil
}

// deriveReconResult is the state derivation, kept separate so it is directly
// testable and so the precedence is visible in one place.
//
// Precedence is deliberate: a CONFLICT outranks everything. A duplicate physical
// invocation or a contradictory binding is a breach of the exactly-one invariant,
// and reporting it as "received" would hide the very thing blocker #6 exists to
// prevent.
func deriveReconResult(obs WitnessObservation, orphan RecoveredAttempt, expectServer, expectMethod string) model.ReconciliationResult {
	// A NEGATIVE count is impossible for a well-formed witness, so it is malformed
	// data, not an observation. Left to fall through it would miss both the >1 and
	// ==1 branches and be read as zero — turning garbage into a definitive "never
	// happened", the one direction this engine must never manufacture (Codex round 1,
	// P1). It resolves nothing and rests at reconciliation_required.
	if obs.Count < 0 {
		return model.ReconRequired
	}
	if obs.Count > 1 {
		// More than one observed invocation is a breach however partial the view is:
		// a duplicate seen is a duplicate, and a wider view could only find more.
		return model.ReconConflict
	}
	if obs.Count == 1 {
		// The observation must be consistent with the durable intent. An id match
		// alone is not enough: an invocation attributed to the wrong server, method
		// or reservation is contradictory evidence, not a success.
		if bindingContradicts(obs, orphan, expectServer, expectMethod) {
			return model.ReconConflict
		}
		// EXACTLY one is a claim about the whole population, so it needs the same
		// completeness proof absence does (Codex round 4, P1). Requiring it for
		// "never happened" but not for "happened exactly once" was an asymmetry with
		// a real consequence: ReconReceived is defined as exactly one and is treated
		// as RESOLVED, so a partial view containing one invocation would settle an
		// attempt whose duplicate simply lay outside the observed set — hiding the
		// precise thing blocker #6 exists to detect. An incomplete view resolves
		// nothing; the count it did report is still on the evidence for an operator.
		if !obs.Complete || obs.CompletenessWatermark == "" {
			return model.ReconRequired
		}
		if !bindingCorroborated(obs, orphan, expectServer, expectMethod) {
			return model.ReconRequired
		}
		return model.ReconReceived
	}
	// Count == 0. Absence is only meaningful if the witness proved its view complete
	// AND the view it proved is the one this attempt was authorized under.
	//
	// The binding check was originally on the Count==1 branch only (Codex round 3,
	// P1), which left the more dangerous direction open: a witness reporting a
	// COMPLETE view of a DIFFERENT reservation, server or method, with zero
	// invocations in it, resolved this attempt to "never happened". That is not
	// contradictory evidence, it is INAPPLICABLE evidence — an answer to a question
	// nobody asked — and turning it into definitive absence is the one direction this
	// engine must never manufacture. It was invisible downstream too, because
	// ReconcileOrphan records the orphan's OWN reservation on the evidence, so
	// recovery's binding check compared a value against itself.
	//
	// The verdict is ReconRequired, deliberately NOT ReconConflict: a conflict
	// asserts a breach of the exactly-once invariant, and zero observations of some
	// other authorization is no evidence of a breach. Reporting one would manufacture
	// an alarm from inapplicable data — the mirror of manufacturing absence — and
	// would be the easier direction for a misdirected or hostile witness to trigger.
	// Knowledge is simply unchanged, which is what the resting state means.
	if obs.Complete && obs.CompletenessWatermark != "" && bindingCorroborated(obs, orphan, expectServer, expectMethod) {
		return model.ReconNotReceived
	}
	return model.ReconRequired
}

// bindingContradicts reports whether the observation DISAGREES with the durable
// intent on a dimension both sides name. It is the CONFLICT test: only a dimension
// reported by both, with different values, is contradictory evidence.
func bindingContradicts(obs WitnessObservation, orphan RecoveredAttempt, expectServer, expectMethod string) bool {
	return disagrees(obs.ReservationID, orphan.ReservationID) ||
		disagrees(obs.ServerID, expectServer) ||
		disagrees(obs.Method, expectMethod)
}

// bindingCorroborated reports whether EVERY dimension the witness names is
// confirmed by a matching, non-empty local value. It is the test for accepting
// RESOLVED knowledge, and it is deliberately stricter than bindingContradicts.
//
// The difference is the case where the witness names a dimension the local intent
// leaves empty — a legacy or nil-gate orphan with no durable ReservationID, say
// (Codex round 4, P2). "Not reported" was being read as "agrees", so a witness could
// present a complete, zero-count view SCOPED TO SOME OTHER AUTHORIZATION and have it
// resolve this unbound orphan to "never happened". Nothing contradicted, but nothing
// corroborated either, and an uncorroborated claim must not become resolved
// knowledge in either direction.
//
// Not contradicting is a weaker property than applying to this attempt, and only the
// stronger one can settle a question.
func bindingCorroborated(obs WitnessObservation, orphan RecoveredAttempt, expectServer, expectMethod string) bool {
	return corroborates(obs.ReservationID, orphan.ReservationID) &&
		corroborates(obs.ServerID, expectServer) &&
		corroborates(obs.Method, expectMethod)
}

// disagrees reports whether both sides named the dimension and named it differently.
func disagrees(observed, expected string) bool {
	return observed != "" && expected != "" && observed != expected
}

// corroborates reports whether an observed dimension is confirmed locally. A
// dimension the witness did not report corroborates nothing but contradicts nothing,
// so it is permitted; one it DID report must match a known local value.
func corroborates(observed, expected string) bool {
	if observed == "" {
		return true
	}
	return expected != "" && observed == expected
}

// ReconcileTransitionAllowed pins the state machine (§9). Reconciliation only ever
// moves an attempt from reconciliation_required to a knowledge state, and there is
// NO transition back to executable — the recovery/reconciliation surfaces expose no
// execution capability at all.
func ReconcileTransitionAllowed(from, to model.ReconciliationResult) bool {
	if from != model.ReconRequired {
		// Already resolved. Re-deriving the SAME result is idempotent (handled by the
		// caller); anything else is a contradiction that must fail closed loudly.
		return to == from
	}
	return to.Valid()
}
