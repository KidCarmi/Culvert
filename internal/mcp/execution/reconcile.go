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
	if orphan.State != AttemptReconciliationRequired {
		// Only an orphan enters reconciliation. A settled attempt already has a
		// terminal outcome; re-deriving it here would be an evidence audit, not
		// execution recovery, and must be requested explicitly.
		return model.ReconciliationEvidence{}, mcperr.New(mcperr.ReasonEventInvalid,
			"execution.reconcile", "only an orphaned attempt may be reconciled")
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
	ev.ObservationCount = obs.Count
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
		return model.ReconConflict
	}
	if obs.Count == 1 {
		// The observation must be consistent with the durable intent. An id match
		// alone is not enough: an invocation attributed to the wrong server, method
		// or reservation is contradictory evidence, not a success.
		if !bindingConsistent(obs, orphan, expectServer, expectMethod) {
			return model.ReconConflict
		}
		return model.ReconReceived
	}
	// Count == 0. Absence is only meaningful if the witness proved its view complete.
	if obs.Complete && obs.CompletenessWatermark != "" {
		return model.ReconNotReceived
	}
	return model.ReconRequired
}

// bindingConsistent checks the observation against the durable intent on every
// dimension the witness reported. An empty witness field means "not reported" and
// is not treated as a mismatch; a non-empty field that disagrees is.
func bindingConsistent(obs WitnessObservation, orphan RecoveredAttempt, expectServer, expectMethod string) bool {
	if obs.ReservationID != "" && orphan.ReservationID != "" && obs.ReservationID != orphan.ReservationID {
		return false
	}
	if obs.ServerID != "" && expectServer != "" && obs.ServerID != expectServer {
		return false
	}
	if obs.Method != "" && expectMethod != "" && obs.Method != expectMethod {
		return false
	}
	return true
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
