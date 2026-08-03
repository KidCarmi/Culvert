package rollout

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// TransitionKind classifies a mode change.
type TransitionKind uint8

const (
	// TransitionNone is the zero value (no valid transition classified).
	TransitionNone TransitionKind = iota
	// TransitionPromotion is a one-stage move up the ladder.
	TransitionPromotion
	// TransitionDemotion is a move down the ladder by one or more stages (including
	// an emergency straight to Disabled). It never requires a qualification receipt.
	TransitionDemotion
)

// QualificationBinding is the exact target a Production Qualification receipt must
// bind to. A receipt valid for one capability/scope/snapshot can never authorize a
// different one. It carries only non-secret identifiers.
type QualificationBinding struct {
	Capability      Capability `json:"capability"`
	FromMode        Mode       `json:"from_mode"`
	ToMode          Mode       `json:"to_mode"` // MUST be ModeProduction
	TargetScopeHash string     `json:"target_scope_hash"`
	SnapshotHash    string     `json:"snapshot_hash"`
}

// ProductionQualificationVerifier is the narrow, injected interface that gates
// entry into Production. The separate Production Qualification gate owns the real
// evidence (full shadow/canary windows, soak, defect closure) and issues an
// immutable receipt; this build contains NO issuer that can mint a receipt this
// verifier accepts. A nil verifier ⇒ Production is unreachable (fail closed).
//
// VerifyProductionQualification MUST return nil ONLY for a present, valid receipt
// that binds EXACTLY to the supplied binding (capability + target scope hash +
// snapshot hash). No environment variable, CLI flag, API parameter, signed
// snapshot field, or boolean can substitute for it.
type ProductionQualificationVerifier interface {
	VerifyProductionQualification(binding QualificationBinding) error
}

// TransitionInput fully describes a requested mode change.
type TransitionInput struct {
	Capability Capability
	From       Mode
	To         Mode
	// Qualification is consulted ONLY for a promotion whose target is Production. It
	// is ignored for every other transition. nil ⇒ Production is unreachable.
	Qualification ProductionQualificationVerifier
	// Binding is required (and only used) when To == ModeProduction. It binds the
	// receipt to the exact capability/scope/snapshot being promoted.
	Binding QualificationBinding
}

// Promotable reports whether to is exactly one stage above from.
func Promotable(from, to Mode) bool {
	return from.Valid() && to.Valid() && to.Rank() == from.Rank()+1
}

// Demotable reports whether to is strictly below from (any number of stages).
func Demotable(from, to Mode) bool {
	return from.Valid() && to.Valid() && to.Rank() < from.Rank()
}

// CheckTransition is the single authoritative gate for a mode change. It returns
// the classified kind and a nil error only for an allowed transition; otherwise a
// classified, fail-closed error. It is pure (no I/O, no clock) except for the
// injected qualification verifier, which is consulted exactly once and only for a
// Production promotion.
//
// Rules (ROLLOUT-AND-ROLLBACK.md §1, §3):
//   - promotion is strictly one stage at a time (Disabled→Observe→Shadow→Canary→
//     Production); any skip (Disabled→Shadow, Observe→Canary, Shadow→Production) is
//     rejected;
//   - Canary→Production requires a valid Production Qualification receipt;
//   - demotion may narrow by one or more stages and never needs a receipt;
//   - a no-op (To == From) is not a transition — use a scope update instead;
//   - an unknown/future mode is rejected.
func CheckTransition(in TransitionInput) (TransitionKind, error) {
	if !in.From.Valid() || !in.To.Valid() {
		return TransitionNone, mcperr.New(mcperr.ReasonRolloutModeInvalid, "rollout.transition", "unknown mode in transition")
	}
	if in.To == in.From {
		return TransitionNone, mcperr.New(mcperr.ReasonRolloutTransitionInvalid, "rollout.transition", "mode unchanged; use a scope update, not a transition")
	}
	if in.To.Rank() < in.From.Rank() {
		// Demotion: any number of stages down, never gated by qualification.
		return TransitionDemotion, nil
	}
	// Promotion: must be exactly one stage.
	if in.To.Rank() != in.From.Rank()+1 {
		return TransitionNone, mcperr.New(mcperr.ReasonRolloutTransitionInvalid, "rollout.transition", "promotion must advance exactly one stage")
	}
	if in.To == ModeProduction {
		if err := checkProductionQualification(in); err != nil {
			return TransitionNone, err
		}
	}
	return TransitionPromotion, nil
}

// checkProductionQualification enforces the Production lockout. It is the ONLY
// path into Production and it fails closed on a missing verifier, a binding that
// does not target Production, or a receipt the verifier rejects.
func checkProductionQualification(in TransitionInput) error {
	if in.Qualification == nil {
		return mcperr.New(mcperr.ReasonRolloutProductionLocked, "rollout.transition", "production requires a qualification receipt (none configured)")
	}
	b := in.Binding
	// The binding must itself describe this exact promotion; a caller cannot pass a
	// binding for a different capability/target and have it accepted.
	if b.Capability != in.Capability || b.ToMode != ModeProduction || b.FromMode != in.From {
		return mcperr.New(mcperr.ReasonRolloutQualificationInvalid, "rollout.transition", "qualification binding does not match this promotion")
	}
	if b.TargetScopeHash == "" || b.SnapshotHash == "" {
		return mcperr.New(mcperr.ReasonRolloutQualificationInvalid, "rollout.transition", "qualification binding missing scope/snapshot hash")
	}
	if err := in.Qualification.VerifyProductionQualification(b); err != nil {
		// Preserve a classified reason; default to the locked reason.
		if mcperr.ReasonOf(err) == mcperr.ReasonNone {
			return mcperr.Wrap(mcperr.ReasonRolloutQualificationInvalid, "rollout.transition", "qualification receipt rejected", err)
		}
		return err
	}
	return nil
}

// EmergencyTarget returns the safe demotion target for an emergency narrowing of
// mode: one stage down, except an explicit disable goes straight to Disabled. It
// never returns a mode above from.
func EmergencyTarget(from Mode, disable bool) Mode {
	if disable || !from.Valid() || from == ModeDisabled {
		return ModeDisabled
	}
	return Mode(from.Rank() - 1)
}
