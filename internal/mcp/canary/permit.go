package canary

import "github.com/KidCarmi/Culvert/internal/mcp/policy"

// EXACT FIRST-CANARY POLICY PERMIT (blocker #14).
//
// The readiness table already proves the target is scoped, reviewed, approved, fingerprint-
// current and catalog-usable. None of that says the exact request RESOLVES to a decision that
// can execute. The only policy row was PolicyHealthy, which is `mcpPolicy.composed()` — a
// snapshot EXISTS. A node could satisfy every other row and still have every request answered
// DENY (no rule matched → default deny), QUARANTINE, REQUIRE_APPROVAL, or an allow-class action
// whose obligation nothing on this node can satisfy.
//
// This file is the PURE half: given the real engine's Decision + ExplainTrace for the exact
// constructed tuple, it decides whether that verdict is an EXECUTABLE PERMIT, and — the part
// that makes it a proof rather than a sample — whether the verdict is INVARIANT over every
// field the activation does not bind.
//
// It decides only. It evaluates nothing, holds no engine, reads no state, and can never permit
// anything: its output is one bounded reason consumed by the readiness table.

// PermitReason is the bounded classification of WHY the exact First-Canary decision is not an
// executable permit. It is a fixed vocabulary — no tenant, rule body, host, or error text ever
// appears — so it is safe on the read-only operator surface. PermitOK is the empty value.
type PermitReason string

const (
	// PermitOK — the exact decision is a plain, executable, invariant ALLOW.
	PermitOK PermitReason = ""
	// PermitTupleUnavailable — the exact decision tuple could not be built from authoritative
	// state (no policy snapshot, no inventory, no reviewed class). Nothing was evaluated.
	PermitTupleUnavailable PermitReason = "exact_tuple_unavailable"
	// PermitEvaluationFailed — the engine returned an error: a structurally invalid tuple or an
	// unavailable snapshot. Distinct from a valid tuple that no rule matched.
	PermitEvaluationFailed PermitReason = "policy_evaluation_failed"
	// PermitHardOverride — a hard security override fired (tenant mismatch, server identity
	// changed, server disabled, unknown/quarantined tool, privilege expansion, invalid input).
	// No operator rule can lift it, so the request can never execute.
	PermitHardOverride PermitReason = "policy_hard_override"
	// PermitNoMatchedRule — no enabled rule matched; the engine fell through to default deny.
	PermitNoMatchedRule PermitReason = "policy_no_matched_rule"
	// PermitActionNotPlainAllow — a rule matched but its action is not a plain ALLOW. See
	// FirstCanaryRequiresPlainAllow for why the First Canary refuses the other allow-class
	// actions rather than accepting Action.IsAllowClass().
	PermitActionNotPlainAllow PermitReason = "policy_action_not_plain_allow"
	// PermitOperationClassNotReadFirst — the operation class the tuple carried is not the
	// read/discovery band. A write-class permit is not a First-Canary permit whatever the rule says.
	PermitOperationClassNotReadFirst PermitReason = "policy_operation_class_not_read_first"
	// PermitObligationNotSatisfiable — the matched ALLOW carries an obligation this node cannot
	// satisfy for this execution, or one whose satisfaction cannot be established before the call.
	PermitObligationNotSatisfiable PermitReason = "policy_obligation_not_satisfiable"
	// PermitVerdictNotInvariant — the verdict was decided by at least one policy field the
	// activation does not BIND, so it holds for the constructed tuple and not for every request
	// the scope admits. See PermitBoundFields.
	PermitVerdictNotInvariant PermitReason = "policy_verdict_not_invariant"
	// PermitCapabilityMismatch — the decision the engine stamped is not for the Gateway
	// capability the Canary executes under.
	PermitCapabilityMismatch PermitReason = "policy_capability_mismatch"
)

// AllPermitReasons returns the complete permit vocabulary in canonical order, so a test can
// prove every reason is reachable and the operator surface can advertise the full list.
func AllPermitReasons() []PermitReason {
	return []PermitReason{
		PermitTupleUnavailable,
		PermitEvaluationFailed,
		PermitHardOverride,
		PermitNoMatchedRule,
		PermitActionNotPlainAllow,
		PermitOperationClassNotReadFirst,
		PermitObligationNotSatisfiable,
		PermitVerdictNotInvariant,
		PermitCapabilityMismatch,
	}
}

// FirstCanaryRequiresPlainAllow documents, in one place, why the permit demands exactly
// policy.ActionAllow rather than Action.IsAllowClass(). Each of the other four allow-class
// actions reaches rollout.EffectExecute and is then gated by state this preflight CANNOT
// observe, or is not executed at all:
//
//   - MONITOR maps to rollout.ActionKindAllow (execution/mapping.go) and therefore DOES perform
//     the real upstream call under Canary — despite the action's own doc calling it
//     "non-blocking policy intent; still no upstream execution". A first experiment must not
//     rest on a documented/behavioural divergence.
//   - ALLOW_ONCE and ALLOW_FOR_SESSION resolve to EffectExecute and are gated afterwards by the
//     executor's in-memory allowance store (`e.allowances.consume`). Whether the allowance is
//     available at call time is runtime state that does not exist at activation.
//   - ALLOW_WITH_REDACTION resolves to EffectExecute and is then unconditionally blocked by the
//     guarded path (ReasonRedactionFailed), because request-argument redaction is not performed
//     there — so it is executable in name and never in fact.
//
// A stronger later Canary may support them, each with its own runtime-state proof. The first one
// needs ONE boring, statically provable path.
const FirstCanaryRequiresPlainAllow = "policy.ActionAllow"

// PermitBoundFields is the CLOSED set of policy fields the activation BINDS: fields whose value
// is fixed for every request the exact First-Canary scope admits, and is derived from
// authoritative node state (the signed scope, the registry record, the catalog record, the
// reviewed operation class) rather than from the request.
//
// It is the heart of the invariance argument. The preflight evaluates ONE constructed tuple; it
// must choose values for the fields a real request would carry (its groups, assurance, client,
// session, inspection evidence). If the winning rule — or the rejection of any rule considered
// before it — depended on one of those, the verdict is true of the constructed tuple and says
// nothing about the actual traffic. Requiring every decisive field to be in this set is what
// makes the permit a statement about the EXPERIMENT rather than about one imagined request.
//
// Membership is deliberately narrow, and a field is in it only when BOTH halves hold:
//
//  1. the exact scope pins it (tenant, principal, server, tool) or the authoritative inventory
//     supplies it (the registry record's owner/enabled/verification, the catalog record's
//     fingerprint/disposition/drift/destination), AND
//  2. the request cannot vary it — the runtime derives the same value from the same snapshot
//     for every in-scope request.
//
// `capability` is bound because a Canary is Gateway-only (ReasonCapabilityNotGateway).
// `operation.*` is bound because the experiment is one tools/call of one tool, whose class comes
// from the reviewed four-eyes approval and is classified exactly once (blocker #4).
//
// Everything else is UNBOUND — principal.kind/issuer/groups/assurance/sender_*, agent.*,
// client.*, session.*, inspection.*, resource.*, destination.*, credential.*, time, and the
// catalog fields the runtime's tuple builder never populates (tool.risk, tool.credential_power,
// tool.reversibility). The last group matters: they are ZERO on every real request, so a rule
// keyed on one of them is matching a value the runtime never supplies, and certifying that as a
// permit would certify a rule that cannot mean what its author intended.
func PermitBoundFields() []string {
	return []string{
		"capability",
		"operation.class",
		"operation.method",
		"operation.namespace",
		"operation.operand",
		"operation.point",
		"principal.subject",
		"principal.tenant",
		"server.enabled",
		"server.environment",
		"server.id",
		"server.owner",
		"server.verification",
		"tool.destination",
		"tool.disposition",
		"tool.drift",
		"tool.fingerprint",
		"tool.name",
	}
}

// permitBoundFieldSet is the sorted lookup form of PermitBoundFields.
var permitBoundFieldSet = func() map[string]struct{} {
	f := PermitBoundFields()
	m := make(map[string]struct{}, len(f))
	for _, k := range f {
		m[k] = struct{}{}
	}
	return m
}()

// PermitInput is everything the pure verdict needs about ONE evaluation of the exact tuple by
// the REAL shared engine. The caller supplies the engine's own outputs verbatim — it never
// re-derives a verdict, and there is no second evaluator.
type PermitInput struct {
	// TupleBuilt reports that the exact decision tuple could be constructed from authoritative
	// state at all. False ⇒ PermitTupleUnavailable; nothing below is read.
	TupleBuilt bool
	// EvalErr reports that Engine.Evaluate returned a non-nil error for this tuple.
	EvalErr bool
	// Decision and Trace are the engine's outputs, unmodified.
	Decision policy.Decision
	Trace    policy.ExplainTrace
	// WinnerConditionFields is Rule.ConditionFields() for the rule the engine named as winner,
	// read from the SAME snapshot the decision came from. Nil for a rule with no conditions
	// (which matches every input of its namespace and therefore reads nothing).
	WinnerConditionFields []string
	// WinnerResolved reports that the caller actually located the winning rule in the snapshot.
	// False with a non-empty MatchedRule means the snapshot and the decision disagree, which is
	// not a permit: the fields the winner read are then unknown, and unknown is never satisfied.
	WinnerResolved bool
	// OperationClass is the class the evaluated tuple carried — the reviewed, four-eyes class
	// bound to this exact fingerprint (blocker #4), never a default.
	OperationClass policy.OperationClass
}

// EvaluateExactPermit returns PermitOK when the exact First-Canary decision is an executable
// permit, else the single bounded reason it is not. It is PURE: same input ⇒ same verdict, no
// I/O, no clock.
//
// Order is fail-closed and each check is independent — no check can substitute for another:
//
//  1. the tuple was built at all;
//  2. the engine did not error (invalid input / no snapshot);
//  3. the decision is for the Gateway capability;
//  4. the evaluated operation class is read-first;
//  5. no hard override fired;
//  6. a rule actually matched (not default deny);
//  7. that rule's action is a plain ALLOW;
//  8. every obligation on the matched rule is satisfiable here;
//  9. the verdict is invariant over every unbound field.
//
// THE CLASS IS CHECKED BEFORE THE HARD OVERRIDE, AND THAT ORDER IS LOAD-BEARING. It is not a
// preference about which refusal reads better — it is what completes the invariance argument,
// which permitVerdictInvariant covers only for the RULE LOOP.
//
// The engine's hard-override band runs first and is not a rule, so its inputs are outside that
// check. Almost all of them are bound fields (the resource tenant — the tuple carries no
// resource; the capability; the server's owner, verification and enabled state; the tool's drift
// and disposition). ONE is not: subjectOverride denies a WRITE-or-higher operation whose
// principal assurance is unknown (MCP-ID-005), and `principal.assurance` is request-variable and
// therefore unbound. A preflight tuple must choose an assurance, so for a write-class tuple the
// hard override's verdict would depend on that choice.
//
// Requiring the class to be read-first FIRST makes that branch unreachable — `writeOrHigher` is
// false for OpRead and OpDiscovery, so the assurance is never read — and with it unreachable,
// EVERY remaining hard override is decided by bound fields alone. The two checks together are
// what make the whole verdict, override band included, invariant over the unbound fields.
//
// Pinned by TestPermitE2E_WriteClassIsNotAPermit, which fails against the other order: the
// engine answers a write-class tuple with ReasonIdentityAmbiguous, so the override fires and the
// class check is never reached.
func EvaluateExactPermit(in PermitInput) PermitReason {
	if !in.TupleBuilt {
		return PermitTupleUnavailable
	}
	if in.EvalErr {
		return PermitEvaluationFailed
	}
	if in.Decision.Capability != policy.CapGateway {
		return PermitCapabilityMismatch
	}
	if !permitReadFirstClass(in.OperationClass) {
		return PermitOperationClassNotReadFirst
	}
	// A hard override dominates every operator rule, so a matched ALLOW beside one is not a
	// permit. Checked BEFORE the matched-rule test because the destructive-contract downgrade
	// and the override paths both leave a decision that looks partially rule-shaped.
	if in.Decision.HardOverride {
		return PermitHardOverride
	}
	if in.Decision.MatchedRule == "" {
		return PermitNoMatchedRule
	}
	if in.Decision.Action != policy.ActionAllow {
		return PermitActionNotPlainAllow
	}
	if r := permitObligationsSatisfiable(in.Decision.Obligations); r != PermitOK {
		return r
	}
	return permitVerdictInvariant(in)
}

// permitReadFirstClass reports whether the class is the read/discovery band. It mirrors the
// scope-level read-first band; a write/destructive/control class is never a First-Canary permit
// even when a rule would allow it.
func permitReadFirstClass(c policy.OperationClass) bool {
	return c == policy.OpRead || c == policy.OpDiscovery
}

// permitVerdictInvariant proves the verdict does not depend on a field the activation leaves
// unbound. Two things must hold, and together they are exhaustive over the engine's rule loop:
//
//   - every rule CONSIDERED and rejected before the winner was rejected on a BOUND field, so its
//     rejection holds for every assignment of the unbound fields (the engine reports the FIRST
//     failing condition, so naming a bound field means a bound field decided it); and
//   - the WINNER read only bound fields, so it still matches under every such assignment.
//
// Given both, the same rule wins with the same action for every request the scope admits, which
// is exactly the claim "the exact First-Canary request resolves to an executable permit".
//
// A rule rejected for EXPIRY is rejected on the tuple's EvalTime, which is neither bound nor
// request-variable — it is the clock. That is reported as not-invariant rather than accepted:
// a rule that expires mid-window would change the verdict, and a permit must not be certified
// against a rulebase whose outcome has a scheduled change built into it.
func permitVerdictInvariant(in PermitInput) PermitReason {
	if !in.WinnerResolved {
		// The decision named a rule the snapshot does not contain. The fields it read are
		// unknowable, and an unknown dependency is never satisfied.
		return PermitVerdictNotInvariant
	}
	for _, f := range in.WinnerConditionFields {
		if _, ok := permitBoundFieldSet[f]; !ok {
			return PermitVerdictNotInvariant
		}
	}
	for i := range in.Trace.Entries {
		e := in.Trace.Entries[i]
		if e.Kind != policy.TraceRuleConsidered {
			continue
		}
		f := policy.ConditionField(e.ConditionID)
		if f == "" {
			// "expiry", or a truncated/unnamed condition. Either way the rejection was not
			// shown to rest on a bound field.
			return PermitVerdictNotInvariant
		}
		if _, ok := permitBoundFieldSet[f]; !ok {
			return PermitVerdictNotInvariant
		}
	}
	// A truncated trace has lost entries, so the rules it dropped were never shown to be
	// bound-rejected. Deterministic truncation is a size guard, not a proof.
	if in.Trace.Truncated {
		return PermitVerdictNotInvariant
	}
	return PermitOK
}

// permitObligationsSatisfiable decides §6: not "is the obligation payload well-formed" — the
// compiler already proved that — but "can THIS node satisfy it for THIS execution".
//
// It is a CLOSED ALLOW-LIST. Exactly two obligations may ride the First-Canary ALLOW:
//
//   - Logging and Observation, which are guaranteed runtime capabilities. Every decision and
//     outcome is recorded through the durable event plane whose health is already a separate
//     readiness row (DurableEventsHealthy), so there is no state left to check here.
//
// Every other obligation makes the permit false, and each for a stated reason:
//
//   - CredentialProfile: the broker plans and materializes at call time. Requiring it absent is
//     what makes the First Canary need no credential at all (see the blocker-#9 overlap note in
//     the ledger — this PR records that overlap and does NOT close #9).
//   - RateLimitProfile, Destination, TicketRequired: NO runtime consumer exists. A rule asking
//     for a rate limit, a destination restriction or a ticket would be silently ignored, so
//     "satisfied" would mean "not enforced". That is the one direction this must never err in.
//   - OnceCall, Session, Redaction, Confirmation, Approval: they belong to other actions. On a
//     plain ALLOW the runtime ignores them (needsAllowance is false for ActionKindAllow, and the
//     redaction transform runs only for ActionKindRedaction) — again "satisfied" would mean
//     "ignored". Approval on a plain ALLOW is already rejected at compile; it is repeated here so
//     the allow-list is complete on its own terms rather than by relying on the compiler.
//
// The set is enumerated field-by-field ON PURPOSE. A future obligation field added to
// policy.Obligations must be classified here before it can ride a First-Canary permit;
// TestPermit_EveryObligationFieldIsClassified derives the field list by reflection and fails
// until it is. An unknown obligation is never silently satisfied.
func permitObligationsSatisfiable(o policy.Obligations) PermitReason {
	switch {
	case o.CredentialProfile != "",
		o.RateLimitProfile != "",
		o.Destination != policy.DestinationUnknown,
		o.TicketRequired,
		o.OnceCall,
		o.Session != nil,
		o.Redaction != nil,
		o.Confirmation,
		o.Approval:
		return PermitObligationNotSatisfiable
	}
	return PermitOK
}

// PermitSatisfiableObligationFields names the obligation fields a First-Canary ALLOW may carry.
// It exists so the reflection wall can assert that the union of these and the refused set covers
// every field of policy.Obligations, with no field in both and none left unclassified.
func PermitSatisfiableObligationFields() []string { return []string{"Logging", "Observation"} }

// PermitRefusedObligationFields names the obligation fields that make the permit false.
func PermitRefusedObligationFields() []string {
	return []string{
		"Approval", "Confirmation", "CredentialProfile", "Destination", "OnceCall",
		"RateLimitProfile", "Redaction", "Session", "TicketRequired",
	}
}

// PermitFieldIsBound reports whether a policy field is in the bound set. Exported for the
// structural walls and the read-only operator surface.
func PermitFieldIsBound(field string) bool {
	_, ok := permitBoundFieldSet[field]
	return ok
}
