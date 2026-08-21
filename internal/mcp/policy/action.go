// Package policy is the deterministic, I/O-free MCP policy-decision engine
// (PR-6, MCP-POLICY-001..007, MCP-TOOL-004/006, MCP-ID-005/006). It answers a
// single question — "is this MCP operation permitted, and exactly why?" — over an
// immutable, caller-supplied decision tuple and an immutable, capability-local
// policy snapshot, and returns an explainable Decision plus an internal explain
// trace.
//
// It is PURE: no network, filesystem, database, DNS, environment, clock, secret
// or logging access happens on the evaluation path. Every fact the evaluator
// needs is supplied in the immutable DecisionInput, and the evaluation timestamp
// is an explicit input — the code never calls time.Now(). It is DEFAULT-DENY,
// bounded, and safe under hostile or incomplete input. Gateway and Management use
// completely separate policy namespaces that can never cross-match.
//
// It decides only. It never executes a business operation, calls an upstream MCP
// server, materializes a credential, contacts a credential provider, performs
// DLP/inspection, or durably commits an event — those are later slices. Even an
// ALLOW-class decision is metadata here; PR-6 never fabricates execution success.
package policy

// Action is one of the exactly nine MCP policy-decision actions. The zero value is
// ActionInvalid so a mis-constructed rule or decision fails closed.
type Action uint8

const (
	// ActionInvalid is the zero value: not a valid action. Fails closed.
	ActionInvalid Action = iota
	// ActionAllow — permitted (requires complete evidence + all mandatory obligations).
	ActionAllow
	// ActionDeny — denied; no execution; carries a stable reason + remediation.
	ActionDeny
	// ActionMonitor — non-blocking policy intent; still no upstream execution in
	// PR-6; carries full telemetry obligations.
	ActionMonitor
	// ActionQuarantine — no execution; used for unknown tools + privilege expansion.
	ActionQuarantine
	// ActionRequireConfirmation — no execution until confirmation evidence exists
	// (a later slice).
	ActionRequireConfirmation
	// ActionRequireApproval — no execution until approval evidence exists (a later
	// slice).
	ActionRequireApproval
	// ActionAllowOnce — carries a one-call obligation, strict scope + short TTL.
	// PR-6 defines the obligation; redemption state is a later slice.
	ActionAllowOnce
	// ActionAllowForSession — carries session-id requirement, max-calls, TTL + revoke.
	// PR-6 defines the obligation; grant state is a later slice.
	ActionAllowForSession
	// ActionAllowWithRedaction — carries a redaction-profile reference + transformed-
	// evidence obligation. PR-7 supplies the actual redaction evidence.
	ActionAllowWithRedaction
)

// actionCode maps each action to its stable UPPER_SNAKE wire code. The strings are
// part of the package contract and MUST NOT change.
var actionCode = map[Action]string{
	ActionInvalid:             "INVALID",
	ActionAllow:               "ALLOW",
	ActionDeny:                "DENY",
	ActionMonitor:             "MONITOR",
	ActionQuarantine:          "QUARANTINE",
	ActionRequireConfirmation: "REQUIRE_CONFIRMATION",
	ActionRequireApproval:     "REQUIRE_APPROVAL",
	ActionAllowOnce:           "ALLOW_ONCE",
	ActionAllowForSession:     "ALLOW_FOR_SESSION",
	ActionAllowWithRedaction:  "ALLOW_WITH_REDACTION",
}

// codeAction is the reverse lookup used by the strict snapshot parser.
var codeAction = func() map[string]Action {
	m := make(map[string]Action, len(actionCode))
	for a, s := range actionCode {
		if a != ActionInvalid {
			m[s] = a
		}
	}
	return m
}()

// String returns the stable action code (e.g. "ALLOW"). An unknown value renders
// "INVALID" so it can never masquerade as a permit.
func (a Action) String() string {
	if s, ok := actionCode[a]; ok {
		return s
	}
	return "INVALID"
}

// Valid reports whether a is one of the nine real actions (never the zero value).
func (a Action) Valid() bool { return a >= ActionAllow && a <= ActionAllowWithRedaction }

// ParseAction resolves a wire code to an Action. It returns (ActionInvalid, false)
// for an unknown/aliased/empty code — the parser rejects it rather than guessing.
func ParseAction(code string) (Action, bool) {
	a, ok := codeAction[code]
	return a, ok
}

// Effect is the coarse execution-effect classification of an action. It exists so
// the runtime can branch on the effect without re-deriving it from the action.
type Effect uint8

const (
	// EffectDenied is the zero value: no execution (fail closed).
	EffectDenied Effect = iota
	// EffectPermitted — permitted (possibly with obligations).
	EffectPermitted
	// EffectPermittedWithObligations — permitted but carrying mandatory obligations.
	EffectPermittedWithObligations
	// EffectPendingConfirmation — no execution until confirmation evidence exists.
	EffectPendingConfirmation
	// EffectPendingApproval — no execution until approval evidence exists.
	EffectPendingApproval
	// EffectQuarantined — no execution; quarantined.
	EffectQuarantined
)

// String returns the effect label.
func (e Effect) String() string {
	switch e {
	case EffectPermitted:
		return "permitted"
	case EffectPermittedWithObligations:
		return "permitted_with_obligations"
	case EffectPendingConfirmation:
		return "pending_confirmation"
	case EffectPendingApproval:
		return "pending_approval"
	case EffectQuarantined:
		return "quarantined"
	default:
		return "denied"
	}
}

// Effect returns the execution-effect classification of the action. An invalid or
// unknown action is EffectDenied (fail closed).
func (a Action) Effect() Effect {
	switch a {
	case ActionAllow:
		return EffectPermitted
	case ActionMonitor, ActionAllowOnce, ActionAllowForSession, ActionAllowWithRedaction:
		return EffectPermittedWithObligations
	case ActionRequireConfirmation:
		return EffectPendingConfirmation
	case ActionRequireApproval:
		return EffectPendingApproval
	case ActionQuarantine:
		return EffectQuarantined
	default: // ActionDeny, ActionInvalid, unknown
		return EffectDenied
	}
}

// IsAllowClass reports whether the action is ALLOW-class — the SINGLE authoritative
// classification used across the engine and runtime. It is METADATA ONLY in PR-6:
// an ALLOW-class result never invokes the credential broker, contacts a provider,
// or authorizes an upstream side effect. Credential planning/materialization only
// becomes reachable after an ALLOW-class decision in a later execution slice.
//
// ALLOW-class = {ALLOW, MONITOR, ALLOW_ONCE, ALLOW_FOR_SESSION, ALLOW_WITH_REDACTION}.
// DENY, QUARANTINE, REQUIRE_CONFIRMATION and REQUIRE_APPROVAL are NOT ALLOW-class.
func (a Action) IsAllowClass() bool {
	switch a {
	case ActionAllow, ActionMonitor, ActionAllowOnce, ActionAllowForSession, ActionAllowWithRedaction:
		return true
	default:
		return false
	}
}

// AllActions returns the nine real actions in stable order (for tests + tooling).
func AllActions() []Action {
	return []Action{
		ActionAllow, ActionDeny, ActionMonitor, ActionQuarantine,
		ActionRequireConfirmation, ActionRequireApproval,
		ActionAllowOnce, ActionAllowForSession, ActionAllowWithRedaction,
	}
}
