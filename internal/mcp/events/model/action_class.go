package model

// Action-class projection for the durable v2 Shadow contract.
//
// The MCP policy engine assigns every decision one of exactly nine STABLE action wire
// codes (policy.Action.String(): ALLOW, DENY, MONITOR, QUARANTINE, REQUIRE_CONFIRMATION,
// REQUIRE_APPROVAL, ALLOW_ONCE, ALLOW_FOR_SESSION, ALLOW_WITH_REDACTION) and classifies
// each as ALLOW-class or restrictive (policy.Action.IsAllowClass()). A v2 Shadow event
// carries that class as a single durable boolean, ShadowEvidence.Override, which the
// producer sets to !action.IsAllowClass() (shadow_evaluator.decide).
//
// The leaf event model deliberately does NOT import internal/mcp/policy — the same
// layering discipline the rollout package follows — so it cannot call
// policy.Action.IsAllowClass() to bind the durable Override to the event's own
// Decision.Action. shadowActionClass is the MINIMAL model-local projection that makes
// that binding expressible in the leaf: it knows the nine wire codes and, for each,
// whether it is allow-class. Its ONLY semantic responsibility is allow-class vs
// restrictive-class — it models no effect, obligation, or other action property.
//
// This table can never silently drift from the policy taxonomy: a cross-package parity
// wall (internal/mcp/execution/shadow_action_class_parity_test.go) iterates
// policy.AllActions() and proves shadowActionClass agrees with policy.Action.IsAllowClass()
// for every current action, so a NEW policy action, or a reclassified one, fails CI until
// the durable schema semantics here are explicitly updated.

// shadowAllowClassActionCodes are the ALLOW-class policy action wire codes.
var shadowAllowClassActionCodes = map[string]struct{}{
	"ALLOW":                {},
	"MONITOR":              {},
	"ALLOW_ONCE":           {},
	"ALLOW_FOR_SESSION":    {},
	"ALLOW_WITH_REDACTION": {},
}

// The two policy-gating action wire codes that have a 1:1 correspondence with a single
// Shadow outcome in the producer (policyClassOutcome emits would_require_approval ONLY for
// REQUIRE_APPROVAL and would_require_confirmation ONLY for REQUIRE_CONFIRMATION). They are
// named constants so the classifier set below and the exact-action binding
// (validateShadowGatedOutcomeAction) share ONE source; the cross-package parity wall pins
// both — like every code — to policy.Action.String(), so a wire-code rename fails CI here.
const (
	actionCodeRequireApproval     = "REQUIRE_APPROVAL"
	actionCodeRequireConfirmation = "REQUIRE_CONFIRMATION"
)

// shadowRestrictiveActionCodes are the restrictive (non-ALLOW-class) policy action wire
// codes. Kept as an explicit set (rather than "anything not allow-class") so an unknown
// or malformed code is DISTINGUISHABLE from a known restrictive one and can fail closed.
var shadowRestrictiveActionCodes = map[string]struct{}{
	"DENY":                        {},
	"QUARANTINE":                  {},
	actionCodeRequireConfirmation: {},
	actionCodeRequireApproval:     {},
}

// shadowActionClass classifies a policy action wire code. known is false for any code
// outside the nine-action taxonomy (including "" and the sentinel "INVALID"), so the
// validator can fail closed on an unknown action rather than guessing a class. When known
// is true, isAllowClass reports whether the code is ALLOW-class.
func shadowActionClass(code string) (isAllowClass bool, known bool) {
	if _, ok := shadowAllowClassActionCodes[code]; ok {
		return true, true
	}
	if _, ok := shadowRestrictiveActionCodes[code]; ok {
		return false, true
	}
	return false, false
}

// ShadowActionClass is the exported form of shadowActionClass, used by the cross-package
// parity wall to prove the model-local classification agrees with the policy taxonomy
// (which the leaf model may not import). It is classification only — it never touches
// event state.
func ShadowActionClass(code string) (isAllowClass bool, known bool) { return shadowActionClass(code) }

// ShadowClassifiedActionCodes returns every wire code the model classifies (allow-class and
// restrictive together), in no particular order. The cross-package parity wall uses it for
// the reverse check — that the model invents no action outside the policy taxonomy — so the
// model's known-action set is pinned to EXACTLY policy.AllActions().
func ShadowClassifiedActionCodes() []string {
	codes := make([]string, 0, len(shadowAllowClassActionCodes)+len(shadowRestrictiveActionCodes))
	for c := range shadowAllowClassActionCodes {
		codes = append(codes, c)
	}
	for c := range shadowRestrictiveActionCodes {
		codes = append(codes, c)
	}
	return codes
}
