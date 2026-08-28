package execution

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// TestShadowActionClassParity is the cross-package parity WALL for the durable v2 Shadow
// action-class projection (SHADOW-EVIDENCE-ROUTING-1, Codex round PR #1235).
//
// The leaf event model (internal/mcp/events/model) deliberately does NOT import the policy
// action taxonomy, so it carries its OWN action-class classifier (model.ShadowActionClass)
// to bind ShadowEvidence.Override to the event's Decision.Action. That model-local table is
// only sound while it agrees, code-for-code, with the single authoritative classification
// (policy.Action.IsAllowClass). This test proves that agreement over policy.AllActions() and
// is the CI gate that a future policy action, or a reclassified one, fails until the durable
// event-model semantics are explicitly updated:
//
//   - every current policy action must be KNOWN to the model classifier (a new policy action
//     with no model classification ⇒ known=false ⇒ CI failure), and
//   - its model class must equal policy.Action.IsAllowClass() (a flipped model classification
//     ⇒ CI failure).
func TestShadowActionClassParity(t *testing.T) {
	actions := policy.AllActions()
	if len(actions) == 0 {
		t.Fatal("policy.AllActions() returned no actions — the parity wall would prove nothing")
	}
	for _, a := range actions {
		code := a.String()
		isAllowClass, known := model.ShadowActionClass(code)
		if !known {
			t.Fatalf("policy action %q is not classified by the event model — a new policy action must be given an event-model action-class before its durable v2 Shadow semantics are defined", code)
		}
		if isAllowClass != a.IsAllowClass() {
			t.Fatalf("event-model class for %q (allow-class=%v) disagrees with policy.Action.IsAllowClass() (%v)", code, isAllowClass, a.IsAllowClass())
		}
	}
}

// TestShadowActionClassParity_ModelHasNoStrayActions is the reverse half: every wire code the
// model classifies (allow-class OR restrictive) must be a REAL policy action. Together with
// the forward test above, this pins the model's known-action set to EXACTLY policy.AllActions()
// — so the classifier can neither miss a real action nor invent one the policy engine never
// emits.
func TestShadowActionClassParity_ModelHasNoStrayActions(t *testing.T) {
	realCodes := make(map[string]struct{}, len(policy.AllActions()))
	for _, a := range policy.AllActions() {
		realCodes[a.String()] = struct{}{}
	}
	for _, code := range model.ShadowClassifiedActionCodes() {
		if _, ok := realCodes[code]; !ok {
			t.Fatalf("event model classifies %q, which is not a real policy action — the model action-class set has drifted from the policy taxonomy", code)
		}
	}
}

// TestShadowActionClassParity_UnknownFailsClosed proves the classifier fails closed on codes
// outside the taxonomy, which is what the validator relies on to reject an unknown action.
func TestShadowActionClassParity_UnknownFailsClosed(t *testing.T) {
	for _, code := range []string{"", "INVALID", "allow", "FROBNICATE", "ALLOW_TWICE"} {
		if _, known := model.ShadowActionClass(code); known {
			t.Fatalf("classifier must not recognise %q as a policy action", code)
		}
	}
}
