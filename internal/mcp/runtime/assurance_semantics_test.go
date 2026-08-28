package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// OVN-05. `Assurance` and `SenderBinding` are DIFFERENT PROPERTIES and must be
// carried separately.
//
// The documented meaning of Assurance across identity/principal.go,
// policy/enums.go, AUTH-AND-CREDENTIAL-MODEL.md and SECURITY-REQUIREMENTS.md
// (MCP-ID-006) is NIST-AAL-style HUMAN authentication strength — "multi-factor",
// "hardware-backed / phishing-resistant", elevated by step-up authentication.
// Culvert cannot observe that: no `amr`/`acr` claim is parsed anywhere, so no AAL
// fact exists in the product. What the runtime derives is the strength of the
// SENDER BINDING, which is a different thing — a DPoP proof shows the presenter
// controls the token's key, not that a person completed MFA.
//
// These tests pin the separation so nobody re-folds one into the other, in either
// direction, without the open decision being resolved.
func TestAssurance_SenderBindingIsCarriedSeparately(t *testing.T) {
	cases := []struct {
		method identity.ConfirmationMethod
		want   policy.SenderBinding
		label  string
	}{
		{identity.ConfirmNone, policy.SenderBindingNone, "none"},
		{identity.ConfirmDPoP, policy.SenderBindingDPoP, "dpop"},
		{identity.ConfirmMTLS, policy.SenderBindingMTLS, "mtls"},
	}
	for _, c := range cases {
		sc := identity.SenderConstraint{Method: c.method}
		if got := policySenderBinding(sc); got != c.want {
			t.Fatalf("%s ⇒ policy binding %v, want %v", c.label, got, c.want)
		}
		if got := senderBindingString(sc); got != c.label {
			t.Fatalf("%s ⇒ evidence label %q, want %q", c.label, got, c.label)
		}
	}
	// The zero value must be the UNBOUND one, so an input that never sets the field
	// fails a binding requirement closed rather than claiming a binding.
	var zero policy.SenderBinding
	if zero != policy.SenderBindingNone || zero.Bound() {
		t.Fatal("the zero SenderBinding must be the unbound value (fail closed)")
	}
}

// A rule that means "require a sender-constrained token" must be expressible
// DIRECTLY, and the runtime must actually populate the fact it reads. Before this,
// the only way to say it was `principal.assurance >= high` — borrowing a field
// whose documented meaning is human MFA strength, which is exactly how the
// conflation became load-bearing in real policies.
//
// This is proven END-TO-END through a real compiled rule rather than by inspecting
// a struct: the field must be in the closed vocabulary, the compiler must accept
// it, the evaluator must read it, and the runtime must fill it from the VERIFIED
// constraint. A field that exists but is never populated is the DEBT-011 pattern.
func TestAssurance_SenderBindingDrivesARealPolicyDecision(t *testing.T) {
	k := newESKey(t, "k1")
	// The gateway fixture uses a BearerControlled profile, so the honest binding is
	// "none". A rule denying unbound senders must therefore fire.
	rule := `{"id":"REQUIRE_POP","priority":1,"action":"DENY",` +
		`"reason":"MCP.POLICY.SENDER_CONSTRAINT","remediation":"increase_assurance",` +
		`"conditions":[{"field":"principal.sender_bound","op":"bool","value":"false"}]}`
	p := policyPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, rule)})
	tok, sid := driveToDecisionPoint(t, p, k)
	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsListBody(2)), sid), fixedClock())

	if out.Record.MatchedRule != "REQUIRE_POP" {
		t.Fatalf("matched rule = %q, want REQUIRE_POP — the runtime did not populate "+
			"principal.sender_bound from the verified constraint", out.Record.MatchedRule)
	}
	if out.Record.PolicyAction != "DENY" {
		t.Fatalf("policy action = %q, want DENY", out.Record.PolicyAction)
	}

	// Control: the SAME rule inverted must NOT match, proving the field carries a
	// real value rather than matching whatever is asked of it.
	inv := `{"id":"REQUIRE_POP","priority":1,"action":"DENY",` +
		`"reason":"MCP.POLICY.SENDER_CONSTRAINT","remediation":"increase_assurance",` +
		`"conditions":[{"field":"principal.sender_bound","op":"bool","value":"true"}]}`
	p2 := policyPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, inv)})
	tok2, sid2 := driveToDecisionPoint(t, p2, k)
	out2 := p2.Process(context.Background(), withSession(gwRequest(tok2, toolsListBody(2)), sid2), fixedClock())
	if out2.Record.MatchedRule == "REQUIRE_POP" {
		t.Fatal("a bearer request matched a rule requiring a sender-constrained token")
	}
}

// Anti-escalation. The assurance derivation must stay a function of the VERIFIED
// sender constraint and nothing else until the open decision is resolved. This
// pins the file-level fact that no `amr`/`acr` claim feeds it — the change that
// would silently turn a sender-binding fact into an AAL claim.
func TestAssurance_NoAALClaimIsRead(t *testing.T) {
	src, err := os.ReadFile(filepath.Clean("../authn/claims.go"))
	if err != nil {
		t.Fatalf("read claims.go: %v", err)
	}
	for _, claim := range []string{`"amr"`, `"acr"`} {
		if strings.Contains(string(src), claim) {
			t.Fatalf("authn now reads %s: an authentication-assurance claim is being parsed, so the "+
				"Assurance semantics decision (docs/design/mcp/OPEN-DECISION-assurance-model.md) "+
				"must be resolved before it can feed the assurance derivation", claim)
		}
	}
}

// The WRITE side must be proven with a NON-ZERO binding. `SenderBindingNone` is
// the zero value, so a bearer-only test cannot distinguish "populated as none"
// from "never populated at all" — removing the assignment leaves such a test
// green. This drives a request with a REAL, verified DPoP proof, where the only
// way the field can read "dpop" is if the runtime actually wrote it from the
// verified constraint.
func TestAssurance_VerifiedDPoPIsReportedAsABinding(t *testing.T) {
	kit := newDPoPKit(t)
	rule := `{"id":"POP_OK","priority":1,"action":"ALLOW",` +
		`"reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",` +
		`"conditions":[{"field":"principal.sender_binding","op":"exact","value":"dpop"},` +
		`{"field":"session.sender_binding","op":"exact","value":"dpop"},` +
		`{"field":"principal.sender_bound","op":"bool","value":"true"}],` +
		`"obligations":{"logging":"standard"}}`

	cfg := gwListenerConfig(t)
	cfg.AuthConfig = gwAuthConfigProfile(t, senderconstraint.DPoPRequired)
	kit.deps.Policy = fakePolicy{gw: gwPolicySnap(t, rule)}
	p, err := newPipeline(cfg, kit.deps, "pop-gw", &counters{}, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}

	tok := kit.token(t)
	init := p.Process(context.Background(), kit.request(t, tok, "jti-1", initializeBody(1)), fixedClock())
	if init.SessionID == "" {
		t.Fatalf("DPoP initialize failed: %d / %v", init.Status, init.Reason)
	}
	p.Process(context.Background(), withSession(kit.request(t, tok, "jti-2", initializedNotification()), init.SessionID), fixedClock())

	call := withSession(kit.request(t, tok, "jti-3", toolsListBody(2)), init.SessionID)
	out := p.Process(context.Background(), call, fixedClock())

	if out.Record.MatchedRule != "POP_OK" {
		t.Fatalf("matched rule = %q (action %q, reason %v), want POP_OK — a VERIFIED DPoP proof "+
			"was not reported on principal.sender_binding, session.sender_binding and principal.sender_bound",
			out.Record.MatchedRule, out.Record.PolicyAction, out.Reason)
	}
	// And the durable evidence records the binding separately from assurance.
	if got := senderBindingString(identity.SenderConstraint{Method: identity.ConfirmDPoP}); got != "dpop" {
		t.Fatalf("evidence label = %q, want dpop", got)
	}
}
