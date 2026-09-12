package runtime

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
)

// read_first_identity_band_test.go — the read-first promotion may move a request between RULES; it
// may not move it out of a HARD OVERRIDE.
//
// WHAT THIS PROTECTS. `op.Class` has more readers than the Canary read-first gate, and one of them
// is MCP-ID-005 in policy/engine.go's subjectOverride: a write/high-risk operation whose principal
// carries NO assurance at all is denied as a hard override that no rule can undo. Because every
// tools/call was OpWrite before the read-first classifier existed, that override denied every tool
// invocation from an unidentified principal, unconditionally. Promotion to OpRead leaves
// writeOrHigher's band (pinned from the engine side by
// policy.TestIdentityBand_ReadIsOutsideTheBandSoAPromotionEscapesIt), so without the guard below
// the promotion itself is the reason an identity control stops applying.
//
// That is a different question from the one the review answered. A four-eyes review determined the
// TOOL does not mutate state; nobody determined that invoking it without knowing who is asking is
// acceptable, and a non-mutating tool still returns upstream data to whoever called it.
//
// WHY IT IS A LATENT COUPLING TODAY RATHER THAN A LIVE HOLE, and why it is still worth pinning.
// buildAuthRequest asserts AssuranceHigh for every request and authn.effectiveAssurance CLAMPS it
// to what the verified sender constraint justifies — High for DPoP/mTLS, Low for a bearer token —
// so the resolved assurance on the live path is never Unknown, and MCP-ID-005 is currently
// unreachable for a Gateway tools/call. The control is therefore held up by a property of a
// different package, asserted nowhere. authn's own effectiveAssurance comment invites exactly the
// change that would end it ("a future caller with INDEPENDENT verified assurance evidence for a
// human must add that evidence as a new derivation branch here"): the first such branch that can
// yield Unknown makes the override reachable again, and at that moment a reviewed tool would be
// silently exempt from it. The guard costs one comparison and changes no behaviour today, which is
// the cheapest possible way to make the invariant hold in advance instead of in hindsight.

// callClass asks the classification site directly for the class it would assign, starting from the
// conservative OpWrite default the protocol mapping produces for a tools/call.
//
// It calls classifyReadFirstToolCall rather than driving Process end to end deliberately: the live
// path cannot produce AssuranceUnknown today (see the file header), so an end-to-end gate could
// only assert the coincidence that keeps the override unreachable — not the rule that must hold
// when it becomes reachable.
func callClass(t *testing.T, p *pipeline, assurance policy.Assurance) policy.OperationClass {
	t.Helper()
	op := policy.Operation{Method: "tools/call", Class: policy.OpWrite}
	p.classifyReadFirstToolCall(&op, testServerID, "x", assurance)
	return op.Class
}

// THE GUARD. An affirmative reviewed-read answer is NOT enough on its own: a principal whose
// assurance is unknown keeps OpWrite, so MCP-ID-005 denies the call exactly as it did before the
// classifier existed.
func TestReadFirstRuntime_AmbiguousIdentityIsNeverPromoted(t *testing.T) {
	cls := &recordingClassifier{class: policy.OpRead, ok: true}
	p, _, _ := readFirstFixture(t, cls)
	if got := callClass(t, p, policy.AssuranceUnknown); got != policy.OpWrite {
		t.Fatalf("SECURITY: a reviewed-read tool must NOT be promoted for a principal with no "+
			"assurance — the promotion would carry it out of the MCP-ID-005 hard override; got %v", got)
	}
}

// THE CONTROL, without which the gate above is satisfied by a classifier that promotes nothing at
// all. Every assurance level that is not Unknown still gets the promotion the First Canary needs,
// so the guard narrows exactly one case and no more.
func TestReadFirstRuntime_KnownIdentityStillGetsThePromotion(t *testing.T) {
	for _, assurance := range []policy.Assurance{policy.AssuranceLow, policy.AssuranceMedium, policy.AssuranceHigh} {
		t.Run(assurance.String(), func(t *testing.T) {
			cls := &recordingClassifier{class: policy.OpRead, ok: true}
			p, _, _ := readFirstFixture(t, cls)
			if got := callClass(t, p, assurance); got != policy.OpRead {
				t.Fatalf("a reviewed-read tool must still be promoted at assurance %v, got %v", assurance, got)
			}
		})
	}
}

// The guard must not become a SECOND way to promote. A known identity does not make an unreviewed
// tool read-first — the reviewed record is still the only authority, and the assurance check only
// ever subtracts.
func TestReadFirstRuntime_KnownIdentityDoesNotPromoteWithoutAReviewedRead(t *testing.T) {
	for _, tc := range []struct {
		name  string
		class policy.OperationClass
		ok    bool
	}{
		{"no reviewed answer", policy.OpUnset, false},
		{"reviewed write", policy.OpWrite, true},
		{"reviewed destructive", policy.OpDestructive, true},
		{"read but not vouched for", policy.OpRead, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cls := &recordingClassifier{class: tc.class, ok: tc.ok}
			p, _, _ := readFirstFixture(t, cls)
			if got := callClass(t, p, policy.AssuranceHigh); got != policy.OpWrite {
				t.Fatalf("SECURITY: %s must leave the call at OpWrite even at high assurance, got %v", tc.name, got)
			}
		})
	}
}

// An ambiguous identity must not even REACH the classifier. Declining to ask is stronger than
// discarding the answer: there is no answer the seam could give that would matter, so a future
// refactor that moved the promotion closer to the seam cannot reintroduce the escape.
func TestReadFirstRuntime_AmbiguousIdentityNeverReachesTheClassifier(t *testing.T) {
	cls := &recordingClassifier{class: policy.OpRead, ok: true}
	p, _, _ := readFirstFixture(t, cls)
	_ = callClass(t, p, policy.AssuranceUnknown)
	if calls := cls.seen(); len(calls) != 0 {
		t.Fatalf("SECURITY: an unidentified principal must not be able to drive the read-first "+
			"classifier at all, got %+v", calls)
	}
}
