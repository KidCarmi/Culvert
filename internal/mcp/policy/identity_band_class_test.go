package policy

import "testing"

// identity_band_class_test.go — WHICH operation classes MCP-ID-005 protects, pinned as a fact.
//
// MCP-ID-005 (subjectOverride) is a HARD OVERRIDE: it denies a write/high-risk operation whose
// principal carries no assurance at all, and no ordinary rule can undo it. Its band is decided by
// writeOrHigher, so the override fires for OpWrite/OpDestructive/OpControl and NOT for
// OpRead/OpDiscovery.
//
// That asymmetry is deliberate and correct in the engine. It becomes load-bearing OUTSIDE the
// engine the moment something upstream can CHANGE an operation's class: the read-first tool
// classification (internal/mcp/runtime, ADR-0024 First Canary) promotes a reviewed non-mutating
// tools/call from the conservative OpWrite default to OpRead, and every tools/call was OpWrite
// before that seam existed. A promotion therefore carries the request out of this override's band,
// which makes the promotion — not a policy decision — the reason an identity control stops
// applying.
//
// These gates pin BOTH halves of that fact so the coupling is visible from this side too: whoever
// widens the band, or teaches another class to be promotable, sees the runtime-side guard named
// here (classifyReadFirstToolCall, and its
// TestReadFirstRuntime_AmbiguousIdentityIsNeverPromoted gate) in a failing test rather than in a
// design document.

// broadAllowRule is an ALLOW-everything rule, so nothing below can pass or fail for want of a
// matching rule: the only thing deciding these cases is the hard override.
const broadAllowRule = `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`

// The band itself: an ambiguous identity is denied for every mutating/high-risk class, and the
// denial is a hard override.
func TestIdentityBand_AmbiguousIdentityIsDeniedForEveryWriteOrHigherClass(t *testing.T) {
	for _, class := range []OperationClass{OpWrite, OpDestructive, OpControl} {
		t.Run(class.String(), func(t *testing.T) {
			in := gwInput()
			in.Operation.Class = class
			in.Principal.Assurance = AssuranceUnknown
			d, _ := eval(t, mustCompile(t, gwSnap(broadAllowRule)), in)
			if d.Action != ActionDeny || d.Reason != ReasonIdentityAmbiguous {
				t.Fatalf("SECURITY: %v with an ambiguous identity must be denied by MCP-ID-005, got %v/%v",
					class, d.Action, d.Reason)
			}
			if !d.HardOverride {
				t.Fatalf("MCP-ID-005 must deny as a hard override, not as a rule match (%v)", class)
			}
		})
	}
}

// The other half, and the reason the runtime must not promote an unidentified request: OpRead is
// OUTSIDE the band, so a class promotion is by itself enough to take a tools/call out of
// MCP-ID-005's reach. This gate asserts the exemption exists — it is not a wish that it did not.
//
// If a future change brings OpRead inside the band, this gate fails and the runtime-side guard
// becomes redundant; that is the intended signal, and the guard should be removed in the SAME
// change rather than left as a second authority on the question.
func TestIdentityBand_ReadIsOutsideTheBandSoAPromotionEscapesIt(t *testing.T) {
	in := gwInput()
	in.Operation.Class = OpRead
	in.Principal.Assurance = AssuranceUnknown
	d, _ := eval(t, mustCompile(t, gwSnap(broadAllowRule)), in)
	if d.Reason == ReasonIdentityAmbiguous {
		t.Fatalf("OpRead is expected to sit OUTSIDE the MCP-ID-005 band; if that changed, remove the "+
			"runtime-side promotion guard in the same change (got %v/%v)", d.Action, d.Reason)
	}
}
