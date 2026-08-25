package rollout

import "testing"

// TestShadow_NeverEmitsExecuteDisposition is the resolver-level structural guard for
// SH-INV-1/2 (docs/design/mcp/SHADOW-ARCHITECTURE.md §3): a Shadow evaluation
// (in-scope, non-hard) must resolve to EffectShadowEvaluate for EVERY policy action
// class, and NEVER to EffectExecute — so a Shadow request can never share the execute
// path with Canary/Production.
//
// Mutation coverage: reverting resolveShadow to `r.Disposition = EffectExecute` (the
// pre-Shadow-architecture behaviour) fails this test for every action.
func TestShadow_NeverEmitsExecuteDisposition(t *testing.T) {
	actions := []ActionKind{
		ActionKindDenied, ActionKindAllow, ActionKindConfirm, ActionKindApproval,
		ActionKindAllowOnce, ActionKindAllowSession, ActionKindRedaction,
	}
	for _, a := range actions {
		r := Resolve(ResolveInput{Mode: ModeShadow, InScope: true, Action: a})
		if r.Disposition == EffectExecute {
			t.Fatalf("action %v: shadow resolved to EffectExecute — Shadow must never take the execute path", a)
		}
		if r.Disposition != EffectShadowEvaluate {
			t.Fatalf("action %v: shadow disposition = %v, want shadow_evaluate", a, r.Disposition)
		}
		if r.Executed {
			t.Fatalf("action %v: shadow marked executed — it evaluates, it does not execute", a)
		}
	}

	// Control (proves the guard is discriminating, not vacuous): a Canary satisfied
	// ALLOW DOES resolve to EffectExecute. If both branches produced the same
	// disposition the test above would be meaningless.
	cn := Resolve(ResolveInput{Mode: ModeCanary, InScope: true, Action: ActionKindAllow, ObligationsSatisfied: true})
	if cn.Disposition != EffectExecute {
		t.Fatalf("control: canary satisfied-allow must resolve to EffectExecute, got %v", cn.Disposition)
	}

	// The two dispositions must be distinct enum values.
	if EffectShadowEvaluate == EffectExecute {
		t.Fatal("EffectShadowEvaluate must be a distinct disposition value from EffectExecute")
	}
}

// TestShadow_CanaryOutOfScopeFallbackNeverExecutes proves the Canary/Production
// out-of-scope shadow fallback also uses the non-executing disposition — the fallback
// must not become a hidden execute path.
func TestShadow_CanaryOutOfScopeFallbackNeverExecutes(t *testing.T) {
	r := Resolve(ResolveInput{Mode: ModeCanary, InScope: false, ShadowEnabled: true, ShadowInScope: true, Action: ActionKindAllow})
	if r.Disposition == EffectExecute || r.Executed {
		t.Fatalf("canary out-of-scope shadow fallback must never execute, got %v executed=%v", r.Disposition, r.Executed)
	}
	if r.Disposition != EffectShadowEvaluate {
		t.Fatalf("fallback disposition = %v, want shadow_evaluate", r.Disposition)
	}
}
