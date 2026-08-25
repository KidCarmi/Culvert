package rollout

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// TestHardFailureNeverExecutesInAnyMode runs EVERY centrally-classified hard-failure
// reason through Shadow, Canary, and Production semantic resolution and proves a hard
// failure is never SOFTENED TO EXECUTION by any rollout mode. The enforcing modes
// (Canary/Production) block it; Shadow — which never enforces and never executes —
// routes it to the non-executing EffectShadowEvaluate disposition where the evaluator
// records WOULD_FAIL_HARD_CONTROL/WOULD_FAIL_INSPECTION. In NO mode does a hard failure
// reach EffectExecute, and in every mode the classified hard reason is preserved.
func TestHardFailureNeverExecutesInAnyMode(t *testing.T) {
	count := 0
	for r := mcperr.Reason(0); r <= lastReason; r++ {
		if strings.HasPrefix(r.Code(), "unknown(") || !IsHardFailure(r) {
			continue
		}
		count++
		// Enforcing modes block outright.
		for _, m := range []Mode{ModeCanary, ModeProduction} {
			res := Resolve(ResolveInput{Mode: m, InScope: true, Action: ActionKindAllow, HardFailure: true, HardReason: r})
			if res.Disposition != EffectBlock {
				t.Fatalf("hard failure %q in mode %v: disposition=%v, want block", r.Code(), m, res.Disposition)
			}
			if res.BlockReason != r {
				t.Fatalf("hard failure %q: block reason=%q", r.Code(), res.BlockReason.Code())
			}
		}
		// Shadow predicts a would-fail via the non-executing evaluation path; it must
		// NEVER execute and must preserve the reason for evidence.
		sh := Resolve(ResolveInput{Mode: ModeShadow, InScope: true, Action: ActionKindAllow, HardFailure: true, HardReason: r})
		if sh.Disposition != EffectShadowEvaluate || sh.Executed {
			t.Fatalf("hard failure %q in shadow: disposition=%v executed=%v, want non-executing evaluation", r.Code(), sh.Disposition, sh.Executed)
		}
		if sh.Disposition == EffectExecute {
			t.Fatalf("hard failure %q in shadow reached EffectExecute — a hard failure must never be softened to execution", r.Code())
		}
		if sh.BlockReason != r {
			t.Fatalf("hard failure %q in shadow: reason=%q not preserved for evidence", r.Code(), sh.BlockReason.Code())
		}
	}
	if count < 30 {
		t.Fatalf("expected many hard-failure reasons, got %d", count)
	}
}

// TestNonHardShadowVsCanary proves a NON-hard policy decision (even a DENY) is
// would-execute-and-record in Shadow (a NON-executing shadow evaluation, override
// set), while the same decision blocks in Canary. Shadow evaluates; it does not
// execute (SH-INV-1) — the disposition is EffectShadowEvaluate, never EffectExecute.
func TestNonHardShadowVsCanary(t *testing.T) {
	sh := Resolve(ResolveInput{Mode: ModeShadow, InScope: true, Action: ActionKindDenied})
	if sh.Disposition != EffectShadowEvaluate || !sh.ShadowOverride || sh.Executed {
		t.Fatal("shadow must record a non-hard DENY as a would-execute override (shadow_evaluate, not executed)")
	}
	cn := Resolve(ResolveInput{Mode: ModeCanary, InScope: true, Action: ActionKindDenied})
	if cn.Disposition != EffectBlock {
		t.Fatal("canary must block a DENY")
	}
}

// TestPropertyNarrowerScopeNeverIncreasesMembership proves adding an exclusion (a
// narrowing) can only remove members, never add them.
func TestPropertyNarrowerScopeNeverIncreasesMembership(t *testing.T) {
	lim := DefaultLimits()
	base, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Tenants: []string{"t1", "t2"}, Servers: []string{"s1"}}, 1, lim)
	narrowed, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Tenants: []string{"t1", "t2"}, Servers: []string{"s1"}, ExcludeTenants: []string{"t2"}}, 2, lim)
	for _, tenant := range []string{"t1", "t2", "t3"} {
		s := Subject{Capability: CapabilityGateway, Tenant: tenant, ServerID: "s1", Operation: RiskRead}
		if narrowed.Contains(s) && !base.Contains(s) {
			t.Fatalf("narrowing added a member: tenant=%s", tenant)
		}
	}
}

// TestPropertyDemotionNeverWidens proves a demotion's effective behavior is never
// broader than the source mode for the same request (record/execute/block ranks).
func TestPropertyDemotionNeverWidens(t *testing.T) {
	// From Canary (enforce) demoting to Observe: an ALLOW that executed in Canary
	// must NOT execute in Observe (Observe never executes).
	canary := Resolve(ResolveInput{Mode: ModeCanary, InScope: true, Action: ActionKindAllow, ObligationsSatisfied: true})
	observe := Resolve(ResolveInput{Mode: ModeObserve, InScope: true, Action: ActionKindAllow, ObligationsSatisfied: true})
	if canary.Executed && observe.Executed {
		t.Fatal("demotion to Observe must not still execute")
	}
}

// TestPropertyFailedTransitionChangesNothing proves an invalid transition returns
// an error and never yields a promotion/demotion classification.
func TestPropertyFailedTransitionChangesNothing(t *testing.T) {
	if k, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: ModeDisabled, To: ModeCanary}); err == nil || k != TransitionNone {
		t.Fatal("a skip-stage promotion must fail with no classification")
	}
}

// TestProductionNeverActivatesWithoutQualification is the property form of the
// lockout: no from-mode + no verifier can reach Production.
func TestProductionNeverActivatesWithoutQualification(t *testing.T) {
	for _, from := range []Mode{ModeDisabled, ModeObserve, ModeShadow, ModeCanary} {
		if _, err := CheckTransition(TransitionInput{Capability: CapabilityGateway, From: from, To: ModeProduction}); err == nil {
			t.Fatalf("production reachable from %v without a verifier", from)
		}
	}
}
