package execution

import (
	"context"
	"reflect"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// TestShadow_TypeGraphHasNoExecuteCapability is the Layer-B structural gate (SH-INV-2,
// docs/design/mcp/SHADOW-ARCHITECTURE.md §3): it proves — in Go types, by reflection,
// not by comment or runtime check — that the Shadow capability object cannot reach the
// irreversible side-effect boundary because it does not POSSESS the capability to.
//
// The invariant: no field of ShadowConfig or ShadowEvaluator has a static type whose
// method set contains `Call` (the upstream side effect) or `Materialize` (the credential
// secret). This is exactly the pair of capabilities the run.go:71 boundary needs, and it
// is the pair a Shadow evaluator must not hold.
//
// Mutation coverage (each verified to fail this test):
//   - adding `Upstream UpstreamCaller` to ShadowConfig  → UpstreamCaller has Call
//   - adding `Broker *broker.Broker` to ShadowConfig     → *broker.Broker has Materialize
//   - adding either as a direct field of ShadowEvaluator → same
//
// The live Executor's Config is asserted as a discriminating CONTROL: it DOES possess
// both capabilities, so a detector that found nothing on it would be vacuous.
func TestShadow_TypeGraphHasNoExecuteCapability(t *testing.T) {
	// The Shadow objects must possess neither capability.
	for _, tt := range []reflect.Type{
		reflect.TypeOf(ShadowConfig{}),
		reflect.TypeOf(ShadowEvaluator{}),
	} {
		if bad := forbiddenCapabilityFields(tt); len(bad) != 0 {
			t.Fatalf("%s possesses a live execution capability via %v — a Shadow evaluator must hold no path to Upstream.Call or credential Materialize", tt.Name(), bad)
		}
	}

	// Control: the live Executor's Config DOES possess both, proving the detector is
	// discriminating rather than trivially green.
	ctrl := forbiddenCapabilityFields(reflect.TypeOf(Config{}))
	if !contains(ctrl, "Upstream.Call") {
		t.Fatalf("control failed: live Config should expose Upstream.Call, detector found %v", ctrl)
	}
	if !contains(ctrl, "Broker.Materialize") {
		t.Fatalf("control failed: live Config should expose Broker.Materialize, detector found %v", ctrl)
	}
}

// TestShadow_ConstructibleWithoutUpstreamOrMaterializingBroker proves the Layer-B
// composition claim: a Shadow evaluator is fully constructible with NO upstream client
// and NO materializing broker — only the required rollout state (and, optionally, a
// plan-only credential capability). If the constructor demanded a live capability, a
// shadow-only runtime could not exist without one.
func TestShadow_ConstructibleWithoutUpstreamOrMaterializingBroker(t *testing.T) {
	st := stateForMode(t, 0) // ModeShadow-independent; any state constructs
	ev, err := NewShadowEvaluator(ShadowConfig{State: st, Events: realEvents(t, nil)})
	if err != nil {
		t.Fatalf("shadow evaluator must construct with no upstream and no broker: %v", err)
	}
	if ev == nil {
		t.Fatal("nil evaluator")
	}
}

// TestShadow_DoesNotRetainConcretePlanner proves the Layer-B narrowing at the VALUE level
// (Codex P2, PR #1226): even when a caller supplies a materialize-capable *broker.Broker as
// the CredentialPlanner (it satisfies the interface), the constructed evaluator does NOT
// retain that concrete value anywhere reachable — `cfg.Planner` is cleared and the only
// credential capability held is the bound Plan method value, which cannot be type-asserted
// back to *broker.Broker. So `s.cfg.Planner.(*broker.Broker).Materialize(...)` is
// impossible: the field is nil, and `s.plan` is a func, not an interface.
func TestShadow_DoesNotRetainConcretePlanner(t *testing.T) {
	b, _ := credDriftSetup(t) // a REAL materializing broker
	ev, err := NewShadowEvaluator(ShadowConfig{
		State: stateForMode(t, 0), Events: realEvents(t, nil), Planner: b,
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	if ev.cfg.Planner != nil {
		t.Fatal("the evaluator retained the CredentialPlanner interface — a type assertion could recover the materialize-capable broker")
	}
	if ev.plan == nil {
		t.Fatal("the plan method value was not extracted — the evaluator cannot check credential readiness")
	}
	// The retained capability is a func, whose reflect.Kind is Func — it holds no methods
	// and exposes no path to the broker (a method value cannot be unwrapped to its receiver).
	if got := reflect.TypeOf(ev.plan).Kind(); got != reflect.Func {
		t.Fatalf("plan capability is %v, want a func (an unwrappable interface would defeat the narrowing)", got)
	}
}

// TestShadow_EmbeddedEvaluatorSharesLiveAllowanceHistory proves the embedded shadow
// evaluator predicts allowances against the SAME store the live executor consumes (Codex
// P2). After the live Canary path consumes an ALLOW_ONCE, the embedded shadow must see it
// as consumed and predict WOULD_BLOCK — not WOULD_EXECUTE against a fresh, independent
// store. wouldSatisfy never mutates, so sharing preserves the read-only contract.
func TestShadow_EmbeddedEvaluatorSharesLiveAllowanceHistory(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))
	if e.shadow.allowances != e.allowances {
		t.Fatal("embedded shadow must SHARE the live executor's allowance store")
	}
	in := execInput(policy.ActionAllowOnce, false)
	// Live Canary consumes the one-shot grant.
	if out := e.Execute(context.Background(), in); !out.Executed {
		t.Fatalf("canary ALLOW_ONCE should execute+consume, state=%q", out.ExecutionState)
	}
	// The embedded shadow now predicts WOULD_BLOCK for the same grant (consumed), matching
	// what the same enforcing executor would return (allowance_consumed).
	if d := e.shadow.decide(in); d.Outcome != ShadowWouldBlock {
		t.Fatalf("embedded shadow should see the consumed ALLOW_ONCE and predict would_block, got %q", d.Outcome)
	}
}

// forbiddenCapabilityFields returns, for a struct type, the "Field.Method" labels of any
// field whose type (value OR pointer method set) exposes a Call or Materialize method.
func forbiddenCapabilityFields(tt reflect.Type) []string {
	var found []string
	for i := 0; i < tt.NumField(); i++ {
		f := tt.Field(i)
		names := methodNamesOf(f.Type)
		for _, bad := range []string{"Call", "Materialize"} {
			if names[bad] {
				found = append(found, f.Name+"."+bad)
			}
		}
	}
	return found
}

// methodNamesOf returns the union of the value and pointer method-set names of t. For an
// interface or pointer type the value method set already carries the full set; for a
// concrete non-pointer type the pointer method set is also consulted so a pointer-receiver
// capability method is not missed.
func methodNamesOf(t reflect.Type) map[string]bool {
	names := map[string]bool{}
	for i := 0; i < t.NumMethod(); i++ {
		names[t.Method(i).Name] = true
	}
	if t.Kind() != reflect.Interface && t.Kind() != reflect.Pointer {
		pt := reflect.PointerTo(t)
		for i := 0; i < pt.NumMethod(); i++ {
			names[pt.Method(i).Name] = true
		}
	}
	return names
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}
