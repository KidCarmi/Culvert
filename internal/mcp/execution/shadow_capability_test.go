package execution

import (
	"context"
	"reflect"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
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
	if out := runExec(e, context.Background(), in); !out.Executed {
		t.Fatalf("canary ALLOW_ONCE should execute+consume, state=%q", out.ExecutionState)
	}
	// The embedded shadow now predicts WOULD_BLOCK for the same grant (consumed), matching
	// what the same enforcing executor would return (allowance_consumed).
	if d := e.shadow.decide(in); d.Outcome != ShadowWouldBlock {
		t.Fatalf("embedded shadow should see the consumed ALLOW_ONCE and predict would_block, got %q", d.Outcome)
	}
}

// TestResolve_RoutesOnlyExecutingDispositions pins the single-resolution routing contract:
// Resolve reports record-only for Observe / Disabled / out-of-scope (so the runtime keeps
// its inline Observe evidence path) and NOT record-only for an in-scope Shadow evaluation
// or a killed capability (so Execute handles the evaluation / emergency block). Resolving
// ONCE and carrying the result into Execute is what preserves Observe evidence on a
// shadow-ready node and routes a killed node to the emergency block instead of a silent
// record — without a second, divergent resolution (Codex P2, PR #1234).
func TestResolve_RoutesOnlyExecutingDispositions(t *testing.T) {
	newEv := func(st *rollout.State) *ShadowEvaluator {
		e, err := NewShadowEvaluator(ShadowConfig{State: st, Events: realEvents(t, nil)})
		if err != nil {
			t.Fatalf("NewShadowEvaluator: %v", err)
		}
		return e
	}
	recordOnly := func(ev *ShadowEvaluator, in runtime.ExecInput) bool {
		return ev.Resolve(in).Disposition == rollout.EffectRecordOnly
	}
	inScope := execInput(policy.ActionAllow, false) // server s1 ∈ scope
	outScope := execInput(policy.ActionAllow, false)
	outScope.Input.Server = &policy.Server{ServerID: "not-in-scope", Environment: "prod"}

	if recordOnly(newEv(stateForMode(t, rollout.ModeShadow)), inScope) {
		t.Fatal("Shadow in-scope must NOT resolve to record-only (it evaluates via Execute)")
	}
	if !recordOnly(newEv(stateForMode(t, rollout.ModeShadow)), outScope) {
		t.Fatal("Shadow out-of-scope must resolve to record-only (Observe behaviour on the inline path)")
	}
	if !recordOnly(newEv(stateForMode(t, rollout.ModeObserve)), inScope) {
		t.Fatal("Observe must resolve to record-only")
	}
	if !recordOnly(newEv(stateForMode(t, rollout.ModeDisabled)), inScope) {
		t.Fatal("Disabled must resolve to record-only")
	}
	killed := stateForMode(t, rollout.ModeShadow)
	killed.EngageKillSwitch("oncall", 1)
	if recordOnly(newEv(killed), inScope) {
		t.Fatal("SECURITY: a killed capability must NOT resolve to record-only — Execute must emit the emergency block")
	}
	// And a killed capability resolves specifically to a block with the emergency reason.
	if res := newEv(killed).Resolve(inScope); res.Disposition != rollout.EffectBlock || res.BlockReason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("killed capability must resolve to an emergency block, got disp=%v reason=%v", res.Disposition, res.BlockReason)
	}
}

func newShadowEvaluatorForTest(t *testing.T, st *rollout.State) *ShadowEvaluator {
	t.Helper()
	e, err := NewShadowEvaluator(ShadowConfig{State: st, Events: realEvents(t, nil)})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	return e
}

// TestExecute_CarriesModeScopeResolutionWithoutReResolving is the F7 single-resolution gate
// (Codex P2, PR #1234): the MODE/SCOPE disposition is resolved EXACTLY ONCE (in Resolve) and
// carried into Execute, which must act on the carried disposition and NOT re-resolve mode or
// scope — so a mode/scope transition landing between Resolve and Execute can never make routing
// and execution observe two different snapshots.
//
// The proof: hand Execute a request the CURRENT state would resolve to record-only (out of
// scope — standing in for "the scope moved out from under the in-flight request after Resolve")
// together with a carried EffectShadowEvaluate resolution (what an earlier in-scope Resolve
// produced). Execute must honour the carried disposition and shadow-evaluate. If Execute
// re-resolved mode/scope it would see the out-of-scope request, return record-only, and fail —
// reopening exactly the evidence gap F7 closed.
func TestExecute_CarriesModeScopeResolutionWithoutReResolving(t *testing.T) {
	st := stateForMode(t, rollout.ModeShadow)
	ev := newShadowEvaluatorForTest(t, st)

	outScope := execInput(policy.ActionAllow, false)
	outScope.Input.Server = &policy.Server{ServerID: "not-in-scope", Environment: "prod"}
	// Sanity: the state genuinely resolves this request to record-only.
	if d := ev.Resolve(outScope).Disposition; d != rollout.EffectRecordOnly {
		t.Fatalf("precondition: out-of-scope Shadow must resolve to record-only, got %v", d)
	}

	// Carry a shadow-evaluate resolution (from a prior in-scope Resolve) into Execute.
	out := ev.Execute(context.Background(), outScope, rollout.Resolution{Disposition: rollout.EffectShadowEvaluate})
	if out.ExecutionState != "shadow_evaluated" {
		t.Fatalf("Execute re-resolved mode/scope instead of acting on the carried resolution: "+
			"an out-of-scope request with a carried shadow-evaluate returned %q (single-resolution TOCTOU is open)", out.ExecutionState)
	}
}

// TestExecute_ReHonorsEmergencyKillEngagedAfterResolve pins the round-5 correction (Codex P2,
// PR #1234): the kill switch is an immediate admission stop, so a kill engaged AFTER Resolve
// but before Execute must still stop the evaluation — Execute re-reads the monotonic kill flag
// even though it carries (never re-resolves) the mode/scope disposition. Without the re-check
// the evaluator would commit durable evidence and return a would_* verdict AFTER the operator's
// emergency stop.
//
// Mutation: dropping the kill re-check at Execute entry shadow-evaluates the carried resolution
// and fails this gate. This is deliberately the OPPOSITE assertion from the mode/scope gate
// above — kill is the one axis Execute re-reads, because re-honouring it can only make the
// outcome more restrictive and so cannot reopen the routing TOCTOU.
func TestExecute_ReHonorsEmergencyKillEngagedAfterResolve(t *testing.T) {
	st := stateForMode(t, rollout.ModeShadow)
	ev := newShadowEvaluatorForTest(t, st)
	in := execInput(policy.ActionAllow, false) // server s1 ∈ scope

	res := ev.Resolve(in)
	if res.Disposition != rollout.EffectShadowEvaluate {
		t.Fatalf("precondition: in-scope Shadow must resolve to shadow-evaluate, got %v", res.Disposition)
	}
	st.EngageKillSwitch("oncall", 1) // emergency stop lands AFTER routing decided

	out := ev.Execute(context.Background(), in, res)
	if out.ExecutionState != "blocked" || out.Reason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("SECURITY: a kill engaged after Resolve must stop the evaluation at Execute: "+
			"got state=%q reason=%v, want blocked/emergency", out.ExecutionState, out.Reason)
	}
}

// spyMetrics records how many times the Shadow-outcome and block observations fire. It
// embeds noopMetrics for every other method of the interface.
type spyMetrics struct {
	noopMetrics
	outcomes int
	blocks   int
}

func (s *spyMetrics) ObserveShadowOutcome(string, string) { s.outcomes++ }
func (s *spyMetrics) ObserveBlock(string, mcperr.Reason)  { s.blocks++ }

// TestShadow_OutcomeMetricRecordedOnlyAfterDurableCommit is the evidence-before-report
// gate (Codex P2, PR #1234): when the durable commit fails, the evaluator returns a block
// (counted as an error) and must NOT ALSO record a would_* verdict — that would
// double-count and overstate successful Shadow outcomes during the durability failures an
// operator most needs to see. Mutation: moving ObserveShadowOutcome back before
// CommitThenAct makes outcomes==1 here and fails the test.
func TestShadow_OutcomeMetricRecordedOnlyAfterDurableCommit(t *testing.T) {
	// Success path: exactly one outcome, no block.
	okSpy := &spyMetrics{}
	okEv, err := NewShadowEvaluator(ShadowConfig{
		State: stateForMode(t, rollout.ModeShadow), Events: realEvents(t, nil), Metrics: okSpy,
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	if out := okEv.evaluate(context.Background(), execInput(policy.ActionAllow, false)); out.ExecutionState != "shadow_evaluated" {
		t.Fatalf("success path should shadow_evaluate, got %q", out.ExecutionState)
	}
	if okSpy.outcomes != 1 || okSpy.blocks != 0 {
		t.Fatalf("success path: outcomes=%d blocks=%d, want 1/0", okSpy.outcomes, okSpy.blocks)
	}

	// Durable-commit failure: a block, NO would_* verdict recorded.
	failSpy := &spyMetrics{}
	failEv, err := NewShadowEvaluator(ShadowConfig{
		State: stateForMode(t, rollout.ModeShadow), Events: realEvents(t, failBackend{inner: spool.NewOSBackend()}), Metrics: failSpy,
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	out := failEv.evaluate(context.Background(), execInput(policy.ActionAllow, false))
	if out.ExecutionState != "blocked" {
		t.Fatalf("commit failure must block, got %q", out.ExecutionState)
	}
	if failSpy.outcomes != 0 {
		t.Fatal("a would_* verdict must NOT be recorded when the durable commit fails (evidence-before-report)")
	}
	if failSpy.blocks == 0 {
		t.Fatal("a durable-commit failure must be counted as a block/evaluation error")
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
