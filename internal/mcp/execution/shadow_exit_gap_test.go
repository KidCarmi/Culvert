package execution

// Shadow Exit Gap Closure — evaluator-level mutation proofs (Phase A).
//
// These are the fine-grained, decide()/Execute-level halves of the Shadow → Canary
// Exit-criteria gap closure. They exercise the REAL *ShadowEvaluator on the exact
// production seams (the ToolStillCurrent boundary re-check, the plan-only
// CredentialPlanner, the admission kill short-circuit) and prove that each defensive
// check is LOAD-BEARING: remove it (the "mutation") and a specific assertion flips.
//
// The end-to-end halves — a real drift injected mid-pipeline through the credential
// planner callback, a same-traffic Observe-vs-Shadow denial-parity run, the operator
// runbook driven through the admin API, and the latency regression gate — live in
// package main (shadow_exit_gap_test.go / shadow_exit_latency_test.go). Neither half
// composes a live executor, an upstream client, or a materialize-capable broker.
//
// Boundaries honored here exactly as in the phase brief: NO Canary, NO Production, NO
// LiveExecutor, NO upstream execution, NO Materialize, NO live_execution approval.

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/broker"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// ── shared planner stubs ─────────────────────────────────────────────────────

// exitGapCountingPlanner is a metadata-only CredentialPlanner: it counts Plan calls
// and returns a caller-chosen error, and it exposes NO Materialize (the interface it
// satisfies has none). It performs no provider call, no secret retrieval, no upstream
// dial — exactly the plan-only capability a Shadow evaluator may hold.
type exitGapCountingPlanner struct {
	plans int32
	err   error
}

func (p *exitGapCountingPlanner) Plan(broker.PlanInput) (broker.CredentialPlan, error) {
	atomic.AddInt32(&p.plans, 1)
	return broker.CredentialPlan{}, p.err
}

func (p *exitGapCountingPlanner) count() int32 { return atomic.LoadInt32(&p.plans) }

// exitGapMaterializingPlanner is the HOSTILE "expose Materialize to Shadow" mutation:
// a value that satisfies CredentialPlanner (Plan) AND additionally exposes a
// Materialize method. Supplying it must NOT let the evaluator reach Materialize — the
// evaluator narrows the interface to the bound Plan method value and drops the concrete
// value (SEC — Codex P2 on PR #1226), so Materialize stays structurally unreachable.
type exitGapMaterializingPlanner struct{ exitGapCountingPlanner }

// Materialize gives this stub a live-credential-shaped method the Shadow type graph must
// never be able to reach. Its signature is irrelevant — the structural detector keys on
// the method NAME.
func (p *exitGapMaterializingPlanner) Materialize() {}

// credProfileInput is a would_execute base decision that carries a credential-profile
// obligation, so decide()'s step-5 credential-readiness path engages the planner.
func credProfileInput(profileRef string) runtime.ExecInput {
	in := execInput(policy.ActionAllow, false)
	in.Decision.Obligations.CredentialProfile = profileRef
	return in
}

// ── Criterion 4 — boundary-drift stale, and its two mutations ────────────────

// TestExitGapC4_BoundaryDriftYieldsStaleNotExecute proves the step-6 boundary re-check is
// load-bearing and its outcome is correct:
//
//   - mutation "skip the boundary-drift recheck" (ToolStillCurrent == nil): the same
//     otherwise-allow-class decision reaches would_execute — i.e. deleting the check
//     silently admits a stale decision. This is the exact regression the check exists to
//     prevent, made visible.
//   - mutation "change the stale outcome to would_execute" (drifted hook returns false):
//     the evaluator returns would_fail_stale_decision, NEVER would_execute — a staleness
//     that a fully-enforcing mode would refuse is predicted as a refusal, not laundered
//     into an execute.
//
// Both run on the REAL *ShadowEvaluator.decide over the production ToolStillCurrent seam;
// nothing is fabricated — the outcome is whatever decide() computes from the hook.
func TestExitGapC4_BoundaryDriftYieldsStaleNotExecute(t *testing.T) {
	ev := newShadowEvaluatorForTest(t, stateForMode(t, rollout.ModeShadow))

	// Control / "skip the recheck": with no boundary re-check the decision executes.
	base := execInput(policy.ActionAllow, false)
	base.ToolStillCurrent = nil
	if d := ev.decide(base); d.Outcome != ShadowWouldExecute {
		t.Fatalf("precondition (no drift check): an allow-class decision must reach would_execute, got %q", d.Outcome)
	}

	// Drifted at the boundary: the SAME decision now predicts a stale refusal.
	drifted := execInput(policy.ActionAllow, false)
	consulted := false
	drifted.ToolStillCurrent = func() bool { consulted = true; return false } // drifted since the decision
	d := ev.decide(drifted)
	if !consulted {
		t.Fatal("ToolStillCurrent was never consulted: the boundary drift re-check did not run, so this does not exercise criterion 4")
	}
	if d.Outcome == ShadowWouldExecute {
		t.Fatal("SECURITY: a boundary-drifted decision was laundered into would_execute — staleness must land as would_fail_stale_decision")
	}
	if d.Outcome != ShadowWouldFailStaleDecision {
		t.Fatalf("boundary drift must predict would_fail_stale_decision, got %q", d.Outcome)
	}
}

// ── Criterion 8 — real credential-planning path, and its mutations ───────────

// TestExitGapC8_CredentialReadinessFromPlanAlone drives all three credential-readiness
// cases through the REAL decide() credential step, proving readiness is DERIVED from Plan
// (metadata) alone — never materialized — and that each mutation is caught:
//
//   - no credential profile               → planner NOT called, plan status "none", would_execute.
//   - valid plan (planner err == nil)     → planner called exactly once, status "valid", would_execute.
//   - invalid plan (planner err != nil)   → planner called, status "invalid", would_fail_credential_readiness.
//     Mutation "make an invalid plan appear ready": the outcome would flip to would_execute; the
//     assertion below forbids it.
//   - profile named but NO planner composed (mutation "skip the CredentialPlanner"): mirrors the
//     LIVE no-broker path — no Authorization is attached and the call proceeds, so the outcome is
//     would_execute with the truthful "no_planner_composed" label. Contrasted against the invalid
//     case, this proves the planner call is LOAD-BEARING: with the planner the invalid credential
//     is refused; skipping the planner would silently drop that refusal.
//
// Across every case Plan is metadata-only: 0 materializations, 0 secret retrievals, 0 upstream
// calls (the *ShadowEvaluator holds no capability to do any — Layer B).
func TestExitGapC8_CredentialReadinessFromPlanAlone(t *testing.T) {
	// (1) No credential profile: the planner must not be consulted at all.
	noProfilePlanner := &exitGapCountingPlanner{}
	evNoProfile, err := NewShadowEvaluator(ShadowConfig{
		State: stateForMode(t, rollout.ModeShadow), Events: realEvents(t, nil), Planner: noProfilePlanner,
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	d := evNoProfile.decide(execInput(policy.ActionAllow, false)) // no CredentialProfile obligation
	if d.Outcome != ShadowWouldExecute || d.CredentialPlan != planStatusNone {
		t.Fatalf("no-profile: want would_execute/%s, got %q/%q", planStatusNone, d.Outcome, d.CredentialPlan)
	}
	if noProfilePlanner.count() != 0 {
		t.Fatalf("no-profile: the planner must NOT be consulted when no credential profile is named, got %d Plan call(s)", noProfilePlanner.count())
	}

	// (2) Valid plan: readiness derived from a clean Plan; planner consulted exactly once.
	validPlanner := &exitGapCountingPlanner{err: nil}
	evValid, err := NewShadowEvaluator(ShadowConfig{
		State: stateForMode(t, rollout.ModeShadow), Events: realEvents(t, nil), Planner: validPlanner,
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	d = evValid.decide(credProfileInput("profile:ro"))
	if d.Outcome != ShadowWouldExecute || d.CredentialPlan != planStatusValid {
		t.Fatalf("valid-plan: want would_execute/%s, got %q/%q", planStatusValid, d.Outcome, d.CredentialPlan)
	}
	if validPlanner.count() != 1 {
		t.Fatalf("valid-plan: Planner.Plan must be called exactly once, got %d", validPlanner.count())
	}

	// (3) Invalid plan: a failed Plan must refuse — never appear ready (mutation guard).
	invalidPlanner := &exitGapCountingPlanner{err: errors.New("credential plan rejected: unready profile")}
	evInvalid, err := NewShadowEvaluator(ShadowConfig{
		State: stateForMode(t, rollout.ModeShadow), Events: realEvents(t, nil), Planner: invalidPlanner,
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	d = evInvalid.decide(credProfileInput("profile:ro"))
	if d.Outcome == ShadowWouldExecute {
		t.Fatal("SECURITY: an INVALID credential plan was reported ready (would_execute) — a failed Plan must predict would_fail_credential_readiness")
	}
	if d.Outcome != ShadowWouldFailCredentialReadiness || d.CredentialPlan != planStatusInvalid {
		t.Fatalf("invalid-plan: want would_fail_credential_readiness/%s, got %q/%q", planStatusInvalid, d.Outcome, d.CredentialPlan)
	}
	if invalidPlanner.count() != 1 {
		t.Fatalf("invalid-plan: Planner.Plan must be called exactly once, got %d", invalidPlanner.count())
	}

	// (4) Profile named but NO planner composed — mirrors live no-broker, which now FAILS CLOSED: a
	// credential is required but cannot be planned/materialized, so live blocks before any side effect
	// rather than reach the upstream with no Authorization (Codex P2 round-6). Shadow predicts the same
	// would_fail_credential_readiness; the no_planner_composed label records WHY.
	evNoPlanner, err := NewShadowEvaluator(ShadowConfig{
		State: stateForMode(t, rollout.ModeShadow), Events: realEvents(t, nil), // Planner: nil
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	d = evNoPlanner.decide(credProfileInput("profile:ro"))
	if d.Outcome != ShadowWouldFailCredentialReadiness || d.CredentialPlan != planStatusNoPlanner {
		t.Fatalf("no-planner: want would_fail_credential_readiness/%s (fail closed, mirror live no-broker), got %q/%q", planStatusNoPlanner, d.Outcome, d.CredentialPlan)
	}
}

// TestExitGapC8_MaterializeStructurallyUnreachableEvenWhenSupplied is the "expose Materialize
// capability to Shadow" mutation: a caller supplies a value that satisfies CredentialPlanner
// AND exposes a Materialize method. The evaluator must still narrow it to the bound Plan
// method value and drop the interface, so the materialize-capable value is genuinely
// unreachable from the constructed evaluator — proven both at the value level (Planner field
// cleared; plan is a func) and structurally (the ShadowEvaluator/ShadowConfig type graph
// exposes no field whose method set contains Call or Materialize).
func TestExitGapC8_MaterializeStructurallyUnreachableEvenWhenSupplied(t *testing.T) {
	mat := &exitGapMaterializingPlanner{}
	// Precondition: the supplied concrete value really does expose Materialize.
	if _, ok := reflect.TypeOf(mat).MethodByName("Materialize"); !ok {
		t.Fatal("precondition: the hostile planner must expose a Materialize method for this mutation to be meaningful")
	}

	ev, err := NewShadowEvaluator(ShadowConfig{
		State: stateForMode(t, rollout.ModeShadow), Events: realEvents(t, nil), Planner: mat,
	})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	// Value-level: the interface is dropped; only a bound func is retained.
	if ev.cfg.Planner != nil {
		t.Fatal("SECURITY: the evaluator retained the CredentialPlanner interface — a type assertion could recover the Materialize-capable value")
	}
	if got := reflect.TypeOf(ev.plan).Kind(); got != reflect.Func {
		t.Fatalf("retained credential capability is %v, want a func (a method value cannot be unwrapped to its receiver)", got)
	}
	// Structural: no field of the Shadow type graph exposes Call or Materialize, even though a
	// Materialize-capable value was passed at construction.
	for _, tt := range []reflect.Type{reflect.TypeOf(ShadowConfig{}), reflect.TypeOf(ShadowEvaluator{})} {
		if bad := forbiddenCapabilityFields(tt); len(bad) != 0 {
			t.Fatalf("SECURITY: %s exposes a live execution capability via %v after a Materialize-capable planner was supplied", tt.Name(), bad)
		}
	}
	// And the plan path still works: a valid Plan yields would_execute (the narrowing did not
	// break the plan-only capability it kept).
	if d := ev.decide(credProfileInput("profile:ro")); d.Outcome != ShadowWouldExecute || d.CredentialPlan != planStatusValid {
		t.Fatalf("narrowed planner must still plan: want would_execute/%s, got %q/%q", planStatusValid, d.Outcome, d.CredentialPlan)
	}
}

// ── Criterion 6 — Shadow never softens a denial (divergence mutation guard) ──

// TestExitGapC6_ShadowNeverSoftensADenial is the evaluator-level guard behind the end-to-end
// Observe-vs-Shadow denial-parity proof (package main). Denial parity can only break if the
// Shadow evaluator DIVERGES from the policy verdict — the raw action and reason are stamped
// once, before the mode branch, so Observe and Shadow read the same decision; the only place
// Shadow could alter a denial is its own policy-class → outcome mapping. This drives decide()
// over every non-allow policy class and asserts each maps to a NON-execute outcome while the
// raw evaluated action is preserved verbatim. The "introduce an Observe/Shadow denial
// divergence" mutation — softening any of these into would_execute, or overwriting the
// evaluated action — flips an assertion here.
func TestExitGapC6_ShadowNeverSoftensADenial(t *testing.T) {
	ev := newShadowEvaluatorForTest(t, stateForMode(t, rollout.ModeShadow))
	cases := []struct {
		action policy.Action
		want   ShadowOutcome
	}{
		{policy.ActionDeny, ShadowWouldBlock},
		{policy.ActionRequireApproval, ShadowWouldRequireApproval},
		{policy.ActionRequireConfirmation, ShadowWouldRequireConfirmation},
	}
	for _, c := range cases {
		d := ev.decide(execInput(c.action, false))
		if d.Outcome == ShadowWouldExecute {
			t.Fatalf("SECURITY: policy %s was softened into would_execute — Shadow diverged from the policy denial", c.action)
		}
		if d.Outcome != c.want {
			t.Fatalf("policy %s: shadow outcome=%q want %q", c.action, d.Outcome, c.want)
		}
		// The raw evaluated action is preserved separately from the enforcement prediction,
		// so a DENY is never laundered into an allow-shaped record.
		if d.EvaluatedAction != c.action.String() {
			t.Fatalf("policy %s: evaluated action was altered to %q — the raw verdict must be preserved verbatim", c.action, d.EvaluatedAction)
		}
		if !d.ShadowOverride {
			t.Fatalf("policy %s: shadow_override must be set for a non-allow-class decision", c.action)
		}
	}
	// A hard control (quarantined/unusable tool) must predict would_fail_hard_control, never execute.
	hard := execInput(policy.ActionAllow, false)
	hard.Server = nil // an unusable/absent server record → decide()'s hard-control gate
	if d := ev.decide(hard); d.Outcome != ShadowWouldFailHardControl {
		t.Fatalf("hard control must predict would_fail_hard_control, got %q", d.Outcome)
	}
}

// ── Criterion 9 — kill is honored fail-closed BEFORE Shadow evaluation ───────

// TestExitGapC9_KillShortCircuitsBeforeEvaluation proves the adopted Invariant A: an engaged
// emergency kill stops the request at admission (the top of Execute) BEFORE any Shadow
// evaluation runs — so no would_* verdict is produced and no durable shadow evidence is
// committed. The block is emergency-classed (rollout_emergency_active), matching how the LIVE
// executor short-circuits at its own admission, which is exactly the parity Shadow must keep.
//
// Mutation "ignore the kill switch": dropping the s.cfg.State.Killed() check at Execute entry
// would route the killed request into evaluate() and record a would_execute outcome — the spy
// asserting outcomes==0 catches it. Fabricating a shadow_evaluated/would_block event AFTER
// admission already rejected the request is explicitly NOT done: no evaluation ran, so there is
// no truthful evaluation event to emit (Invariant A rationale — see the report and §12 wording).
func TestExitGapC9_KillShortCircuitsBeforeEvaluation(t *testing.T) {
	st := stateForMode(t, rollout.ModeShadow)
	spy := &spyMetrics{}
	ev, err := NewShadowEvaluator(ShadowConfig{State: st, Events: realEvents(t, nil), Metrics: spy})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	in := execInput(policy.ActionAllow, false) // server s1 ∈ scope: absent a kill this would_execute

	st.EngageKillSwitch("oncall", 1)
	out := runExec(ev, context.Background(), in)

	if out.ExecutionState != "blocked" || out.Reason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("SECURITY: a killed capability must emergency-block at admission, got state=%q reason=%v", out.ExecutionState, out.Reason)
	}
	if out.ExecutionState == "shadow_evaluated" {
		t.Fatal("SECURITY: a killed request must NOT be shadow-evaluated (Invariant A: kill honored before evaluation)")
	}
	// The decisive Invariant-A proof: evaluate() never ran, so NO would_* outcome was recorded.
	if spy.outcomes != 0 {
		t.Fatalf("SECURITY: a would_* outcome was recorded for a killed request (%d) — the kill did not short-circuit before evaluation", spy.outcomes)
	}
	if spy.blocks == 0 {
		t.Fatal("a killed request must be counted as a block/evaluation error")
	}
}
