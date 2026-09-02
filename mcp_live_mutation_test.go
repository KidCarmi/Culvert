package main

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// §21 mutation campaign for the LIVE-tier composition/arming/quiesce phase.
//
// Each entry names a MUTATION (a way the safety property could be broken) and demonstrates the
// NAMED GATE that catches it by driving the real composition-layer code with the mutation's
// condition and asserting the fail-closed outcome. Mutations that live inside internal/mcp/execution
// (the kill/freshness boundary, the credential gate, the durable commit, the response DLP) are pinned
// by that package's OWN tests (PREREQ-MCP-KILL-1, executor_test.go, materialize_test.go) — which the
// LiveGate hook kept green (byte-identical when nil) — and are referenced here, not re-proven.

func TestLiveTierMutationCampaign_Roster(t *testing.T) {
	tests := []struct {
		name string // mutation
		gate string // the named gate that catches it
		demo func(t *testing.T)
	}{
		{
			name: "m1: composed implies armed",
			gate: "mcpLiveTier.markComposed leaves the armed bit false",
			demo: func(t *testing.T) {
				resetLiveTierGlobals(t)
				lt := mcpLiveTierFor(rollout.CapabilityGateway)
				lt.markComposed("composed")
				if !lt.composed() || lt.armed() || liveExecDepsConfigured(false) {
					t.Fatal("composition must NEVER arm")
				}
			},
		},
		{
			name: "m2: arming automatically activates Canary",
			gate: "arm begins no generation; rollout mode unchanged (TestLiveTier_ComposeAndArmDoesNotActivateCanary)",
			demo: func(t *testing.T) {
				resetLiveTierGlobals(t)
				lt := mcpLiveTierFor(rollout.CapabilityGateway)
				lt.markComposed("composed")
				if err := lt.arm(true, "armed"); err != nil {
					t.Fatalf("arm: %v", err)
				}
				if globalCanaryRuntime.armed(rollout.CapabilityGateway) {
					t.Fatal("arming must not begin a Canary generation")
				}
			},
		},
		{
			name: "m3: Shadow can reach the live executor",
			gate: "strengthened execution-posture wall + execution.ShadowConfig cannot carry Upstream/Broker (shadow_capability_test.go)",
			demo: func(t *testing.T) {
				// Structural: the shadow composition file may reference NO live-executor symbol (the wall's
				// TestExecPosture_LiveExecutorConstructedOnlyByLiveComposition), and ShadowConfig has no
				// Upstream/Broker field (execution package). Here we assert the SHADOW composition never
				// arms the live tier (composing shadow must not set liveExecDepsConfigured).
				resetLiveTierGlobals(t)
				if liveExecDepsConfigured(false) {
					t.Fatal("baseline: live must be unarmed")
				}
				markGatewayShadowDepsReady() // arm ONLY the shadow tier
				if liveExecDepsConfigured(false) {
					t.Fatal("arming the SHADOW tier must never arm the LIVE tier")
				}
			},
		},
		{
			name: "m4: read-first runtime gate removed",
			gate: "mcpLiveSideEffectGate rejects a non-read-first op (rollout_out_of_scope)",
			demo: func(t *testing.T) {
				g := newInjectedGate(&gateSeams{admitOK: true, readOK: false, trustOK: true, outcome: canary.BudgetGranted})
				if d := g.AdmitSideEffect(gateInput()); d.Admit || d.Reason != mcperr.ReasonRolloutOutOfScope {
					t.Fatalf("read-first mutation must be caught, got admit=%v reason=%s", d.Admit, d.Reason.Code())
				}
			},
		},
		{
			name: "m5: revoked live approval still executes",
			gate: "runtime live-trust revalidation rejects (live_trust_revalidation_failed)",
			demo: func(t *testing.T) {
				g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: false, outcome: canary.BudgetGranted})
				if d := g.AdmitSideEffect(gateInput()); d.Admit || d.Reason != mcperr.ReasonLiveTrustRevalidationFailed {
					t.Fatalf("revoked-trust mutation must be caught, got admit=%v", d.Admit)
				}
			},
		},
		{
			name: "m6: expired live approval still executes",
			gate: "canary.SatisfiesLiveExecution rejects an expired approval (TrustExpired) ⇒ trustOK false ⇒ gate rejects",
			demo: func(t *testing.T) {
				// The expiry rejection lives in canary.SatisfiesLiveExecution (its own tests). At the gate,
				// an expired approval yields trustOK=false, which the gate rejects identically to m5.
				g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: false, outcome: canary.BudgetGranted})
				if d := g.AdmitSideEffect(gateInput()); d.Admit {
					t.Fatal("an expired approval (trust false) must be rejected")
				}
			},
		},
		{
			name: "m7: budget reservation bypassed",
			gate: "the gate calls reserveCanaryExecution and rejects a non-granted outcome (rollout_budget_exhausted)",
			demo: func(t *testing.T) {
				g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: true, outcome: canary.BudgetDeniedTotal})
				if d := g.AdmitSideEffect(gateInput()); d.Admit || d.Reason != mcperr.ReasonRolloutBudgetExhausted {
					t.Fatalf("budget-bypass mutation must be caught, got admit=%v", d.Admit)
				}
			},
		},
		{
			name: "m8: N+1 execution reaches upstream",
			gate: "end-to-end: a total budget of 1 denies the 2nd execution (Upstream.Call stays 1)",
			demo: func(t *testing.T) {
				up := &recordingUpstream{}
				cfg := armCanaryLiveTier(t, up, true, 1)
				ex := cfg.Deps.Executor
				in := liveExecInput(policy.OpRead, "t1", "p1")
				_ = ex.Execute(context.Background(), in, ex.Resolve(in))
				_ = ex.Execute(context.Background(), in, ex.Resolve(in))
				if up.callCount() != 1 {
					t.Fatalf("the N+1 execution must not reach upstream, calls=%d", up.callCount())
				}
			},
		},
		{
			name: "m9: kill boundary removed",
			gate: "execution.preCallGuard re-reads the kill generation LAST (PREREQ-MCP-KILL-1); rehearsal proof 3",
			demo: func(t *testing.T) {
				up := &recordingUpstream{}
				cfg := armCanaryLiveTier(t, up, true, 10)
				ex := cfg.Deps.Executor
				getMCPRollout().gateway.EngageKillSwitch("mut", time.Unix(0, 1).UnixNano())
				in := liveExecInput(policy.OpRead, "t1", "p1")
				out := ex.Execute(context.Background(), in, ex.Resolve(in))
				if up.callCount() != 0 || out.Executed {
					t.Fatalf("an engaged kill must stop the side effect, calls=%d", up.callCount())
				}
			},
		},
		{
			name: "m10: tool-freshness boundary removed",
			gate: "execution.preCallGuard evaluates ToolStillCurrent (execution executor_test.go drift cases)",
			demo: func(t *testing.T) {
				up := &recordingUpstream{}
				cfg := armCanaryLiveTier(t, up, true, 10)
				ex := cfg.Deps.Executor
				in := liveExecInput(policy.OpRead, "t1", "p1")
				in.ToolStillCurrent = func() bool { return false } // the tool drifted
				out := ex.Execute(context.Background(), in, ex.Resolve(in))
				if up.callCount() != 0 || out.Executed {
					t.Fatalf("a drifted tool must not cross the boundary, calls=%d", up.callCount())
				}
			},
		},
		{
			name: "m11: Materialize without the credential gate",
			gate: "broker.Materialize runs the pre-materialization gate before any decrypt (materialize_test.go)",
			demo: func(t *testing.T) {
				t.Skip("pinned by internal/mcp/credentials/broker + execution tests (LiveGate kept them green)")
			},
		},
		{
			name: "m12: evidence commit bypassed",
			gate: "execution.runExecute wraps the side effect in Events.CommitThenAct (executor_test.go)",
			demo: func(t *testing.T) {
				t.Skip("pinned by internal/mcp/execution CommitThenAct tests (LiveGate kept them green)")
			},
		},
		{
			name: "m13: response inspection bypassed",
			gate: "execution.finishUpstream runs response DLP before egress (executor_test.go DLP cases)",
			demo: func(t *testing.T) {
				t.Skip("pinned by internal/mcp/execution finishUpstream DLP tests (LiveGate kept them green)")
			},
		},
		{
			name: "m14: quiesce admits a new execution",
			gate: "mcpLiveTier.admitExecution returns ok=false once admitClosed (gate rejects rollout_mode_invalid)",
			demo: func(t *testing.T) {
				g := newInjectedGate(&gateSeams{admitOK: false, readOK: true, trustOK: true, outcome: canary.BudgetGranted})
				if d := g.AdmitSideEffect(gateInput()); d.Admit || d.Reason != mcperr.ReasonRolloutModeInvalid {
					t.Fatalf("a quiescing tier must reject admission, got admit=%v", d.Admit)
				}
			},
		},
		{
			name: "m15: restart silently re-arms",
			gate: "mcpLiveTier.disarmForRestart lands composed+unarmed (TestLiveTier_RestartDoesNotReArm)",
			demo: func(t *testing.T) {
				resetLiveTierGlobals(t)
				lt := mcpLiveTierFor(rollout.CapabilityGateway)
				lt.markComposed("composed")
				_ = lt.arm(true, "armed")
				lt.disarmForRestart()
				if lt.armed() || liveExecDepsConfigured(false) {
					t.Fatal("a restart must never re-arm")
				}
			},
		},
		{
			name: "m16: rollback keeps the old Canary generation valid",
			gate: "commit-gate demoteCanary invalidates the generation (rehearsal proof 4; canary runtime tests)",
			demo: func(t *testing.T) {
				resetLiveTierGlobals(t)
				setDataDirForTest(t, t.TempDir())
				capb := rollout.CapabilityGateway
				if _, err := globalCanaryRuntime.beginCanaryActivation(capb, runtimeTestBudget(10), time.Unix(0, 1)); err != nil {
					t.Fatalf("begin: %v", err)
				}
				if !globalCanaryRuntime.armed(capb) {
					t.Fatal("precondition: armed")
				}
				if err := globalCanaryRuntime.demoteCanary(capb); err != nil {
					t.Fatalf("demote: %v", err)
				}
				if globalCanaryRuntime.armed(capb) || globalCanaryRuntime.executionEligible(capb, time.Unix(0, 1)) {
					t.Fatal("a demotion must invalidate the generation (no longer armed/eligible)")
				}
			},
		},
	}
	if len(tests) < 16 {
		t.Fatalf("mutation campaign must have >= 16 entries, got %d", len(tests))
	}
	for _, tc := range tests {
		t.Run(tc.name, tc.demo)
	}
}
