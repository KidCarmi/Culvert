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
//
// The demo bodies are top-level named functions (not inline closures) so the roster stays a flat
// table the gocognit gate can read — each mutation's logic is isolated and independently callable.

// liveMutation binds a mutation name to the named gate that catches it and the demo that drives it.
type liveMutation struct {
	name string // mutation
	gate string // the named gate that catches it
	demo func(t *testing.T)
}

func TestLiveTierMutationCampaign_Roster(t *testing.T) {
	tests := liveMutationRoster()
	if len(tests) < 16 {
		t.Fatalf("mutation campaign must have >= 16 entries, got %d", len(tests))
	}
	for _, tc := range tests {
		t.Run(tc.name, tc.demo)
	}
}

func liveMutationRoster() []liveMutation {
	return []liveMutation{
		{"m1: composed implies armed", "mcpLiveTier.markComposed leaves the armed bit false", mutComposedNotArmed},
		{"m2: arming automatically activates Canary", "arm begins no generation; rollout mode unchanged (TestLiveTier_ComposeAndArmDoesNotActivateCanary)", mutArmDoesNotActivate},
		{"m3: Shadow can reach the live executor", "strengthened execution-posture wall + execution.ShadowConfig cannot carry Upstream/Broker (shadow_capability_test.go)", mutShadowNeverArmsLive},
		{"m4: read-first runtime gate removed", "mcpLiveSideEffectGate rejects a non-read-first op (rollout_out_of_scope)", mutReadFirstCaught},
		{"m5: revoked live approval still executes", "runtime live-trust revalidation rejects (live_trust_revalidation_failed)", mutRevokedTrustCaught},
		{"m6: expired live approval still executes", "canary.SatisfiesLiveExecution rejects an expired approval (TrustExpired) ⇒ trustOK false ⇒ gate rejects", mutExpiredTrustCaught},
		{"m7: budget reservation bypassed", "the gate calls reserveCanaryExecution and rejects a non-granted outcome (rollout_budget_exhausted)", mutBudgetBypassCaught},
		{"m8: N+1 execution reaches upstream", "end-to-end: a total budget of 1 denies the 2nd execution (Upstream.Call stays 1)", mutNPlusOneCaught},
		{"m9: kill boundary removed", "execution.preCallGuard re-reads the kill generation LAST (PREREQ-MCP-KILL-1); rehearsal proof 3", mutKillBoundaryCaught},
		{"m10: tool-freshness boundary removed", "execution.preCallGuard evaluates ToolStillCurrent (execution executor_test.go drift cases)", mutFreshnessBoundaryCaught},
		{"m11: Materialize without the credential gate", "broker.Materialize runs the pre-materialization gate before any decrypt (materialize_test.go)", mutSkipCredGate},
		{"m12: evidence commit bypassed", "execution.runExecute wraps the side effect in Events.CommitThenAct (executor_test.go)", mutSkipCommit},
		{"m13: response inspection bypassed", "execution.finishUpstream runs response DLP before egress (executor_test.go DLP cases)", mutSkipDLP},
		{"m14: quiesce admits a new execution", "mcpLiveTier.admitExecution returns ok=false once admitClosed (gate rejects rollout_mode_invalid)", mutQuiesceRejectsCaught},
		{"m15: restart silently re-arms", "mcpLiveTier.disarmForRestart lands composed+unarmed (TestLiveTier_RestartDoesNotReArm)", mutRestartNoReArm},
		{"m16: rollback keeps the old Canary generation valid", "commit-gate demoteCanary invalidates the generation (rehearsal proof 4; canary runtime tests)", mutRollbackInvalidatesGen},
	}
}

// m1: composition must NEVER arm.
func mutComposedNotArmed(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	lt.markComposed()
	if !lt.composed() || lt.armed() || liveExecDepsConfigured(false) {
		t.Fatal("composition must NEVER arm")
	}
}

// m2: arming must not begin a Canary generation.
func mutArmDoesNotActivate(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	lt.markComposed()
	if err := lt.arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	if globalCanaryRuntime.armed(rollout.CapabilityGateway) {
		t.Fatal("arming must not begin a Canary generation")
	}
}

// m3: arming the SHADOW tier must never arm the LIVE tier. (Structural: the shadow composition file
// may reference NO live-executor symbol — the wall's
// TestExecPosture_LiveExecutorConstructedOnlyByLiveComposition — and ShadowConfig has no
// Upstream/Broker field.)
func mutShadowNeverArmsLive(t *testing.T) {
	resetLiveTierGlobals(t)
	if liveExecDepsConfigured(false) {
		t.Fatal("baseline: live must be unarmed")
	}
	markGatewayShadowDepsReady() // arm ONLY the shadow tier
	if liveExecDepsConfigured(false) {
		t.Fatal("arming the SHADOW tier must never arm the LIVE tier")
	}
}

// m4: a non-read-first op is rejected by the read-first gate.
func mutReadFirstCaught(t *testing.T) {
	g := newInjectedGate(&gateSeams{admitOK: true, readOK: false, trustOK: true, outcome: canary.BudgetGranted})
	if d := g.AdmitSideEffect(gateInput()); d.Admit || d.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("read-first mutation must be caught, got admit=%v reason=%s", d.Admit, d.Reason.Code())
	}
}

// m5: a revoked live approval is rejected by runtime live-trust revalidation.
func mutRevokedTrustCaught(t *testing.T) {
	g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: false, outcome: canary.BudgetGranted})
	if d := g.AdmitSideEffect(gateInput()); d.Admit || d.Reason != mcperr.ReasonLiveTrustRevalidationFailed {
		t.Fatalf("revoked-trust mutation must be caught, got admit=%v", d.Admit)
	}
}

// m6: an expired approval (trust false) is rejected identically to a revoke. (The expiry rejection
// itself lives in canary.SatisfiesLiveExecution's own tests.)
func mutExpiredTrustCaught(t *testing.T) {
	g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: false, outcome: canary.BudgetGranted})
	if d := g.AdmitSideEffect(gateInput()); d.Admit {
		t.Fatal("an expired approval (trust false) must be rejected")
	}
}

// m7: a non-granted budget outcome is rejected by the gate.
func mutBudgetBypassCaught(t *testing.T) {
	g := newInjectedGate(&gateSeams{admitOK: true, readOK: true, trustOK: true, outcome: canary.BudgetDeniedTotal})
	if d := g.AdmitSideEffect(gateInput()); d.Admit || d.Reason != mcperr.ReasonRolloutBudgetExhausted {
		t.Fatalf("budget-bypass mutation must be caught, got admit=%v", d.Admit)
	}
}

// m8: with a total budget of 1, the 2nd execution never reaches the upstream.
func mutNPlusOneCaught(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 1)
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	_ = ex.Execute(context.Background(), in, ex.Resolve(in))
	_ = ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 1 {
		t.Fatalf("the N+1 execution must not reach upstream, calls=%d", up.callCount())
	}
}

// m9: an engaged kill stops the side effect (kill re-read is LAST before Upstream.Call).
func mutKillBoundaryCaught(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	getMCPRollout().gateway.EngageKillSwitch("mut", time.Unix(0, 1).UnixNano())
	in := liveExecInput(policy.OpRead, "t1", "p1")
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 || out.Executed {
		t.Fatalf("an engaged kill must stop the side effect, calls=%d", up.callCount())
	}
}

// m10: a drifted tool does not cross the boundary.
func mutFreshnessBoundaryCaught(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	in.ToolStillCurrent = func() bool { return false } // the tool drifted
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 || out.Executed {
		t.Fatalf("a drifted tool must not cross the boundary, calls=%d", up.callCount())
	}
}

// m11: the pre-materialization credential gate is pinned by the broker + execution packages.
func mutSkipCredGate(t *testing.T) {
	t.Skip("pinned by internal/mcp/credentials/broker + execution tests (LiveGate kept them green)")
}

// m12: the durable evidence commit is pinned by the execution package's CommitThenAct tests.
func mutSkipCommit(t *testing.T) {
	t.Skip("pinned by internal/mcp/execution CommitThenAct tests (LiveGate kept them green)")
}

// m13: the response DLP inspection is pinned by the execution package's finishUpstream DLP tests.
func mutSkipDLP(t *testing.T) {
	t.Skip("pinned by internal/mcp/execution finishUpstream DLP tests (LiveGate kept them green)")
}

// m14: a quiescing tier rejects admission (admitExecution returns ok=false once admitClosed).
func mutQuiesceRejectsCaught(t *testing.T) {
	g := newInjectedGate(&gateSeams{admitOK: false, readOK: true, trustOK: true, outcome: canary.BudgetGranted})
	if d := g.AdmitSideEffect(gateInput()); d.Admit || d.Reason != mcperr.ReasonRolloutModeInvalid {
		t.Fatalf("a quiescing tier must reject admission, got admit=%v", d.Admit)
	}
}

// m15: a restart lands composed+unarmed (disarmForRestart never re-arms).
func mutRestartNoReArm(t *testing.T) {
	resetLiveTierGlobals(t)
	lt := mcpLiveTierFor(rollout.CapabilityGateway)
	lt.markComposed()
	_ = lt.arm(true, "armed")
	lt.disarmForRestart()
	if lt.armed() || liveExecDepsConfigured(false) {
		t.Fatal("a restart must never re-arm")
	}
}

// m16: a demotion invalidates the generation (no longer armed/eligible).
func mutRollbackInvalidatesGen(t *testing.T) {
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
}
