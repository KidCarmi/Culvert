package main

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// End-to-end controlled live execution + the CANARY-ROLLBACK-LIVE-QUIESCE-REHEARSAL (§15).
//
// These drive the REAL composed live executor through the REAL side-effect gate to a SYNTHETIC
// recording upstream (§19: controlled side effects in tests only — no external server, no real
// credential, every invocation counted). The runtime live-trust revalidation is exercised with a
// deterministic seam (its own logic is proven by the gate-logic and red-team tests); everything
// else — the lifecycle admission, the Canary budget reservation, the executor boundary
// (freshness+kill), and the coordinator rollback — is the production path.

// liveRealGate builds the production gate wired to the real composition-layer singletons, with only
// the trust seam controlled (true ⇒ a valid live approval; false ⇒ none). Budget reservation,
// lifecycle admission, and read-first are all REAL.
func liveRealGate(capb rollout.Capability, trustOK bool) *mcpLiveSideEffectGate {
	return &mcpLiveSideEffectGate{
		capb:      capb,
		admit:     mcpLiveTierFor(capb).admitExecution,
		readFirst: canary.IsReadFirstOperation,
		trustOK:   func(string, string, string, string, time.Time) bool { return trustOK },
		reserve: func(now time.Time, ident canary.ExecutionIdentity) (canary.BudgetOutcome, uint64) {
			return globalCanaryRuntime.reserveCanaryExecution(capb, now, ident)
		},
		releaseBudget: func(gen uint64) { globalCanaryRuntime.releaseCanaryExecution(capb, gen) },
		note:          noteMCPLiveGateDenied,
	}
}

// armCanaryLiveTier sets up a fully COMPOSED + ARMED + Canary-ACTIVE live tier for a controlled
// execution: the global rollout gateway state is Canary (scope admits s1), the canary runtime is
// begun with budgetTotal, the lifecycle is armed, and the live executor is composed with a
// controlled-trust gate and the given recording upstream. It returns the runtime Config (with
// Deps.Executor installed). All global state is restored on cleanup.
func armCanaryLiveTier(t *testing.T, up *recordingUpstream, trustOK bool, budgetTotal int) *mcpruntime.Config {
	t.Helper()
	resetLiveTierGlobals(t)
	setDataDirForTest(t, t.TempDir())

	// Put the global rollout gateway state into Canary (scope admits server s1).
	gw := getMCPRollout().gateway
	prevCfg := gw.CurrentConfig()
	if err := gw.SetConfig(*gwCanaryCfg(1), "test", time.Unix(0, 1).UnixNano()); err != nil {
		t.Fatalf("SetConfig canary: %v", err)
	}
	t.Cleanup(func() { _ = gw.SetConfig(prevCfg, "test-restore", time.Unix(0, 2).UnixNano()) })

	// Compose the live executor with the controlled-trust gate + recording upstream.
	cfg := &mcpruntime.Config{}
	if err := composeGatewayLiveTierInto(cfg, liveTierComposition{
		Upstream: up, Events: liveTestEvents(t),
		ResponseProfile: inspection.DefaultGatewayProfile(1),
		Clock:           func() time.Time { return time.Unix(0, 1) },
		LiveGate:        liveRealGate(rollout.CapabilityGateway, trustOK),
	}); err != nil {
		t.Fatalf("compose live tier: %v", err)
	}
	// Arm the lifecycle (composed→armed).
	if err := mcpLiveTierFor(rollout.CapabilityGateway).arm(true, "armed"); err != nil {
		t.Fatalf("arm: %v", err)
	}
	// Begin the Canary runtime budget (the gate reserves against it).
	if _, err := globalCanaryRuntime.beginCanaryActivation(rollout.CapabilityGateway, runtimeTestBudget(budgetTotal), time.Unix(0, 1)); err != nil {
		t.Fatalf("beginCanaryActivation: %v", err)
	}
	return cfg
}

// TestLiveE2E_ApprovedReadExecutes proves the happy path: a Canary-active, armed, trusted,
// in-budget, read-first request crosses the boundary and the recording upstream sees EXACTLY one
// invocation, reported executed.
func TestLiveE2E_ApprovedReadExecutes(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 1 {
		t.Fatalf("an approved read-first Canary request must cross the boundary exactly once, calls=%d out=%+v", up.callCount(), out)
	}
	if !out.Executed {
		t.Fatalf("the request must be reported executed, out=%+v", out)
	}
}

// TestLiveE2E_BudgetDenialMeansUpstreamZero proves §8: once the budget is spent, the next execution
// is denied at the gate and the upstream is NEVER reached.
func TestLiveE2E_BudgetDenialMeansUpstreamZero(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 1) // total budget = 1
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	// First execution consumes the whole budget.
	_ = ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 1 {
		t.Fatalf("first execution should cross once, calls=%d", up.callCount())
	}
	// Second execution: budget exhausted ⇒ denied ⇒ upstream not called again.
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 1 {
		t.Fatalf("budget-denied execution must make Upstream.Call == 0 (still 1 total), calls=%d", up.callCount())
	}
	if out.Reason != mcperr.ReasonRolloutBudgetExhausted {
		t.Fatalf("budget-denied reason=%s want rollout_budget_exhausted", out.Reason.Code())
	}
}

// TestLiveE2E_TrustRevokedMeansUpstreamZero proves §10: a request whose live trust does not
// revalidate at the boundary is denied and the upstream is never reached (even though Canary is
// active and the budget has room).
func TestLiveE2E_TrustRevokedMeansUpstreamZero(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, false, 10) // trustOK=false ⇒ no valid live approval
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 {
		t.Fatalf("a request with no valid live trust must make Upstream.Call == 0, calls=%d", up.callCount())
	}
	if out.Reason != mcperr.ReasonLiveTrustRevalidationFailed {
		t.Fatalf("trust-revoked reason=%s want live_trust_revalidation_failed", out.Reason.Code())
	}
}

// TestLiveE2E_ControlOperationRejectedByReadFirst proves §9: a non-read-first operation (OpControl)
// is rejected at the gate before the boundary, even disguised in the read RiskClass bucket.
func TestLiveE2E_ControlOperationRejectedByReadFirst(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpControl, "t1", "p1") // OpControl folds into RiskRead but is NOT read-first
	out := ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 0 {
		t.Fatalf("an OpControl request must be rejected before upstream (§9), calls=%d", up.callCount())
	}
	if out.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("read-first refusal reason=%s want rollout_out_of_scope", out.Reason.Code())
	}
}
