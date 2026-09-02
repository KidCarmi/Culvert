package main

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// §13 abort-controller runtime wiring + §14 evidence truth.
//
// The objective, in-hand breach signals — whole-Canary budget exhaustion and a per-identity
// blast-radius (scope-escape) cap — trip the abort controller INSIDE reserveCanaryExecution, so the
// breach stops the WHOLE Canary (execution-ineligible), not merely the one request. Per-request
// fail-closed refusals that are NOT objective whole-Canary breaches (a drifted tool, a revoked trust,
// a non-read-first op, an emergency kill) stop the request and are surfaced with DISTINCT bounded
// reasons; escalating those to a whole-Canary abort is an explicit, recorded owner decision
// (threshold ownership for error-rate/latency pathologies is deliberately left unresolved — §13).

// §13: budget exhaustion trips the whole-Canary abort — the Canary becomes execution-ineligible.
func TestLiveAbort_BudgetExhaustionTripsWholeCanary(t *testing.T) {
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 1) // total budget = 1
	ex := cfg.Deps.Executor
	capb := rollout.CapabilityGateway
	in := liveExecInput(policy.OpRead, "t1", "p1")

	// First execution consumes the whole budget and crosses the boundary.
	_ = ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != 1 {
		t.Fatalf("first execution should cross once, calls=%d", up.callCount())
	}
	// Second execution: the budget is exhausted, which TRIPS the whole-Canary abort inside
	// reserveCanaryExecution — so the Canary as a whole is now ineligible.
	_ = ex.Execute(context.Background(), in, ex.Resolve(in))
	if globalCanaryRuntime.executionEligible(capb, time.Unix(0, 1)) {
		t.Fatal("a whole-Canary budget exhaustion must trip the abort so the Canary is execution-ineligible (not just one request denied)")
	}
	// A third execution stays denied and never reaches the upstream (the abort latched).
	before := up.callCount()
	_ = ex.Execute(context.Background(), in, ex.Resolve(in))
	if up.callCount() != before {
		t.Fatalf("no execution may cross after the whole-Canary abort latched, delta=%d", up.callCount()-before)
	}
}

// §14: the durable refusal REASONS are distinct, so evidence can tell apart approved+executed,
// budget-aborted, kill-aborted, stale-aborted, and trust-revoked outcomes.
func TestLiveEvidence_DistinctRefusalReasons(t *testing.T) {
	// executed
	up := &recordingUpstream{}
	cfg := armCanaryLiveTier(t, up, true, 10)
	ex := cfg.Deps.Executor
	in := liveExecInput(policy.OpRead, "t1", "p1")
	if out := ex.Execute(context.Background(), in, ex.Resolve(in)); !out.Executed {
		t.Fatalf("approved read must be executed, out=%+v", out)
	}

	// stale-aborted (tool drift) — distinct reason.
	in2 := liveExecInput(policy.OpRead, "t1", "p1")
	in2.ToolStillCurrent = func() bool { return false }
	if out := ex.Execute(context.Background(), in2, ex.Resolve(in2)); out.Reason != mcperr.ReasonDecisionSnapshotStale {
		t.Fatalf("tool drift reason=%s want decision_snapshot_stale", out.Reason.Code())
	}

	// kill-aborted — distinct reason.
	getMCPRollout().gateway.EngageKillSwitch("t", time.Unix(0, 1).UnixNano())
	if out := ex.Execute(context.Background(), in, ex.Resolve(in)); out.Reason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("kill reason=%s want rollout_emergency_active", out.Reason.Code())
	}
	getMCPRollout().gateway.ClearKillSwitch()

	// read-first refusal — distinct reason.
	inC := liveExecInput(policy.OpControl, "t1", "p1")
	if out := ex.Execute(context.Background(), inC, ex.Resolve(inC)); out.Reason != mcperr.ReasonRolloutOutOfScope {
		t.Fatalf("read-first reason=%s want rollout_out_of_scope", out.Reason.Code())
	}
}
