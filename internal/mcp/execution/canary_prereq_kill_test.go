package execution

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary is the permanent,
// non-vacuous security gate for PREREQ-MCP-KILL-1 (docs/design/mcp/SHADOW-ARCHITECTURE.md
// §10). It was formerly *_KillStateNotRevalidated* and documented the OPEN gap by observing
// one upstream call; it is now inverted to prove the CLOSED invariant.
//
// The prerequisite: the authoritative emergency-kill state is revalidated immediately before
// the irreversible side-effect boundary, so a kill engaged after admission aborts an in-flight
// live call. This test drives that exact window: it engages the kill switch from INSIDE the
// `ToolStillCurrent` hook, which the executor invokes at the boundary immediately before
// `Upstream.Call` — so the kill is live microseconds before the side effect and the hook itself
// reports "not drifted", leaving the boundary kill re-check as the ONLY thing that can stop the
// call. It is non-vacuous precisely because it reaches the real production boundary, not a
// stand-in.
//
// Proven here: boundary hook reached = true, kill engaged = true, upstream calls = 0,
// Executed = false, reason = rollout_emergency_active.
func TestCanaryPrerequisite_KillStateRevalidatedAtSideEffectBoundary(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))

	in := execInput(policy.ActionAllow, false)
	killed := false
	in.ToolStillCurrent = func() bool {
		// Emergency kill engaged AFTER admission, at the boundary, immediately before the
		// upstream side effect. Report "not drifted" so ONLY the boundary kill re-check could
		// stop the call.
		if !killed {
			st.EngageKillSwitch("oncall", 2)
			killed = true
		}
		return true
	}

	out := runExec(e, context.Background(), in)

	if !killed {
		t.Fatal("boundary hook was never invoked — the test did not reach the side-effect boundary, so it proves nothing")
	}
	// PREREQ-MCP-KILL-1 (CLOSED): the boundary re-validates the authoritative kill state, so a
	// kill engaged immediately before the irreversible call aborts it.
	if up.calls != 0 {
		t.Fatalf("SECURITY: an emergency kill engaged at the side-effect boundary must abort the upstream call — got %d upstream call(s), want 0 (PREREQ-MCP-KILL-1)", up.calls)
	}
	if out.Executed {
		t.Fatalf("SECURITY: a boundary emergency-kill refusal must not report Executed=true, got state=%q", out.ExecutionState)
	}
	if out.Reason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("boundary kill refusal reason = %v, want %v (never a transport/durability fault or ReasonNone)", out.Reason, mcperr.ReasonRolloutEmergencyActive)
	}

	// Compensating fact: Shadow reflects a kill at ADMISSION (it never reaches the boundary),
	// so a killed capability yields a terminal block, never a would-execute.
	shSt := stateForMode(t, rollout.ModeShadow)
	shSt.EngageKillSwitch("oncall", 3)
	shadow, err := NewShadowEvaluator(ShadowConfig{State: shSt, Events: realEvents(t, nil)})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	shOut := runExec(shadow, context.Background(), execInput(policy.ActionAllow, false))
	if shOut.Executed || shOut.ExecutionState == "shadow_evaluated" {
		t.Fatalf("a killed Shadow capability must terminally block at admission, not evaluate: executed=%v state=%q", shOut.Executed, shOut.ExecutionState)
	}
}
