package execution

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// TestCanaryPrerequisite_KillStateNotRevalidatedAtSideEffectBoundary is the non-vacuous
// gate for PREREQ-MCP-KILL-1 (docs/design/mcp/SHADOW-ARCHITECTURE.md §10).
//
// The prerequisite: Canary/Production activation is PROHIBITED until the authoritative
// kill state is revalidated immediately before the irreversible side-effect boundary.
// Today it is NOT: `Executor.Execute` checks `State.Killed()` once at admission, but
// `run.go` `callUpstream` — the boundary — does not re-read it. A kill engaged after
// admission but before the boundary therefore does not abort an in-flight live call.
//
// This test drives that exact window: it engages the kill switch inside the
// `ToolStillCurrent` hook, which the executor invokes at the boundary (immediately before
// `Upstream.Call`) — so the kill is live microseconds before the side effect. It asserts
// the CURRENT (gap-present) behaviour: the call still proceeds. It is non-vacuous because
// it exercises the real boundary; it is a placeholder because closing PREREQ-MCP-KILL-1
// means adding a kill re-read at the boundary and INVERTING this assertion to
// `up.calls == 0` (see the §12 exit criterion and the debt-register fix note).
//
// The gap is safe today ONLY because no production executor is composed (arming hooks
// uncalled; AST posture wall in mcp_execution_posture_test.go), so this window is
// unreachable in production. The test also asserts, as the compensating fact, that Shadow
// — which never reaches the boundary — reflects a kill immediately at admission.
func TestCanaryPrerequisite_KillStateNotRevalidatedAtSideEffectBoundary(t *testing.T) {
	st := stateForMode(t, rollout.ModeCanary)
	up := &fakeUpstream{}
	e := newExec(t, st, up, realEvents(t, nil))

	in := execInput(policy.ActionAllow, false)
	killed := false
	in.ToolStillCurrent = func() bool {
		// Emergency kill engaged AFTER admission, at the boundary, immediately before the
		// upstream side effect. Report "not drifted" so ONLY the (missing) kill re-check
		// could stop the call.
		if !killed {
			st.EngageKillSwitch("oncall", 2)
			killed = true
		}
		return true
	}

	out := e.Execute(context.Background(), in)

	if !killed {
		t.Fatal("boundary hook was never invoked — the test did not reach the side-effect boundary, so it proves nothing")
	}

	// PREREQ-MCP-KILL-1 (OPEN): the boundary does not re-validate the kill state, so the
	// call proceeds despite a kill engaged immediately before it. When the prerequisite is
	// CLOSED (a killEpoch re-read added to callUpstream), invert this to `up.calls == 0`,
	// assert the emergency block reason, and check off the §12 Shadow→Canary exit criterion.
	if up.calls != 1 {
		t.Fatalf("expected the CURRENT gap behaviour of exactly 1 upstream call (kill NOT re-validated at the boundary), got %d.\n"+
			"If the boundary kill re-check has been implemented, this is the intended fix: invert this assertion to `up.calls == 0`, "+
			"assert reason rollout_emergency_active, update PREREQ-MCP-KILL-1 in the debt register, and check off the §12 exit criterion.", up.calls)
	}
	_ = out

	// Compensating fact: Shadow reflects a kill at ADMISSION (it never reaches the boundary),
	// so a killed capability yields a terminal block, never a would-execute. This is the
	// reason the boundary re-check is a Canary prerequisite, not a Shadow one.
	shSt := stateForMode(t, rollout.ModeShadow)
	shSt.EngageKillSwitch("oncall", 3)
	shadow, err := NewShadowEvaluator(ShadowConfig{State: shSt, Events: realEvents(t, nil)})
	if err != nil {
		t.Fatalf("NewShadowEvaluator: %v", err)
	}
	shOut := shadow.Execute(context.Background(), execInput(policy.ActionAllow, false))
	if shOut.Executed || shOut.ExecutionState == "shadow_evaluated" {
		t.Fatalf("a killed Shadow capability must terminally block at admission, not evaluate: executed=%v state=%q", shOut.Executed, shOut.ExecutionState)
	}
}
