package runtime

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// recordOnlyKilledExec resolves every request to record-only (so the runtime takes the
// inline Observe fall-through, never Execute) and reports a configurable kill state.
type recordOnlyKilledExec struct {
	killed         bool
	executeReached int
}

func (e *recordOnlyKilledExec) Resolve(ExecInput) rollout.Resolution {
	return rollout.Resolution{Disposition: rollout.EffectRecordOnly}
}

func (e *recordOnlyKilledExec) Execute(context.Context, ExecInput, rollout.Resolution) ExecOutput {
	e.executeReached++
	return ExecOutput{Status: 200, Disposition: DispObserveOnly, ExecutionState: "not_implemented"}
}

func (e *recordOnlyKilledExec) KillActive() bool { return e.killed }

// TestKill_RecordOnlyPathHonorsKillEngagedAfterResolve pins the round-8 correction (Codex P2,
// PR #1234): a record-only disposition takes the inline Observe fall-through and never reaches
// Execute, so Execute's entry kill re-check cannot cover it. The runtime therefore re-checks
// the current kill on that fall-through — a kill engaged after Resolve must block even a
// record-only request, because the kill is a capability-wide admission stop. Mutation:
// removing the record-only kill re-check lets the request continue through the Observe path
// under an active kill and fails this gate.
func TestKill_RecordOnlyPathHonorsKillEngagedAfterResolve(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	ex := &recordOnlyKilledExec{killed: true}
	deps.Executor = ex
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	p := newGatewayPipeline(t, deps)

	tok, sid := driveToDecisionPoint(t, p, k)
	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsListBody(2)), sid), fixedClock())
	if out.Disposition != DispRejected || out.Reason != mcperr.ReasonRolloutEmergencyActive {
		t.Fatalf("a record-only request under an active kill must emergency-block, got %v / %v", out.Disposition, out.Reason)
	}
	if ex.executeReached != 0 {
		t.Fatalf("the record-only path must not reach Execute (reached %d)", ex.executeReached)
	}

	// Control: with the kill cleared, the record-only disposition falls through to the inline
	// Observe path and is NOT emergency-blocked — so the block above is the kill, not the path.
	ex.killed = false
	tok2, sid2 := driveToDecisionPoint(t, p, k)
	out2 := p.Process(context.Background(), withSession(gwRequest(tok2, toolsListBody(3)), sid2), fixedClock())
	if out2.Reason == mcperr.ReasonRolloutEmergencyActive {
		t.Fatal("with the kill cleared, the record-only path must not emergency-block")
	}
}
