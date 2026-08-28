package execution

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// OVN-09, residual window.
//
// The runtime refuses a decision whose tool has drifted BEFORE handing it to the
// executor. That narrows the decision/execution TOCTOU window; it does not close
// it. Between the entry check and the irreversible call the executor commits
// durable evidence, plans credentials and fetches provider material — every one of
// which can block — while a concurrent execution.Discovery -> catalog Ingest
// publishes a new snapshot. The upstream call would then run under a decision made
// about a tool that has since been redefined or withdrawn, which is exactly the
// drift MCP-TOOL-001 / MCP-T-011 / MCP-T-016 exist to prevent.
//
// The re-check lives at the top of callUpstream because that closure is the ONE
// place either branch (credential and no-credential) performs the side effect.

func TestToolDrift_RefusedAtTheSideEffectBoundary(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))

	in := execInput(policy.ActionAllow, false)
	checked := false
	in.ToolStillCurrent = func() bool { checked = true; return false }

	out := runExec(e, context.Background(), in)

	if !checked {
		t.Fatal("ToolStillCurrent was never consulted: the executor performs the upstream " +
			"call without re-validating the decision's tool, so the window between the " +
			"runtime's entry check and the side effect is still open")
	}
	if up.calls != 0 {
		t.Fatalf("upstream called %d time(s) under a stale decision — the refusal must "+
			"PRECEDE the irreversible call, not follow it", up.calls)
	}
	if out.Executed {
		t.Fatal("a drift refusal must not be reported as executed")
	}
	if out.Reason != mcperr.ReasonDecisionSnapshotStale {
		t.Fatalf("reason = %v, want %v — a drift refusal is not a transport or durability "+
			"fault and must not be classified as one", out.Reason, mcperr.ReasonDecisionSnapshotStale)
	}
}

// The control. Without it, a re-check that always refused would pass the test
// above while disabling execution entirely.
func TestToolDrift_CurrentToolStillExecutes(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = func() bool { return true }

	out := runExec(e, context.Background(), in)
	if up.calls != 1 {
		t.Fatalf("a current tool must still execute, calls=%d", up.calls)
	}
	if !out.Executed {
		t.Fatal("a current tool must still be marked executed")
	}
}

// A caller with no catalog seam leaves the hook nil. That must behave exactly as
// before the hook existed — inventing drift where there is nothing to compare
// would refuse traffic the gateway is configured to allow.
func TestToolDrift_NilHookIsUnchangedBehaviour(t *testing.T) {
	up := &fakeUpstream{}
	e := newExec(t, stateForMode(t, rollout.ModeCanary), up, realEvents(t, nil))

	in := execInput(policy.ActionAllow, false)
	in.ToolStillCurrent = nil

	if out := runExec(e, context.Background(), in); !out.Executed || up.calls != 1 {
		t.Fatalf("nil hook changed behaviour: executed=%v calls=%d, want true/1", out.Executed, up.calls)
	}
}
