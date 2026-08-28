package runtime

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// hookCapturingExec captures the last-moment revalidation hook the runtime hands
// the executor, and can drive catalog drift from INSIDE the executor — i.e. from
// exactly the region the entry check cannot cover.
type hookCapturingExec struct {
	reached      int
	beforeDrift  bool
	afterDrift   bool
	driftInside  func()
	sawHookIsNil bool
}

// Resolve returns a non-record-only disposition so the runtime always reaches Execute
// (this fixture exercises the last-moment drift re-check the runtime hands the executor).
func (e *hookCapturingExec) Resolve(ExecInput) rollout.Resolution {
	return rollout.Resolution{Disposition: rollout.EffectShadowEvaluate}
}

func (e *hookCapturingExec) Execute(_ context.Context, in ExecInput, _ rollout.Resolution) ExecOutput {
	e.reached++
	if in.ToolStillCurrent == nil {
		e.sawHookIsNil = true
		return ExecOutput{Status: 200, Disposition: DispObserveOnly, ExecutionState: "not_implemented"}
	}
	e.beforeDrift = in.ToolStillCurrent()
	if e.driftInside != nil {
		e.driftInside()
	}
	e.afterDrift = in.ToolStillCurrent()
	return ExecOutput{Status: 200, Disposition: DispObserveOnly, ExecutionState: "not_implemented"}
}

// OVN-09, residual window — the WIRING half.
//
// The executor's last-moment re-check can only close the window if the runtime
// actually hands it a hook that reads the LIVE catalog. An unwired (nil) seam
// leaves the executor with nothing to consult while every unit test in the
// execution package still passes, which is the defect class this whole review
// exists to catch: a control that is designed, documented and tested in isolation
// but never invoked by the request path.
//
// The catalog is moved from INSIDE Execute, so the drift lands strictly after the
// runtime's entry check has already passed — the region the entry check cannot
// see.
func TestTOCTOU_ExecutorReceivesALiveRevalidationHook(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	before := ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)

	ex := &hookCapturingExec{}
	deps.Executor = ex
	deps.Policy = fakePolicy{gw: gwPolicySnap(t,
		`{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE",`+
			`"remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}

	var after string
	ex.driftInside = func() {
		after = ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x",
			`{"type":"object","properties":{"cmd":{"type":"string"}}}`)
	}

	p := newGatewayPipeline(t, deps)
	tok, sid := driveToDecisionPoint(t, p, k)
	p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())

	if ex.reached != 1 {
		t.Fatalf("executor reached %d times, want 1 — the fixture never got to the seam", ex.reached)
	}
	if ex.sawHookIsNil {
		t.Fatal("the runtime handed the executor a nil ToolStillCurrent: the last-moment " +
			"revalidation seam is unwired, so the window between the entry check and the " +
			"irreversible upstream call is still open in production")
	}
	if after == "" || after == before {
		t.Fatalf("fixture did not change the fingerprint inside Execute (before=%q after=%q)", before, after)
	}
	if !ex.beforeDrift {
		t.Fatal("the hook reported drift for an UNCHANGED catalog: it would refuse every " +
			"execution, which is a denial of service dressed as a security control")
	}
	if ex.afterDrift {
		t.Fatal("the hook still reported the tool as current after the catalog changed " +
			"under it: it is not reading live state, so it closes nothing")
	}
}
