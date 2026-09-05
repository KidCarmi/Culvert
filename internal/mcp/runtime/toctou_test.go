package runtime

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// recordingExec captures whether the guarded executor was reached, standing in for
// "an irreversible upstream side effect happened".
type recordingExec struct {
	reached int
	gotTool string
}

func (e *recordingExec) Execute(_ context.Context, in ExecInput, _ rollout.Resolution) ExecOutput {
	e.reached++
	if in.Input.Tool != nil {
		e.gotTool = in.Input.Tool.FingerprintHash
	}
	return ExecOutput{Status: 200, Disposition: DispObserveOnly, ExecutionState: "not_implemented"}
}

// Resolve returns a non-record-only disposition so the runtime always reaches Execute
// (this fixture verifies the runtime's entry-side tool-drift refusal before the executor).
func (e *recordingExec) Resolve(ExecInput) rollout.Resolution {
	return rollout.Resolution{Disposition: rollout.EffectShadowEvaluate}
}

// KillActive: these fixtures never engage the kill switch.
func (e *recordingExec) KillActive() bool { return false }

// ingestTool publishes a tool into the catalog with the given input schema, and
// returns its resulting fingerprint hash.
func ingestTool(t *testing.T, reg *registry.Registry, cat *catalog.Catalog, server, name, inputSchema string) string {
	t.Helper()
	raw := []byte(`{"tools":[{"name":"` + name + `","inputSchema":` + inputSchema + `}]}`)
	srv, ok := reg.Current().Get(registry.ServerID(server))
	if !ok {
		t.Fatalf("server %s not registered", server)
	}
	if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
		ServerID: registry.ServerID(server), Identity: srv.PinnedIdentity, Raw: raw,
	}); err != nil {
		t.Fatalf("ingest %s: %v", name, err)
	}
	rec, ok := cat.Current().Get(catalog.ToolKey{Server: registry.ServerID(server), Name: name})
	if !ok {
		t.Fatalf("tool %s not in catalog after ingest", name)
	}
	sum := rec.Fingerprint.Sum()
	return hex.EncodeToString(sum[:])
}

// mutatingInspection fires inside the REAL decision->execution window. The
// pipeline consults the inspection provider AFTER buildPolicyInput has read the
// catalog and BEFORE dispatchExecute, so this is exactly where a concurrent
// discovery (execution.Discovery -> catalog.Ingest) would land. It returns
// ok=false so no inspection actually runs — the hook exists only to move the
// catalog under the in-flight decision, deterministically.
type mutatingInspection struct {
	fire func()
	done bool
}

func (m *mutatingInspection) InspectionProfile(protocol.Capability) (inspection.Profile, bool) {
	if !m.done {
		m.done = true
		m.fire()
	}
	return inspection.Profile{}, false
}

// OVN-09. The policy decision is computed against a catalog SNAPSHOT. Between the
// decision and the irreversible upstream call there is a real window —
// inspection, durable event commit, credential planning, provider fetch — during
// which a concurrent discovery can change the tool the decision was made about.
//
// Nothing re-validated it. The executor consumed the decision's
// Tool.FingerprintHash and never compared it to the live catalog, so a tool
// rug-pull landing inside that window would be EXECUTED under a decision made
// about a DIFFERENT tool, and the durable event would record the stale
// fingerprint — evidence naming a tool that was not the one called. That is the
// drift MCP-TOOL-001 / MCP-T-011 / MCP-T-016 exist to prevent.
//
// Execution is dormant, which is why this is the time to close it.
func TestTOCTOU_CatalogChangeInsideTheWindowNeverReachesTheExecutor(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	before := ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object","properties":{"a":{"type":"string"}}}`)

	ex := &recordingExec{}
	deps.Executor = ex
	deps.Policy = fakePolicy{gw: gwPolicySnap(t,
		`{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE",`+
			`"remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	p := newGatewayPipeline(t, deps)
	tok, sid := driveToDecisionPoint(t, p, k)

	// Control: with a stable catalog the executor IS reached, so a later
	// zero-reach result means the guard fired and not that the fixture is inert.
	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(2)), sid), fixedClock())
	if ex.reached != 1 {
		t.Fatalf("control: executor reached %d times, want 1 (status %d, reason %v)", ex.reached, out.Status, out.Reason)
	}
	if ex.gotTool != before {
		t.Fatalf("control: executor saw fingerprint %q, want %q", ex.gotTool, before)
	}

	// Now move the catalog INSIDE the window: same tool name, different schema, so
	// a different fingerprint.
	var after string
	deps.Inspection = &mutatingInspection{fire: func() {
		after = ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x",
			`{"type":"object","properties":{"a":{"type":"string"},"cmd":{"type":"string"}}}`)
	}}
	p2 := newGatewayPipeline(t, deps)
	tok2, sid2 := driveToDecisionPoint(t, p2, k)
	ex.reached, ex.gotTool = 0, ""

	drifted := p2.Process(context.Background(), withSession(gwRequest(tok2, toolsCallBody(3)), sid2), fixedClock())

	if after == "" || after == before {
		t.Fatalf("fixture did not change the fingerprint inside the window (before=%q after=%q)", before, after)
	}
	if ex.reached != 0 {
		t.Fatalf("the executor was reached under a STALE decision (it saw fingerprint %q while the "+
			"catalog now reports %q): a tool rug-pull inside the decision window was executed", ex.gotTool, after)
	}
	if drifted.Reason != mcperr.ReasonDecisionSnapshotStale {
		t.Fatalf("reason = %v, want decision_snapshot_stale", drifted.Reason)
	}
	if drifted.Disposition != DispRejected {
		t.Fatalf("disposition = %v, want rejected", drifted.Disposition)
	}
}

// The precise property, driven at the seam: a decision carrying one fingerprint
// must be refused when the live catalog reports another.
func TestTOCTOU_StaleDecisionFingerprintIsRefusedAtTheExecutionBoundary(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	live := ingestTool(t, deps.Registry, deps.Catalog, testServerID, "x", `{"type":"object"}`)

	ex := &recordingExec{}
	deps.Executor = ex
	p := newGatewayPipeline(t, deps)

	// Disposition/Drift are populated exactly as the pipeline populates them
	// (policy.go), from the LIVE record. DispUnset is documented as invalid for a
	// Gateway tool input and the runtime never produces it, so a fixture leaving it
	// zero would differ from the live record on the eligibility axis as well and the
	// refusal below would no longer prove the FINGERPRINT is what refused it.
	liveRec, ok := deps.Catalog.Current().Get(catalog.ToolKey{
		Server: registry.ServerID(testServerID), Name: "x",
	})
	if !ok {
		t.Fatal("the ingested tool is not in the catalog")
	}
	liveDisp, liveDrift := policyDisposition(liveRec.Eligibility)

	rb := p.newRecord(Request{}, fixedClock())
	in := policy.DecisionInput{
		Capability: policy.CapGateway,
		Tool: &policy.Tool{
			Name: "x", ServerID: testServerID, FingerprintHash: "stale" + live,
			Disposition: liveDisp, Drift: liveDrift,
		},
	}
	out, ok := p.refuseOnToolDrift(rb, in, jsonrpc.ID{}, true)
	if !ok {
		t.Fatal("a stale decision fingerprint must be refused at the execution boundary")
	}
	if out.Disposition != DispRejected || out.Reason != mcperr.ReasonDecisionSnapshotStale {
		t.Fatalf("refusal = %v / %v, want rejected / decision_snapshot_stale", out.Disposition, out.Reason)
	}
	if ex.reached != 0 {
		t.Fatal("the executor was reached despite a stale decision")
	}

	// A MATCHING fingerprint must pass through untouched.
	fresh := policy.DecisionInput{
		Capability: policy.CapGateway,
		Tool: &policy.Tool{
			Name: "x", ServerID: testServerID, FingerprintHash: live,
			Disposition: liveDisp, Drift: liveDrift,
		},
	}
	if _, refused := p.refuseOnToolDrift(rb, fresh, jsonrpc.ID{}, true); refused {
		t.Fatal("a current fingerprint must not be refused")
	}
}

// A tool that has DISAPPEARED from the catalog between decision and execution is
// also a stale decision, and must fail closed rather than execute against nothing.
func TestTOCTOU_ToolRemovedAfterDecisionRefusesExecution(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, nil)
	p := newGatewayPipeline(t, deps)

	rb := p.newRecord(Request{}, fixedClock())
	in := policy.DecisionInput{
		Capability: policy.CapGateway,
		Tool:       &policy.Tool{Name: "never-ingested", ServerID: testServerID, FingerprintHash: "abc"},
	}
	if _, refused := p.refuseOnToolDrift(rb, in, jsonrpc.ID{}, true); !refused {
		t.Fatal("a decision naming a tool that is no longer in the catalog must be refused")
	}
}
