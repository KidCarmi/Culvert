package runtime

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/dlp"
	"github.com/KidCarmi/Culvert/internal/mcp/jsonrpc"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// fakeInspection is a test InspectionProvider returning a fixed Gateway profile.
type fakeInspection struct{ gw inspection.Profile }

func (f fakeInspection) InspectionProfile(capNS protocol.Capability) (inspection.Profile, bool) {
	if capNS == protocol.Gateway {
		return f.gw, true
	}
	return inspection.Profile{}, false
}

func gwInspectionProfile(t *testing.T) inspection.Profile {
	t.Helper()
	rules, err := destination.CompileRules([]string{"/url"}, true, limits.DefaultGatewayInspection())
	if err != nil {
		t.Fatal(err)
	}
	p, err := inspection.NewProfile(inspection.ProfileConfig{
		Capability: "gateway", Limits: limits.DefaultGatewayInspection(),
		DestPolicy: destination.DefaultGatewayPolicy(), Extraction: rules, Revision: 4,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func inspectionPipeline(t *testing.T, k *esKey, pol PolicyProvider, insp InspectionProvider) *pipeline {
	t.Helper()
	deps := testDeps(t, k, NewBoundedSink(16))
	deps.Policy = pol
	deps.Inspection = insp
	ctr := &counters{}
	p, err := newPipeline(gwListenerConfig(t), deps, "test-gw", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	return p
}

func toolsCallArgs(id int, name, argsJSON string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + argsJSON + `}}`)
}

// broadAllow is a rule that ALLOWs any tools/call (used to prove inspection hard
// failures beat a broad ALLOW).
const broadAllow = `{"id":"ALLOW_ALL","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"operation.namespace","op":"exact","value":"gateway_tool"}],"obligations":{"logging":"standard"}}`

// TestInspection_SSRFHardBlockBeatsAllow: a private-IP destination in the args is a
// hard SSRF block BEFORE policy — even a broad ALLOW cannot permit it.
func TestInspection_SSRFHardBlockBeatsAllow(t *testing.T) {
	k := newESKey(t, "k1")
	p := inspectionPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, broadAllow)}, fakeInspection{gw: gwInspectionProfile(t)})
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(withSession(gwRequest(tok, toolsCallArgs(3, "fetch", `{"url":"https://10.0.0.1/x"}`)), sid), fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("SSRF must be rejected, got %v", out.Disposition)
	}
	if out.Reason != mcperr.ReasonSSRFBlocked {
		t.Fatalf("reason = %v, want ssrf_blocked", out.Reason.Code())
	}
	if out.Record.PolicyAction != "BLOCKED_BY_INSPECTION" {
		t.Fatalf("record action = %q, want BLOCKED_BY_INSPECTION", out.Record.PolicyAction)
	}
}

// TestInspection_SecretHardBlockBeatsAllow: a secret in the args hard-blocks before
// policy regardless of a broad ALLOW.
func TestInspection_SecretHardBlockBeatsAllow(t *testing.T) {
	k := newESKey(t, "k1")
	jwt := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`
	p := inspectionPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, broadAllow)}, fakeInspection{gw: gwInspectionProfile(t)})
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(withSession(gwRequest(tok, toolsCallArgs(3, "echo", `{"token":"`+jwt+`"}`)), sid), fixedClock())
	if out.Disposition != DispRejected || out.Reason != mcperr.ReasonSecretDetected {
		t.Fatalf("secret must hard-block: disp=%v reason=%v", out.Disposition, out.Reason.Code())
	}
}

// TestInspection_CleanArgsPolicyGoverns: clean args do NOT hard-fail; policy still
// governs (here the unknown tool is quarantined), and the inspection facts are
// recorded (inspection ran but did not block).
func TestInspection_CleanArgsPolicyGoverns(t *testing.T) {
	k := newESKey(t, "k1")
	p := inspectionPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, broadAllow)}, fakeInspection{gw: gwInspectionProfile(t)})
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(withSession(gwRequest(tok, toolsCallArgs(3, "echo", `{"msg":"hello"}`)), sid), fixedClock())
	// Unknown tool (empty catalog) → hard quarantine override by policy, NOT inspection.
	if out.Record.PolicyAction != "QUARANTINE" {
		t.Fatalf("expected policy QUARANTINE for unknown tool, got %q (reason %v)", out.Record.PolicyAction, out.Reason.Code())
	}
	// Inspection ran and recorded facts (revision stamped).
	if out.Record.InspectionRevision != 4 {
		t.Fatalf("inspection facts not recorded: revision=%d", out.Record.InspectionRevision)
	}
}

// TestInspection_ToolsListUnchanged: tools/list is NOT inspected (inspection is a
// tools/call concern) — the decision path is unchanged.
func TestInspection_ToolsListUnchanged(t *testing.T) {
	k := newESKey(t, "k1")
	rule := `{"id":"ALLOW_LIST","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}],"obligations":{"logging":"standard"}}`
	p := inspectionPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, rule)}, fakeInspection{gw: gwInspectionProfile(t)})
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispPolicyAllowed {
		t.Fatalf("tools/list allow-class unchanged expected, got %v", out.Disposition)
	}
	if out.Record.InspectionRevision != 0 {
		t.Fatalf("tools/list must not run inspection, got revision %d", out.Record.InspectionRevision)
	}
}

// TestInspection_ManagementDoesNotRunGatewayInspection: a Management pipeline never
// runs Gateway inspection (capability isolation).
func TestInspection_ManagementDoesNotRunGatewayInspection(t *testing.T) {
	k := newESKey(t, "k1")
	deps := testDeps(t, k, NewBoundedSink(16))
	deps.Policy = fakePolicy{mgmt: nil} // management snapshot absent → fail closed
	deps.Inspection = fakeInspection{gw: gwInspectionProfile(t)}
	ctr := &counters{}
	p, err := newPipeline(mgmtListenerConfig(t), deps, "test-mgmt", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline mgmt: %v", err)
	}
	if p.inspection == nil {
		t.Fatal("management pipeline should still carry the provider (it just never resolves a gateway profile)")
	}
	// runInspection must not run for a Management capability (capability gate).
	run := p.runInspection(Request{ServerID: ""}, jsonrpc.Message{Class: jsonrpc.ClassRequest, Method: "tools/call"}, fixedClock())
	if run.ran {
		t.Fatal("management capability must not run gateway inspection")
	}
}

// TestSatisfyRedaction_RequiresRealEvidence proves the ALLOW_WITH_REDACTION wiring
// only succeeds with a real re-validated transform, and fails closed otherwise.
func TestSatisfyRedaction_RequiresRealEvidence(t *testing.T) {
	set := map[dlp.Classification]struct{}{dlp.ClassBearerToken: {}}
	rp := inspectionRedactionProfile(t, set)
	jwt := `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`
	args := decodeArgsForTest(t, rp, `{"token":"`+jwt+`","keep":"x"}`)
	run := inspectionRun{ran: true, profile: rp, args: args}

	// A proper ALLOW_WITH_REDACTION obligation → satisfied with real evidence.
	d := policy.Decision{Action: policy.ActionAllowWithRedaction, Obligations: policy.Obligations{
		Redaction: &policy.RedactionReq{ProfileRef: "r1", TransformedHashRequired: true}}}
	rb := &recBuilder{}
	if !(&pipeline{}).satisfyRedaction(rb, run, d) {
		t.Fatal("valid redaction obligation must be satisfiable")
	}
	if !rb.rec.RedactionApplied || rb.rec.TransformedHash == "" {
		t.Fatalf("redaction evidence not recorded: %+v", rb.rec)
	}

	// A missing obligation profile → fail closed.
	d2 := policy.Decision{Action: policy.ActionAllowWithRedaction, Obligations: policy.Obligations{
		Redaction: &policy.RedactionReq{ProfileRef: "nonexistent", TransformedHashRequired: true}}}
	if (&pipeline{}).satisfyRedaction(&recBuilder{}, run, d2) {
		t.Fatal("missing redaction profile must fail closed")
	}
	// No obligation at all → fail closed.
	if (&pipeline{}).satisfyRedaction(&recBuilder{}, run, policy.Decision{Action: policy.ActionAllowWithRedaction}) {
		t.Fatal("absent redaction obligation must fail closed")
	}
}

// --- helpers ---------------------------------------------------------------

func inspectionRedactionProfile(t *testing.T, classes map[dlp.Classification]struct{}) inspection.Profile {
	t.Helper()
	disp := map[dlp.Classification]inspection.Disposition{dlp.ClassBearerToken: inspection.DispRedact}
	classSlice := make([]dlp.Classification, 0, len(classes))
	for c := range classes {
		classSlice = append(classSlice, c)
	}
	p, err := inspection.NewProfile(inspection.ProfileConfig{
		Capability: "gateway", Limits: limits.DefaultGatewayInspection(),
		DestPolicy:   destination.DefaultGatewayPolicy(),
		Dispositions: disp, Revision: 9,
		RedactionProfiles: []inspection.RedactionProfile{inspection.NewRedactionProfile("r1", 5, classSlice, true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func decodeArgsForTest(t *testing.T, p inspection.Profile, argsJSON string) *canonical.Node {
	t.Helper()
	n, err := p.DecodeArgs([]byte(argsJSON))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
