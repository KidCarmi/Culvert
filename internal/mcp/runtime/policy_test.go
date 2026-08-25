package runtime

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// fakePolicy is a test PolicyProvider returning a fixed capability-local snapshot.
// A nil field means "no snapshot published for that capability" (fail closed).
type fakePolicy struct {
	gw   *policy.Snapshot
	mgmt *policy.Snapshot
}

func (f fakePolicy) PolicySnapshot(capNS protocol.Capability) *policy.Snapshot {
	if capNS == protocol.Management {
		return f.mgmt
	}
	return f.gw
}

func gwPolicySnap(t *testing.T, rules string) *policy.Snapshot {
	t.Helper()
	doc := `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[` + rules + `]}`
	snap, err := policy.Compile([]byte(doc), policy.CreatedMeta{}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("compile policy: %v\n%s", err, doc)
	}
	return snap
}

// policyPipeline builds a gateway pipeline whose deps carry the given provider.
func policyPipeline(t *testing.T, k *esKey, prov PolicyProvider) *pipeline {
	t.Helper()
	deps := testDeps(t, k, NewBoundedSink(16))
	deps.Policy = prov
	ctr := &counters{}
	p, err := newPipeline(gwListenerConfig(t), deps, "test-gw", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	return p
}

// driveToDecisionPoint initializes a session and returns (pipeline, token, sid).
func driveToDecisionPoint(t *testing.T, p *pipeline, k *esKey) (token, sid string) {
	t.Helper()
	token = gwToken(k)
	sid = doInit(t, p, token)
	p.Process(context.Background(), withSession(gwRequest(token, initializedNotification()), sid), fixedClock())
	return token, sid
}

func decodeEnv(t *testing.T, body []byte) (errMember *struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}, result json.RawMessage) {
	t.Helper()
	var env struct {
		Error *struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		} `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("response not JSON: %v (%q)", err, body)
	}
	return env.Error, env.Result
}

// TestPolicy_DefaultDenyRejects: with a default-deny snapshot, a tools/list is a
// deterministic policy DENY (DispRejected) — never a fabricated result.
func TestPolicy_DefaultDenyRejects(t *testing.T) {
	k := newESKey(t, "k1")
	p := policyPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, "")})
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispRejected || out.Status != 200 {
		t.Fatalf("default deny: disp=%v status=%d", out.Disposition, out.Status)
	}
	errM, result := decodeEnv(t, out.ResponseBody)
	if errM == nil || result != nil {
		t.Fatalf("default deny must be a typed error, no result: %q", out.ResponseBody)
	}
	if errM.Message != string(policy.ReasonNoMatchDefaultDeny) {
		t.Fatalf("reason = %q, want %s", errM.Message, policy.ReasonNoMatchDefaultDeny)
	}
	if out.Record.PolicyAction != "DENY" {
		t.Fatalf("record policy action = %q, want DENY", out.Record.PolicyAction)
	}
}

// TestPolicy_AllowClassNeverExecutes: an ALLOW-class decision records the TRUE
// policy result but returns execution_state=not_implemented — it never fabricates a
// tool result and never contacts an upstream/credential/broker (none are wired).
func TestPolicy_AllowClassNeverExecutes(t *testing.T) {
	k := newESKey(t, "k1")
	// Allow the discovery method tools/list.
	rule := `{"id":"ALLOW_LIST","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}],"obligations":{"logging":"standard"}}`
	p := policyPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, rule)})
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispPolicyAllowed || out.Status != 200 {
		t.Fatalf("allow-class: disp=%v status=%d", out.Disposition, out.Status)
	}
	errM, result := decodeEnv(t, out.ResponseBody)
	if errM != nil {
		t.Fatalf("allow-class must not be an error: %q", out.ResponseBody)
	}
	if result == nil {
		t.Fatalf("allow-class must carry a result member: %q", out.ResponseBody)
	}
	var res struct {
		ExecutionState string `json:"execution_state"`
		PolicyAction   string `json:"policy_action"`
	}
	if err := json.Unmarshal(result, &res); err != nil {
		t.Fatalf("result not JSON: %v", err)
	}
	if res.ExecutionState != "not_implemented" {
		t.Fatalf("execution_state = %q, want not_implemented (never fabricated success)", res.ExecutionState)
	}
	if res.PolicyAction != "ALLOW" {
		t.Fatalf("policy_action = %q, want ALLOW", res.PolicyAction)
	}
	if out.Record.PolicyAction != "ALLOW" || out.Record.ExecutionState != "not_implemented" {
		t.Fatalf("record: action=%q exec=%q", out.Record.PolicyAction, out.Record.ExecutionState)
	}
}

// TestPolicy_UnknownToolQuarantined: a tools/call for a tool absent from the catalog
// is QUARANTINE via the hard override, even under a permissive snapshot — the policy
// path never launders an unknown tool into an allow.
func TestPolicy_UnknownToolQuarantined(t *testing.T) {
	k := newESKey(t, "k1")
	// A broad ALLOW rule that would otherwise permit everything.
	rule := `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`
	p := policyPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, rule)})
	tok, sid := driveToDecisionPoint(t, p, k)

	// The catalog is empty ⇒ tool "x" is unknown ⇒ hard quarantine.
	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsCallBody(4)), sid), fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("unknown tool: disp=%v, want rejected", out.Disposition)
	}
	errM, result := decodeEnv(t, out.ResponseBody)
	if errM == nil || result != nil {
		t.Fatalf("unknown tool must be a typed error: %q", out.ResponseBody)
	}
	if errM.Message != string(policy.ReasonToolUnknown) {
		t.Fatalf("reason = %q, want %s", errM.Message, policy.ReasonToolUnknown)
	}
	if out.Record.PolicyAction != "QUARANTINE" {
		t.Fatalf("record action = %q, want QUARANTINE", out.Record.PolicyAction)
	}
}

// TestPolicy_MissingSnapshotFailsClosed: a provider that publishes NO snapshot for
// the capability fails closed with the exact SNAPSHOT_UNAVAILABLE reason — never a
// permissive fall-back to observe-only.
func TestPolicy_MissingSnapshotFailsClosed(t *testing.T) {
	k := newESKey(t, "k1")
	p := policyPipeline(t, k, fakePolicy{gw: nil}) // provider set, but no snapshot
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("missing snapshot: disp=%v, want rejected", out.Disposition)
	}
	errM, result := decodeEnv(t, out.ResponseBody)
	if errM == nil || result != nil {
		t.Fatalf("missing snapshot must be a typed error: %q", out.ResponseBody)
	}
	if errM.Message != string(policy.ReasonSnapshotUnavailable) {
		t.Fatalf("reason = %q, want %s", errM.Message, policy.ReasonSnapshotUnavailable)
	}
	if out.Record.PolicyAction != "DENY" {
		t.Fatalf("record action = %q, want DENY", out.Record.PolicyAction)
	}
}

// TestPolicy_NilProviderKeepsObserveOnly: without a policy provider the PR-5
// observe-only disposition is preserved (backward compatibility).
func TestPolicy_NilProviderKeepsObserveOnly(t *testing.T) {
	k := newESKey(t, "k1")
	p := policyPipeline(t, k, nil) // deps.Policy stays nil
	if p.policy != nil || p.policyEngine != nil {
		t.Fatal("nil provider must leave the pipeline observe-only")
	}
	tok, sid := driveToDecisionPoint(t, p, k)
	out := p.Process(context.Background(), withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispObserveOnly || out.Reason != mcperr.ReasonObserveOnly {
		t.Fatalf("nil provider: disp=%v reason=%v, want observe-only", out.Disposition, out.Reason)
	}
}

// TestPolicy_KernelTerminalUnchanged: the policy path only affects decision-point
// methods; initialize/ping/notifications stay kernel-terminal even with a provider.
func TestPolicy_KernelTerminalUnchanged(t *testing.T) {
	k := newESKey(t, "k1")
	p := policyPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, "")})
	tok := gwToken(k)
	sid := doInit(t, p, tok) // initialize is kernel-terminal (doInit asserts it)

	out := p.Process(context.Background(), withSession(gwRequest(tok, pingBody(2)), sid), fixedClock())
	if out.Disposition != DispKernelTerminal || out.Status != 200 {
		t.Fatalf("ping under policy: disp=%v status=%d", out.Disposition, out.Status)
	}
}
