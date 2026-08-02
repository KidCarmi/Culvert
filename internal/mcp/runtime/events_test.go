package runtime

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/events"
	evmodel "github.com/KidCarmi/Culvert/internal/mcp/events/model"
	"github.com/KidCarmi/Culvert/internal/mcp/events/spool"
)

// fakeEvents records CommitDecision / ObserveDenial calls and can fail commits.
type fakeEvents struct {
	mu         sync.Mutex
	commits    []events.DecisionFacts
	denials    []events.DenialInput
	failCommit bool
	writeAllow bool
}

func newFakeEvents() *fakeEvents { return &fakeEvents{writeAllow: true} }

func (f *fakeEvents) CommitDecision(fx events.DecisionFacts) (spool.CommitReceipt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commits = append(f.commits, fx)
	if f.failCommit {
		return spool.CommitReceipt{}, errors.New("injected commit failure")
	}
	return spool.CommitReceipt{}, nil
}

func (f *fakeEvents) ObserveDenial(in events.DenialInput) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.denials = append(f.denials, in)
}

func (f *fakeEvents) WriteAllowedCritical(_ evmodel.Capability) bool { return f.writeAllow }

func (f *fakeEvents) commitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.commits)
}

func (f *fakeEvents) denialCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.denials)
}

func eventsPipeline(t *testing.T, k *esKey, prov PolicyProvider, ev EventProvider) *pipeline {
	t.Helper()
	deps := testDeps(t, k, NewBoundedSink(16))
	deps.Policy = prov
	deps.Events = ev
	ctr := &counters{}
	p, err := newPipeline(gwListenerConfig(t), deps, "test-gw", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	return p
}

// TestEvents_AllowClassCommitsAndStaysNotImplemented: an ALLOW-class decision
// durably commits a decision event AND still returns execution_state
// not_implemented — the event is evidence, not execution.
func TestEvents_AllowClassCommitsAndStaysNotImplemented(t *testing.T) {
	k := newESKey(t, "k1")
	rule := `{"id":"ALLOW_LIST","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}],"obligations":{"logging":"standard"}}`
	ev := newFakeEvents()
	p := eventsPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, rule)}, ev)
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispPolicyAllowed {
		t.Fatalf("disp=%v", out.Disposition)
	}
	if ev.commitCount() != 1 {
		t.Fatalf("CommitDecision calls = %d, want 1", ev.commitCount())
	}
	_, result := decodeEnv(t, out.ResponseBody)
	var res struct {
		ExecutionState string `json:"execution_state"`
	}
	_ = json.Unmarshal(result, &res)
	if res.ExecutionState != "not_implemented" {
		t.Fatalf("execution_state = %q, want not_implemented", res.ExecutionState)
	}
	// The committed facts are decision-only.
	ev.mu.Lock()
	fx := ev.commits[0]
	ev.mu.Unlock()
	if fx.Decision.ExecutionState != "not_implemented" {
		t.Fatal("committed facts do not carry not_implemented")
	}
}

// TestEvents_OrdinaryCommitFailureDoesNotBlock: a failing ORDINARY commit applies
// the loss policy — the operation still proceeds (never silently, but not blocked).
func TestEvents_OrdinaryCommitFailureDoesNotBlock(t *testing.T) {
	k := newESKey(t, "k1")
	rule := `{"id":"ALLOW_LIST","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}],"obligations":{"logging":"standard"}}`
	ev := newFakeEvents()
	ev.failCommit = true
	p := eventsPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, rule)}, ev)
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	// tools/list is a discovery (ordinary) op: a commit failure does not block.
	if out.Disposition != DispPolicyAllowed {
		t.Fatalf("ordinary commit failure blocked the operation: disp=%v", out.Disposition)
	}
}

// TestEvents_DenialRouted: a policy DENY routes into the denial lane.
func TestEvents_DenialRouted(t *testing.T) {
	k := newESKey(t, "k1")
	ev := newFakeEvents()
	p := eventsPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, "")}, ev) // default deny
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("disp=%v", out.Disposition)
	}
	if ev.denialCount() == 0 {
		t.Fatal("policy DENY was not routed into the denial lane")
	}
}

// TestEvents_AuthFailureRoutedWithoutTenant: a pre-identity authentication failure
// routes into the denial lane WITHOUT tenant attribution.
func TestEvents_AuthFailureRoutedWithoutTenant(t *testing.T) {
	k := newESKey(t, "k1")
	ev := newFakeEvents()
	p := eventsPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, "")}, ev)
	sid := doInit(t, p, gwToken(k))
	// Send a decision-point request with a BAD token → auth failure.
	out := p.Process(withSession(gwRequest("bad.token.value", toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("expected rejection, got %v", out.Disposition)
	}
	if ev.denialCount() == 0 {
		t.Fatal("auth failure not routed into the denial lane")
	}
	ev.mu.Lock()
	defer ev.mu.Unlock()
	for _, d := range ev.denials {
		if d.Tenant != "" {
			t.Fatal("pre-identity auth failure invented a tenant")
		}
	}
}

// TestEvents_NilProviderNoCalls confirms a nil Events dep leaves the path
// byte-identical (no commit, no denial routing).
func TestEvents_NilProviderNoCalls(t *testing.T) {
	k := newESKey(t, "k1")
	rule := `{"id":"ALLOW_LIST","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}],"obligations":{"logging":"standard"}}`
	p := policyPipeline(t, k, fakePolicy{gw: gwPolicySnap(t, rule)}) // no Events
	tok, sid := driveToDecisionPoint(t, p, k)
	out := p.Process(withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispPolicyAllowed {
		t.Fatalf("nil-events path changed disposition: %v", out.Disposition)
	}
}
