package runtime

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// foreignOwnedDeps builds runtime Deps whose registry holds srv-1 owned by a tenant
// OTHER than the token tenant, so a valid tenant-a token addressing srv-1 is a
// cross-tenant request. Auth still binds (the token aud/scope match srv-1's canonical
// resource); only the server OWNER differs from the authenticated tenant.
func foreignOwnedDeps(t testing.TB, k *esKey, owner string, ev EventProvider) Deps {
	t.Helper()
	keys := authn.NewStaticKeyResolver()
	keys.Add(testIssuer, k.kid, k.priv.Public())
	reg := registry.New(limits.DefaultCatalog())
	if _, err := reg.Register(registry.Registration{
		ID: testServerID, Endpoint: "https://upstream.example/mcp",
		PinnedIdentity: "spiffe://upstream/srv-1", Capability: protocol.Gateway,
		OwnerScope: registry.OwnerScope(owner),
	}); err != nil {
		t.Fatalf("register srv-1: %v", err)
	}
	return Deps{
		Registry: reg,
		Catalog:  catalog.New(limits.DefaultCatalog()),
		Keys:     keys,
		Sink:     NewBoundedSink(16),
		Clock:    fixedClock,
		Events:   ev,
	}
}

// TestTenantIsolation_CrossTenantRoutesToDenialLane proves the request-time invariant
// end-to-end through the real pipeline: an authenticated tenant-a token addressing a
// server owned by tenant-b is DENIED with TENANT_MISMATCH, routes into the isolated
// P-DEN denial lane (never the decision-commit lane), and never fabricates a result.
// The broad ALLOW rule proves the hard override beats any user policy.
func TestTenantIsolation_CrossTenantRoutesToDenialLane(t *testing.T) {
	k := newESKey(t, "k1")
	ev := newFakeEvents()
	deps := foreignOwnedDeps(t, k, "tenant-b", ev) // token tenant is tenant-a
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	ctr := &counters{}
	p, err := newPipeline(gwListenerConfig(t), deps, "test-gw", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	tok, sid := driveToDecisionPoint(t, p, k)

	// A tools/call on the foreign server, under a broad ALLOW policy.
	out := p.Process(withSession(gwRequest(tok, toolsCallBody(4)), sid), fixedClock())
	if out.Disposition != DispRejected || out.Status != 200 {
		t.Fatalf("cross-tenant request must be rejected: disp=%v status=%d", out.Disposition, out.Status)
	}
	errM, result := decodeEnv(t, out.ResponseBody)
	if errM == nil || result != nil {
		t.Fatalf("cross-tenant denial must be a typed error, no result: %q", out.ResponseBody)
	}
	if errM.Message != string(policy.ReasonTenantMismatch) {
		t.Fatalf("reason = %q, want %s", errM.Message, policy.ReasonTenantMismatch)
	}
	if out.Record.PolicyAction != "DENY" {
		t.Fatalf("record action = %q, want DENY", out.Record.PolicyAction)
	}
	// The denial travels the P-DEN denial lane, never the decision-commit lane.
	if ev.denialCount() == 0 {
		t.Fatal("cross-tenant denial was not routed into the P-DEN denial lane")
	}
	if ev.commitCount() != 0 {
		t.Fatalf("cross-tenant denial must NOT commit a decision event: commits=%d", ev.commitCount())
	}
	// Attribution is the AUTHENTICATED tenant, never the foreign owner.
	ev.mu.Lock()
	defer ev.mu.Unlock()
	for _, d := range ev.denials {
		if d.Tenant != testTenant {
			t.Fatalf("denial tenant = %q, want authenticated %q (never the foreign owner)", d.Tenant, testTenant)
		}
	}
}

// TestTenantIsolation_EmptyOwnerFailsClosedPipeline proves an unscoped server (empty
// OwnerScope) fails closed for an authenticated Gateway request — it is never treated
// as owned by every tenant.
func TestTenantIsolation_EmptyOwnerFailsClosedPipeline(t *testing.T) {
	k := newESKey(t, "k1")
	ev := newFakeEvents()
	deps := foreignOwnedDeps(t, k, "", ev) // empty owner scope
	deps.Policy = fakePolicy{gw: gwPolicySnap(t, `{"id":"BROAD","priority":1,"action":"ALLOW","reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none","conditions":[],"obligations":{"logging":"standard"}}`)}
	ctr := &counters{}
	p, err := newPipeline(gwListenerConfig(t), deps, "test-gw", ctr, 1)
	if err != nil {
		t.Fatalf("newPipeline: %v", err)
	}
	tok, sid := driveToDecisionPoint(t, p, k)

	out := p.Process(withSession(gwRequest(tok, toolsListBody(3)), sid), fixedClock())
	if out.Disposition != DispRejected {
		t.Fatalf("empty-owner request must be rejected: disp=%v", out.Disposition)
	}
	errM, _ := decodeEnv(t, out.ResponseBody)
	if errM == nil || errM.Message != string(policy.ReasonTenantMismatch) {
		t.Fatalf("empty owner must fail closed with TENANT_MISMATCH: %q", out.ResponseBody)
	}
}
