package main

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/policy"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// SEC-MCP-07. The holder documents its Gateway store pointer as stable for the
// life of the process, and the single-source-of-truth invariant rests on that:
// the runtime evaluator and the read-only Policy Admin API must never disagree
// about which snapshot is active. But invalidateForStartupFailure and
// resetForTest both REPLACE h.gw. A provider that captured the pointer at
// compose() time would keep evaluating the OLD store's snapshot while the admin
// surface — which reads the holder live — reported no active policy.
//
// Nothing reaches that divergence in production today (the only replacement path
// runs when the listener never started), which is exactly why it needs a test:
// the invariant is currently true by coincidence, not by construction.
func TestPolicyProvider_ReadsTheHolderLiveNotACapturedStore(t *testing.T) {
	h := newMCPPolicyHolder()
	prov := gatewayPolicyProvider{h: h}

	snap := compileGatewayTestSnapshot(t)
	if err := h.publish(mcpPolLoaded, "", snap); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := prov.PolicySnapshot(protocol.Gateway); got == nil {
		t.Fatal("provider does not see the published snapshot")
	}

	// Replace the store, exactly as the startup-failure path does.
	h.invalidateForStartupFailure()

	if got := prov.PolicySnapshot(protocol.Gateway); got != nil {
		t.Fatal("provider still serves a snapshot from the replaced store: " +
			"the runtime evaluator and the admin surface have diverged")
	}
	// And the admin-facing read agrees.
	gw, ok := h.storeFor("gateway")
	if !ok || gw.Current() != nil {
		t.Fatal("admin store read disagrees with the provider")
	}
}

// Capability isolation is unchanged by reading the holder live: a Gateway
// qualification snapshot can never be served as a Management policy.
func TestPolicyProvider_NeverServesGatewaySnapshotToManagement(t *testing.T) {
	h := newMCPPolicyHolder()
	if err := h.publish(mcpPolLoaded, "", compileGatewayTestSnapshot(t)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	prov := gatewayPolicyProvider{h: h}
	if got := prov.PolicySnapshot(protocol.Management); got != nil {
		t.Fatal("a Gateway snapshot was served for the Management capability")
	}
	// A provider with no holder fails closed rather than panicking or returning a
	// permissive nil-safe default.
	if got := (gatewayPolicyProvider{}).PolicySnapshot(protocol.Gateway); got != nil {
		t.Fatal("an unbound provider must fail closed")
	}
}

func compileGatewayTestSnapshot(t *testing.T) *policy.Snapshot {
	t.Helper()
	doc := `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`
	snap, err := policy.Compile([]byte(doc), policy.CreatedMeta{}, policy.DefaultLimits())
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return snap
}
