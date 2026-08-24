package main

import (
	"testing"
	"time"

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

// OVN-03. The runtime PolicyProvider dereferences the Gateway store on EVERY
// decision-point request. Reading it under the holder's RWMutex made a
// process-wide lock part of the request path — an atomic read-modify-write on one
// shared word, i.e. a throughput ceiling rather than a constant cost. That is the
// exact shape Culvert has repeatedly removed elsewhere (internal/threatfeed,
// the IP filter, internal/connlimit), and re-introducing it for MCP would be a
// regression against a standing architectural rule.
//
// Structural, not timing-based: hold the holder's write lock and require the
// provider to answer anyway. Deterministic on any hardware, under -race, at any
// load.
func TestPolicyProvider_ReadTakesNoHolderLock(t *testing.T) {
	h := newMCPPolicyHolder()
	if err := h.publish(mcpPolLoaded, "", compileGatewayTestSnapshot(t)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	prov := gatewayPolicyProvider{h: h}

	h.mu.Lock()
	defer h.mu.Unlock()

	done := make(chan bool, 1)
	go func() { done <- prov.PolicySnapshot(protocol.Gateway) != nil }()
	select {
	case ok := <-done:
		if !ok {
			t.Fatal("provider returned no snapshot while the holder lock was held")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("PolicySnapshot blocked on the holder lock: the policy read is on the request path " +
			"and must not take a process-wide mutex")
	}
}

// A store REPLACEMENT must still be observed immediately by the provider — the
// lock-free read may not trade freshness for speed.
func TestPolicyProvider_LockFreeReadIsStillFresh(t *testing.T) {
	h := newMCPPolicyHolder()
	prov := gatewayPolicyProvider{h: h}
	if got := prov.PolicySnapshot(protocol.Gateway); got != nil {
		t.Fatal("a fresh holder must serve no snapshot")
	}
	if err := h.publish(mcpPolLoaded, "", compileGatewayTestSnapshot(t)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := prov.PolicySnapshot(protocol.Gateway); got == nil {
		t.Fatal("publication not visible to the lock-free read")
	}
	h.invalidateForStartupFailure()
	if got := prov.PolicySnapshot(protocol.Gateway); got != nil {
		t.Fatal("store replacement not visible to the lock-free read")
	}
}
