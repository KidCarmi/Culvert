package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Capability-isolation regression tests for the embedded rollout config.
//
// cpdp.Payload.checkCapabilityIsolation walled the payload BLOCKS by capability but
// never validated the capability the embedded rollout.SignedConfig declares about
// ITSELF. That field is load-bearing: commitRolloutTransition routes by cfg.Capability
// and rollout.State is capability-local, so a Gateway envelope carrying a rollout that
// declares Management steers the commit onto the MANAGEMENT rollout state — crossing
// the ADR-0024 isolation boundary.
//
// Pre-fix RED behavior (reproduced against b697cf3 before this change):
//   - Applier.Apply ACCEPTED a Gateway envelope whose inner rollout declared
//     Management (cpdp never checked it), so it landed in the Gateway durable store;
//   - reconcileRolloutWithDistribution then committed it onto the Management rollout
//     state at startup — no operator action, no CP round trip — because the reconcile
//     path, unlike the apply-time coordinator, ran no capability cross-check.
//
// The fix walls it at BOTH layers: cpdp rejects such an envelope outright, and every
// path that COMMITS a rollout re-checks locally (rolloutCapabilityMatches) so the
// guarantee never depends on validation having run in a different process lifetime —
// Applier.Recover deliberately re-verifies only signature/capability/min-version, not
// full payload validation.

// ---- layer 1: the cpdp engine rejects a capability-crossing rollout -------------

// TestMCPSnapshot_RejectsGatewayEnvelopeWithManagementRollout proves a Gateway
// envelope whose inner rollout declares Management is rejected WHOLE: no distribution
// activation, and neither capability's rollout state moves.
func TestMCPSnapshot_RejectsGatewayEnvelopeWithManagementRollout(t *testing.T) {
	signer, _ := mcpProdSetup(t)

	crossing := mcpObserveRollout(rollout.CapabilityManagement)
	crossing.Scope.Tenants = []string{"tenant-crossed"}
	env := mcpSignedGWEnv(t, signer, 2, crossing)

	gw := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)
	if _, err := gw.Apply(env); err == nil {
		t.Fatal("Apply accepted a Gateway envelope carrying a Management rollout config")
	}
	if gw.Active() != nil {
		t.Fatal("a rejected envelope must not become the active distribution snapshot")
	}
	if m := getMCPRollout().management.CurrentMode(); m != rollout.ModeDisabled {
		t.Fatalf("Management rollout state moved to %s from a Gateway envelope", m)
	}
	if m := getMCPRollout().gateway.CurrentMode(); m != rollout.ModeDisabled {
		t.Fatalf("Gateway rollout state moved to %s on a rejected envelope", m)
	}
}

// TestMCPSnapshot_RejectsManagementEnvelopeWithGatewayRollout is the mirror
// direction — the wall must be symmetric, not Gateway-only.
func TestMCPSnapshot_RejectsManagementEnvelopeWithGatewayRollout(t *testing.T) {
	signer, _ := mcpProdSetup(t)

	crossing := mcpObserveRollout(rollout.CapabilityGateway)
	env := mcpSignedMGEnv(t, signer, 2, crossing)

	mg := globalMCPDistribution.dpApplierFor(cpdp.CapabilityManagement)
	if _, err := mg.Apply(env); err == nil {
		t.Fatal("Apply accepted a Management envelope carrying a Gateway rollout config")
	}
	if mg.Active() != nil {
		t.Fatal("a rejected envelope must not become the active distribution snapshot")
	}
	if m := getMCPRollout().gateway.CurrentMode(); m != rollout.ModeDisabled {
		t.Fatalf("Gateway rollout state moved to %s from a Management envelope", m)
	}
}

// TestMCPSnapshot_MatchingRolloutStillApplies is the POSITIVE half: the wall must
// reject only the crossing case and leave the legitimate path byte-identical.
func TestMCPSnapshot_MatchingRolloutStillApplies(t *testing.T) {
	signer, _ := mcpProdSetup(t)

	rc := mcpObserveRollout(rollout.CapabilityGateway)
	rc.Scope.Tenants = []string{"tenant-ok"}
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: mcpSignedGWEnv(t, signer, 2, rc)})

	if m := getMCPRollout().gateway.CurrentMode(); m != rollout.ModeObserve {
		t.Fatalf("a capability-correct rollout must still apply; Gateway mode = %s", m)
	}
	got := getMCPRollout().gateway.CurrentConfig()
	if len(got.Scope.Tenants) != 1 || got.Scope.Tenants[0] != "tenant-ok" {
		t.Fatalf("Gateway scope = %v, want [tenant-ok]", got.Scope.Tenants)
	}
	// Isolation still holds in the good case: Management is untouched.
	if m := getMCPRollout().management.CurrentMode(); m != rollout.ModeDisabled {
		t.Fatalf("Management rollout state moved to %s from a Gateway apply", m)
	}
}

// ---- layer 2: consumers select/commit by the SIGNED capability ------------------

// TestRolloutFromEnvelope_SelectsBySignedCapability pins that the rollout config is
// read from the block named by Manifest.Capability, never from whichever block
// happens to be populated (block presence is publisher-influenced; the manifest
// capability is signature-covered).
func TestRolloutFromEnvelope_SelectsBySignedCapability(t *testing.T) {
	gwRC := mcpObserveRollout(rollout.CapabilityGateway)
	mgRC := mcpObserveRollout(rollout.CapabilityManagement)

	// A Management-capability envelope with BOTH blocks populated: selection must
	// follow the manifest, so the Management block's rollout is returned.
	env := &cpdp.Envelope{
		Manifest: cpdp.Manifest{Capability: cpdp.CapabilityManagement},
		Payload: cpdp.Payload{
			Gateway:    &cpdp.GatewayPayload{Rollout: gwRC},
			Management: &cpdp.ManagementPayload{Rollout: mgRC},
		},
	}
	if got := rolloutFromEnvelope(env); got != mgRC {
		t.Fatal("rolloutFromEnvelope followed block presence instead of the signed capability")
	}

	// Mirror: a Gateway-capability envelope reads the Gateway block.
	env.Manifest.Capability = cpdp.CapabilityGateway
	if got := rolloutFromEnvelope(env); got != gwRC {
		t.Fatal("rolloutFromEnvelope did not read the Gateway block for a Gateway envelope")
	}

	// A capability with no corresponding block carries no rollout change.
	env.Payload.Gateway = nil
	if got := rolloutFromEnvelope(env); got != nil {
		t.Fatal("a missing block for the signed capability must yield no rollout change")
	}
	if got := rolloutFromEnvelope(nil); got != nil {
		t.Fatal("a nil envelope must yield no rollout change")
	}
}

// TestRolloutCapabilityMatches covers the guard's boundaries directly, including the
// nil case (absence is not a change) and both crossing directions.
func TestRolloutCapabilityMatches(t *testing.T) {
	cases := []struct {
		name string
		cfg  *rollout.SignedConfig
		capb cpdp.Capability
		want bool
	}{
		{"nil is not a change", nil, cpdp.CapabilityGateway, true},
		{"gateway/gateway", mcpObserveRollout(rollout.CapabilityGateway), cpdp.CapabilityGateway, true},
		{"management/management", mcpObserveRollout(rollout.CapabilityManagement), cpdp.CapabilityManagement, true},
		{"management rollout on gateway envelope", mcpObserveRollout(rollout.CapabilityManagement), cpdp.CapabilityGateway, false},
		{"gateway rollout on management envelope", mcpObserveRollout(rollout.CapabilityGateway), cpdp.CapabilityManagement, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rolloutCapabilityMatches(tc.cfg, tc.capb); got != tc.want {
				t.Fatalf("rolloutCapabilityMatches = %v, want %v", got, tc.want)
			}
		})
	}
}

// ---- layer 3: the startup reconcile path is self-sufficient ---------------------

// TestReconcile_RefusesCapabilityCrossingRecoveredState is the defense-in-depth
// proof. It splices a VALIDLY SIGNED capability-crossing envelope into the Gateway
// durable state file — the one thing Applier.Recover cannot catch, because recheck()
// re-verifies signature + capability + min-version but deliberately NOT full payload
// validation. On restart the envelope recovers as the active Gateway snapshot, and
// the reconcile path must refuse to commit its Management-declaring rollout rather
// than steer it onto the Management state.
func TestReconcile_RefusesCapabilityCrossingRecoveredState(t *testing.T) {
	signer, dir := mcpProdSetup(t)

	// Establish a legitimate persisted state so the file carries the real envelope
	// format and state version (never hand-rolled).
	applySnapshotMCP(ConfigSnapshot{
		MCPGatewaySnapshot: mcpSignedGWEnv(t, signer, 2, mcpObserveRollout(rollout.CapabilityGateway)),
	})
	statePath := filepath.Join(dir, "mcp_distribution", "mcp_gateway_active.json")
	raw, err := os.ReadFile(statePath) // #nosec G304 -- test-owned temp path
	if err != nil {
		t.Fatalf("read persisted state: %v", err)
	}

	// Splice in a validly-signed Gateway envelope whose inner rollout declares
	// Management. Signed by the SAME trusted key, so recovery re-verification passes.
	crossing := mcpObserveRollout(rollout.CapabilityManagement)
	crossing.Scope.Tenants = []string{"tenant-crossed"}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatalf("unmarshal persisted state: %v", err)
	}
	spliced, err := json.Marshal(mcpSignedGWEnv(t, signer, 3, crossing))
	if err != nil {
		t.Fatal(err)
	}
	var envAny any
	if err := json.Unmarshal(spliced, &envAny); err != nil {
		t.Fatal(err)
	}
	st["current"] = envAny
	delete(st, "previous")
	out, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, out, 0o600); err != nil {
		t.Fatalf("write spliced state: %v", err)
	}

	// Restart: recover the Gateway store, then reconcile.
	mcpSimulateRestart(t)

	if got := getMCPRollout().management.CurrentConfig(); len(got.Scope.Tenants) != 0 {
		t.Fatalf("capability isolation breach: startup reconcile of the GATEWAY store committed %v onto the MANAGEMENT rollout state",
			got.Scope.Tenants)
	}
	if m := getMCPRollout().management.CurrentMode(); m != rollout.ModeDisabled {
		t.Fatalf("Management rollout state moved to %s during Gateway reconcile", m)
	}
	// The crossing config must not land on the Gateway state either — it declares a
	// capability this store does not own, so the safe outcome is "leave it alone".
	if got := getMCPRollout().gateway.CurrentConfig(); len(got.Scope.Tenants) == 1 && got.Scope.Tenants[0] == "tenant-crossed" {
		t.Fatal("a capability-crossing rollout was committed onto the Gateway state")
	}
}
