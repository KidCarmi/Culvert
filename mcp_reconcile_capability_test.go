package main

// mcp_reconcile_capability_test.go — capability isolation on the STARTUP
// reconcile path (PR-12 §8 crash-window convergence).
//
// applyMCPCapabilityEnvelope (mcp_distribution.go) enforces capability isolation
// on the runtime apply path: a Gateway envelope whose payload carries a
// Management rollout config — or vice versa — is rejected WHOLE, before any
// distribution state is staged. That check is load-bearing because the signed
// envelope's own validation does NOT cover it: cpdp.Validate step 8
// (Payload.checkCapabilityIsolation) constrains which payload CONTAINER may be
// present, and nothing cross-checks the nested Rollout.Capability field. A
// correctly signed Gateway envelope carrying Rollout.Capability=management is
// therefore structurally valid, signature-valid, and epoch-valid.
//
// reconcileRolloutWithDistribution — which re-commits the recovered active
// envelope's rollout at every startup — did not repeat that check. It read the
// rollout config out of the Gateway applier's active envelope and handed it
// straight to commitRolloutTransition, which selects its target state by
// cfg.Capability. A Gateway-signed envelope could therefore drive the MANAGEMENT
// rollout state on restart: the two capabilities are physically isolated by
// design (separate appliers, separate trust-verified engines, separate durable
// files), and this is the one path that crossed them.
//
// The shipped runtime pre-check means such an envelope is never persisted by
// this build, so the gap is defense-in-depth rather than a live bypass. It is
// still worth closing: the invariant lived only in the caller, both paths reach
// the same durable commit, and a state file written by any other producer — a
// build without the pre-check, a future CP-side path, a restore — reaches
// reconcile without ever passing the runtime coordinator.

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// TestReconcile_CrossCapabilityRolloutRejected drives the real production
// composition, persists a signature-valid Gateway envelope whose nested rollout
// claims the Management capability (bypassing the runtime coordinator exactly as
// a foreign producer would), then restarts. The Management rollout state must be
// untouched: a Gateway-signed envelope may never write it.
func TestReconcile_CrossCapabilityRolloutRejected(t *testing.T) {
	s, _ := mcpProdSetup(t)
	gwA := globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway)

	// A correctly signed GATEWAY envelope whose rollout claims MANAGEMENT.
	crossed := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityManagement))

	// Persist it by applying it directly to the Gateway applier, bypassing
	// applyMCPCapabilityEnvelope's pre-check — this is precisely the durable
	// state a producer without that check would leave behind. The envelope's own
	// validation must accept it, which is the premise of the finding.
	if _, err := gwA.Apply(crossed); err != nil {
		t.Fatalf("premise failed: a signed Gateway envelope carrying a Management rollout "+
			"was rejected by envelope validation (%v) — if this is now enforced in cpdp, "+
			"this test and the reconcile guard can both be simplified", err)
	}
	if gwA.Active() == nil {
		t.Fatal("premise failed: the crossed envelope did not become active")
	}

	// Restart: rollout state is restored, appliers recovered, reconcile runs.
	mcpSimulateRestart(t)

	if got := getMCPRollout().management.CurrentMode(); got != rollout.ModeDisabled {
		t.Errorf("management rollout mode = %s after reconcile, want disabled: a GATEWAY-signed "+
			"envelope drove the MANAGEMENT rollout state, crossing the capability isolation "+
			"boundary the two appliers exist to enforce", got)
	}
	if got := getMCPRollout().gateway.CurrentMode(); got != rollout.ModeDisabled {
		t.Errorf("gateway rollout mode = %s after reconcile, want disabled: a rollout rejected "+
			"for capability mismatch must not be committed to the envelope's own state either", got)
	}
}

// TestReconcile_MatchingCapabilityStillConverges is the counterweight: the guard
// must reject only the crossed case. A well-formed Gateway envelope must still
// re-commit its own rollout at startup, or the §8 crash-window convergence the
// reconcile exists for would be silently disabled.
func TestReconcile_MatchingCapabilityStillConverges(t *testing.T) {
	s, _ := mcpProdSetup(t)

	env := mcpSignedGWEnv(t, s, 2, mcpObserveRollout(rollout.CapabilityGateway))
	applySnapshotMCP(ConfigSnapshot{MCPGatewaySnapshot: env})
	if getMCPRollout().gateway.CurrentMode() != rollout.ModeObserve {
		t.Fatal("premise failed: the matching envelope did not commit its rollout")
	}

	mcpSimulateRestart(t)

	if got := getMCPRollout().gateway.CurrentMode(); got != rollout.ModeObserve {
		t.Errorf("gateway rollout mode = %s after restart, want observe: reconcile must still "+
			"converge a well-formed envelope's own rollout", got)
	}
	if got := getMCPRollout().management.CurrentMode(); got != rollout.ModeDisabled {
		t.Errorf("management rollout mode = %s, want disabled (isolation)", got)
	}
}
