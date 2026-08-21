package main

import (
	"encoding/json"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/cpdp"
	cpdpapply "github.com/KidCarmi/Culvert/internal/mcp/cpdp/apply"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// Security-regression gates for the PR-12 MCP CP→DP distribution composition.
//
// Each test below pins a property that a security review found was NOT pinned when
// the composition landed. They are written against the REAL production composition
// path (env trust + initMCPDistribution) — never a test-only seam — so they cannot
// pass by wiring something production does not do.

// TestMCPDistribution_DPTrustDoesNotArmCPPublication is the capability-separation
// gate.
//
// CULVERT_MCP_DISTRIBUTION_TRUST_KEYS provisions PUBLIC verification roots — a
// CONSUMING capability on a Data Plane. It must never arm a PUBLISHING capability.
// The composition originally flipped the single `enabled` flag, which is also the
// gate the Control-Plane capture path (mcpCaptured*) reads before stamping a signed
// MCP envelope onto every outbound ConfigSnapshot. That conflated "this node may
// verify snapshots" with "this node may publish snapshots" and silently armed an
// outbound wire path from an unrelated env var — a privilege-confusion / unsafe-
// default class (CWE-269, OWASP A04/A05).
func TestMCPDistribution_DPTrustDoesNotArmCPPublication(t *testing.T) {
	_, _ = mcpProdSetup(t) // real composition: DP verify-trust provisioned

	if globalMCPDistribution.cpEnabled.Load() {
		t.Fatal("DP verify-trust provisioning armed the CP publication capture path")
	}
	if env := mcpCapturedGateway(); env != nil {
		t.Fatalf("DP-only node captured a Gateway envelope for the wire: %+v", env)
	}
	if env := mcpCapturedManagement(); env != nil {
		t.Fatalf("DP-only node captured a Management envelope for the wire: %+v", env)
	}

	st := mcpDistributionStatus()
	if armed, _ := st["cp_publication"].(bool); armed {
		t.Fatal("status reports the CP publication path armed on a DP-only node")
	}
	if state, _ := st["distribution_state"].(string); state != "local_only" {
		t.Fatalf("distribution_state = %q, want local_only on a DP-only node", state)
	}

	// The whole point of the gate: the outbound snapshot must stay byte-compatible
	// with the pre-MCP SWG snapshot on a node that only verifies.
	snap := ConfigSnapshot{Version: 1}
	snap.MCPGatewaySnapshot = mcpCapturedGateway()
	snap.MCPManagementSnapshot = mcpCapturedManagement()
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "mcp_gateway_snapshot") || strings.Contains(string(raw), "mcp_management_snapshot") {
		t.Fatalf("DP verify-trust leaked MCP fields onto the wire: %s", raw)
	}
}

// TestMCPDistribution_ReconcileDoesNotDependOnThePublishedSeam is the deterministic
// half of the startup-ordering gate.
//
// Startup convergence must be driveable from the appliers the composing goroutine
// just built, WITHOUT reading them back off the process-wide seam. Reading them back
// forces the seam to be published first, which is what opens the race the companion
// test below exercises.
func TestMCPDistribution_ReconcileDoesNotDependOnThePublishedSeam(t *testing.T) {
	signer, dir := mcpProdSetup(t)

	// Commit an Observe rollout through the real transaction so both durable stores
	// hold it.
	env := mcpSignedGWEnv(t, signer, 2, mcpObserveRollout(rollout.CapabilityGateway))
	applySnapshotMCP(ConfigSnapshot{Version: 1, MCPGatewaySnapshot: env})
	if got := getMCPRollout().stateFor(rollout.CapabilityGateway).CurrentMode(); got != rollout.ModeObserve {
		t.Fatalf("setup: rollout mode = %v, want observe", got)
	}

	// Restart with the rollout half deliberately missing, so only reconcile can
	// restore it — and keep the appliers OFF the global seam.
	if err := os.Remove(rolloutStateFileName(rollout.CapabilityGateway)); err != nil {
		t.Fatalf("remove rollout state: %v", err)
	}
	mcpResetGlobals(t)
	setDataDirForTest(t, dir)
	getMCPRollout().restore()

	trust, err := cpdp.NewTrustStore([]cpdp.TrustRoot{{KeyID: "mcp-k1", Alg: cpdp.SigAlgEd25519, Public: signer.Public()}})
	if err != nil {
		t.Fatal(err)
	}
	ap, err := cpdpapply.New(cpdpapply.Config{
		Capability: cpdp.CapabilityGateway,
		Trust:      trust,
		DPVersion:  cpdp.DPCompatVersion,
		Limits:     cpdp.DefaultLimits(),
		NodeID:     "n1",
		Store:      cpdpapply.NewFileStore(dir+"/mcp_distribution", cpdp.CapabilityGateway),
		Clock:      func() int64 { return 1 },
		IDGen:      func() string { return "ack-1" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := ap.Recover(); err != nil {
		t.Fatalf("recover: %v", err)
	}
	if globalMCPDistribution.dpApplierFor(cpdp.CapabilityGateway) != nil {
		t.Fatal("precondition: the seam must be unpublished for this test")
	}

	reconcileRolloutWithAppliers(map[cpdp.Capability]*cpdpapply.Applier{cpdp.CapabilityGateway: ap})

	if got := getMCPRollout().stateFor(rollout.CapabilityGateway).CurrentMode(); got != rollout.ModeObserve {
		t.Fatalf("reconcile off an unpublished applier did not converge: mode = %v, want observe", got)
	}
}

// TestMCPDistribution_AppliersAreNeverVisibleBeforeReconcile is the concurrency half
// of the startup-ordering gate.
//
// The DP config-sync poller is already running (started from initCluster, ~16 startup
// steps before initMCPDistribution, and it polls immediately). If the appliers are
// published BEFORE startup reconciliation finishes, a freshly-pulled and validly
// signed ConfigSnapshot can be applied in that window and then have its rollout
// commit OVERWRITTEN by reconcile replaying the stale recovered envelope — the exact
// distribution/rollout split the PR-12 transaction exists to prevent, and a silent
// revert to the wider mode when the newer envelope was a de-escalation.
//
// The invariant asserted here is the one that makes the window unreachable: at the
// FIRST instant an applier is observable on the seam, the rollout state must already
// be converged.
func TestMCPDistribution_AppliersAreNeverVisibleBeforeReconcile(t *testing.T) {
	for i := 0; i < 20; i++ {
		t.Run("", func(t *testing.T) {
			signer, dir := mcpProdSetup(t)
			env := mcpSignedGWEnv(t, signer, 2, mcpObserveRollout(rollout.CapabilityGateway))
			applySnapshotMCP(ConfigSnapshot{Version: 1, MCPGatewaySnapshot: env})
			if got := getMCPRollout().stateFor(rollout.CapabilityGateway).CurrentMode(); got != rollout.ModeObserve {
				t.Fatalf("setup: rollout mode = %v, want observe", got)
			}
			// Drop the rollout half so reconcile has real work to do on restart.
			if err := os.Remove(rolloutStateFileName(rollout.CapabilityGateway)); err != nil {
				t.Fatalf("remove rollout state: %v", err)
			}

			mcpResetGlobals(t)
			setDataDirForTest(t, dir)
			d, r := globalMCPDistribution, globalMCPRollout
			getMCPRollout().restore()

			observed := make(chan rollout.Mode, 1)
			go func() {
				for {
					if d.dpApplierFor(cpdp.CapabilityGateway) != nil {
						observed <- r.stateFor(rollout.CapabilityGateway).CurrentMode()
						return
					}
					runtime.Gosched()
				}
			}()

			initMCPDistribution(nil)

			if got := <-observed; got != rollout.ModeObserve {
				t.Fatalf("applier became observable before reconcile converged: rollout mode = %v, want observe", got)
			}
		})
	}
}
