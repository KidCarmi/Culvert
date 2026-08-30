package main

import (
	"errors"
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// withCoordinatorRehearsalEnv arms a node on which the authoritative rollback rehearsal can run: the
// FULL shadow tier composed (so the Gateway Shadow preflight the Canary→Shadow rung hits is satisfied),
// the live tier NOT armed (the Shadow preflight forbids a live-armed node — the rehearsal is run while
// in Shadow, before Canary), a concrete build stamp (evidence must be build-bound), a fresh temp
// dataDir, and a fresh rollout singleton so the coordinator core reads deterministic node state.
func withCoordinatorRehearsalEnv(t *testing.T) *mcpRollout {
	t.Helper()
	withTempDataDir(t)
	pinTestBuildVersion(t)
	withReadyShadowNode(t) // durable events, policy, inventory, inspection, listener + usable-tool probes; live tier OFF
	_ = getMCPRollout()
	prevR := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	t.Cleanup(func() { globalMCPRollout = prevR })
	return globalMCPRollout
}

// TestCoordinatorRehearsal_EndToEndPassThroughRealCoordinator is the load-bearing PASS proof: on a
// genuinely rollback-capable node the authoritative rehearsal drives Canary→Shadow→Observe THROUGH the
// real coordinator core (commitRolloutTransitionCore — the same body production uses), recovers the
// scratch state to Observe, records durable build-bound evidence, and closes row 20. It also proves the
// rehearsal never touched live state and left no scratch file.
func TestCoordinatorRehearsal_EndToEndPassThroughRealCoordinator(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway

	// Precondition: row 20 is UNMET before any rehearsal.
	if productionCoordinatorRollbackRehearsed(r, capb, false) {
		t.Fatal("precondition: row 20 must be unmet before a rehearsal")
	}
	// Snapshot live state so we can prove the rehearsal never mutated it.
	liveModeBefore := r.stateFor(capb).CurrentMode()

	if err := r.recordCoordinatorRehearsal(capb); err != nil {
		t.Fatalf("authoritative rehearsal on a ready node must succeed, got %v", err)
	}

	// Row 20 is now CLOSED (both accessors agree).
	if !productionCoordinatorRollbackRehearsed(r, capb, false) {
		t.Fatal("row 20 must be closed after a successful coordinator-routed rehearsal (locking)")
	}
	if !r.coordinatorRollbackRehearsalAttested(capb) {
		t.Fatal("coordinatorRollbackRehearsalAttested must be true after a successful rehearsal")
	}
	// The durable record validates and is coordinator-routed with the full ladder + Observe recovery.
	rec, err := loadCoordinatorRehearsal(capb)
	if err != nil || rec == nil {
		t.Fatalf("a valid record must be loadable, got rec=%v err=%v", rec, err)
	}
	if reason := canary.ValidateCoordinatorRehearsal(rec, capb.String(), currentRuntimeIdentity()); reason != canary.CoordinatorRehearsalOK {
		t.Fatalf("the recorded evidence must validate, got %q", reason)
	}
	if !rec.Routed || rec.RecoveredMode != canary.CoordinatorRecoveredMode() {
		t.Fatalf("evidence must be coordinator-routed and recovered to observe, got routed=%v recovered=%q", rec.Routed, rec.RecoveredMode)
	}

	// SECURITY: the rehearsal must not have mutated live state, the live rollout file, or the mgmt cap.
	if r.stateFor(capb).CurrentMode() != liveModeBefore {
		t.Fatalf("SECURITY: the rehearsal mutated live rollout mode (%s → %s)", liveModeBefore, r.stateFor(capb).CurrentMode())
	}
	if _, serr := os.Stat(rolloutStateFileName(capb)); !os.IsNotExist(serr) {
		t.Fatal("SECURITY: the rehearsal must not write the live rollout state file")
	}
	if _, serr := os.Stat(coordinatorRehearsalScratchPath(capb)); !os.IsNotExist(serr) {
		t.Fatal("the drill scratch file must be removed after the drill")
	}
	if r.coordinatorRollbackRehearsalAttested(rollout.CapabilityManagement) {
		t.Fatal("a gateway rehearsal must not certify the management capability (capability isolation)")
	}
}

// TestCoordinatorRehearsal_RejectionCases is the core-invariant proof: the rehearsal FAILS (records no
// evidence, leaves row 20 unmet) for every security reason a REAL Canary→Shadow rollback through the
// coordinator would fail — because it runs through that same coordinator. Each case breaks exactly one
// node-authoritative gate.
func TestCoordinatorRehearsal_RejectionCases(t *testing.T) {
	capb := rollout.CapabilityGateway
	cases := []struct {
		name   string
		break_ func(t *testing.T, r *mcpRollout)
	}{
		{"shadow_preflight_fails", func(t *testing.T, _ *mcpRollout) {
			// Remove the inventory so the Gateway Shadow preflight the Canary→Shadow rung hits fails.
			publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
		}},
		{"emergency_kill_active", func(t *testing.T, r *mcpRollout) {
			// Engage the emergency kill: the Shadow preflight includes shadowPFKillActive.
			r.stateFor(capb).EngageKillSwitch("test", 1)
		}},
		{"durability_unhealthy", func(t *testing.T, _ *mcpRollout) {
			// Force the persist gate to fail: a rollback that cannot be durably persisted must not pass.
			prev := rolloutStateAtomicWrite
			rolloutStateAtomicWrite = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
			t.Cleanup(func() { rolloutStateAtomicWrite = prev })
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := withCoordinatorRehearsalEnv(t)
			tc.break_(t, r)
			if err := r.recordCoordinatorRehearsal(capb); err == nil {
				t.Fatalf("SECURITY: the rehearsal must FAIL when %s, but it passed", tc.name)
			}
			if r.coordinatorRollbackRehearsalAttested(capb) {
				t.Fatalf("SECURITY: a failed rehearsal (%s) must leave row 20 UNMET", tc.name)
			}
			if _, serr := os.Stat(coordinatorRehearsalPath(capb)); !os.IsNotExist(serr) {
				t.Fatalf("a failed rehearsal (%s) must write no durable record", tc.name)
			}
		})
	}
}

// TestCoordinatorRehearsal_InvalidConfigRejected proves the config/scope-validity gate (cfg.Validate
// via SetConfig, inside the coordinator core) fails the rehearsal: a Shadow rung whose scope is not
// enumerable (Shadow/Canary require an enumerable scope) is rejected exactly as a real transition would
// be, so a rollback whose target config the coordinator would reject records no evidence.
func TestCoordinatorRehearsal_InvalidConfigRejected(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway
	// Corrupt the drill's Shadow config to carry a NON-enumerable scope, which cfg.Validate rejects for
	// an executing mode.
	prev := rehearsalDrillConfigsFn
	rehearsalDrillConfigsFn = func(c rollout.Capability) (canaryCfg, shadowCfg, observeCfg rollout.SignedConfig) {
		canaryCfg, shadowCfg, observeCfg = rehearsalDrillConfigs(c)
		shadowCfg.Scope = rollout.ScopeSpec{Capability: c} // no tenants/principals/operations ⇒ not enumerable
		return
	}
	t.Cleanup(func() { rehearsalDrillConfigsFn = prev })
	if err := r.recordCoordinatorRehearsal(capb); err == nil {
		t.Fatal("SECURITY: an invalid Shadow config (non-enumerable scope) must fail the rehearsal")
	}
	if r.coordinatorRollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: an invalid-config rehearsal must leave row 20 unmet")
	}
}
