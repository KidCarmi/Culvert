package main

import (
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
)

// TestCoordinatorRehearsalParity_ProductionAndRehearsalAgree is the PARITY WALL: production commits and
// the authoritative rehearsal share ONE coordinator core (commitRolloutTransitionCore), so for the SAME
// node conditions they reach the SAME accept/reject verdict. A security gate that fired only in
// production — silently missing from the rehearsal — would make one of these DISAGREE and fail this
// test. For each gate-breaking condition, both a REAL production Canary→Shadow commit and the rehearsal
// must reject; with nothing broken, both accept.
func TestCoordinatorRehearsalParity_ProductionAndRehearsalAgree(t *testing.T) {
	capb := rollout.CapabilityGateway
	// productionRejects puts the LIVE gateway state directly into Canary (test setup — the live-exec gate
	// makes committing INTO Canary impossible here) and runs a REAL production Canary→Shadow commit,
	// reporting whether the coordinator rejected it. It then resets the live state so the rehearsal that
	// follows starts clean on the same node.
	productionRejects := func(t *testing.T, r *mcpRollout) bool {
		canaryCfg, shadowCfg, _ := rehearsalDrillConfigs(capb)
		if err := r.gateway.SetConfig(canaryCfg, "parity-setup", 1); err != nil {
			t.Fatalf("parity setup into canary: %v", err)
		}
		err := r.commitRolloutTransition(&shadowCfg, "parity", time.Unix(1000, 0))
		_ = r.gateway.SetConfig(rollout.DisabledConfig(capb), "parity-reset", 2)
		return err != nil
	}
	cases := []struct {
		name       string
		breakGate  func(t *testing.T, r *mcpRollout)
		wantReject bool
	}{
		{"healthy", func(*testing.T, *mcpRollout) {}, false},
		{"emergency_kill", func(_ *testing.T, r *mcpRollout) { r.gateway.EngageKillSwitch("t", 1) }, true},
		{"shadow_preflight", func(*testing.T, *mcpRollout) { publishMCPInventory(mcpInvNotConfigured, "", nil, nil) }, true},
		{"durability", func(t *testing.T, _ *mcpRollout) {
			prev := rolloutStateAtomicWrite
			rolloutStateAtomicWrite = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
			t.Cleanup(func() { rolloutStateAtomicWrite = prev })
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := withCoordinatorRehearsalEnv(t)
			tc.breakGate(t, r)
			prodRej := productionRejects(t, r)
			rehRej := r.recordCoordinatorRehearsal(capb) != nil
			if prodRej != tc.wantReject || rehRej != tc.wantReject {
				t.Fatalf("PARITY VIOLATION for %q: production rejected=%v, rehearsal rejected=%v, want both=%v",
					tc.name, prodRej, rehRej, tc.wantReject)
			}
		})
	}
}

// TestCoordinatorRehearsal_RoutingThroughCoreIsLoadBearing proves the rehearsal's security comes from
// ROUTING through the coordinator core, not from the drill itself: with an emergency kill active, the
// MECHANICS drill (direct SetConfig+persist, bypassing the coordinator) does NOT enforce the kill and
// succeeds, while the authoritative drill — routed through the core, whose Gateway Shadow preflight
// includes the kill — is blocked. A regression that made the rehearsal bypass the core would let it pass
// under the kill and fail this test.
func TestCoordinatorRehearsal_RoutingThroughCoreIsLoadBearing(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway
	r.stateFor(capb).EngageKillSwitch("t", 1) // emergency kill active on the live node

	// CONTROL: the mechanics drill bypasses the coordinator (direct SetConfig on a fresh scratch state),
	// so it never consults the emergency-kill gate and succeeds even with the kill active.
	if _, err := executeRollbackRehearsalDrill(capb); err != nil {
		t.Fatalf("control: the mechanics drill bypasses the coordinator, so the kill must not block it, got %v", err)
	}
	// The AUTHORITATIVE drill routes through the coordinator core, so the SAME kill blocks it — proving the
	// gate comes from the core, not the drill.
	if err := r.recordCoordinatorRehearsal(capb); err == nil {
		t.Fatal("SECURITY: the coordinator-routed rehearsal must be blocked by the emergency kill; routing through the core is what enforces it")
	}
	if r.coordinatorRollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: a kill-blocked rehearsal must record no evidence")
	}
}

// writeValidCoordinatorRecordForTest writes a valid coordinator-rehearsal record for the current build.
func writeValidCoordinatorRecordForTest(t *testing.T, capb rollout.Capability) {
	t.Helper()
	rec := canary.CoordinatorRollbackRehearsalRecord{
		SchemaVersion:       canary.CoordinatorRollbackRehearsalSchemaVersion,
		Capability:          capb.String(),
		Identity:            currentRuntimeIdentity(),
		Routed:              true,
		Steps:               canary.RequiredRollbackPath(),
		RecoveredMode:       canary.CoordinatorRecoveredMode(),
		RehearsedAtUnixNano: 1,
	}
	if err := saveCoordinatorRehearsal(capb, &rec); err != nil {
		t.Fatalf("write valid coordinator record: %v", err)
	}
}

// TestCoordinatorRehearsal_EvidenceEdges pins the durable-evidence fail-closed contract: a valid record
// attests; a build change, a not-routed record, and a corrupt record each fail closed (the corrupt one
// is quarantined), and evidence survives a restart (fresh singleton) for the SAME build only.
func TestCoordinatorRehearsal_EvidenceEdges(t *testing.T) {
	capb := rollout.CapabilityGateway

	t.Run("valid_attests_and_survives_restart", func(t *testing.T) {
		r := withCoordinatorRehearsalEnv(t)
		writeValidCoordinatorRecordForTest(t, capb)
		if !r.coordinatorRollbackRehearsalAttested(capb) {
			t.Fatal("a valid current-build record must attest")
		}
		// Restart: a FRESH rollout singleton (same dataDir/build) must still read the durable record.
		fresh := &mcpRollout{
			gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
			management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
		}
		if !fresh.coordinatorRollbackRehearsalAttested(capb) {
			t.Fatal("durable evidence must survive a restart for the same build")
		}
	})

	t.Run("build_change_fails_closed", func(t *testing.T) {
		r := withCoordinatorRehearsalEnv(t)
		writeValidCoordinatorRecordForTest(t, capb)
		if !r.coordinatorRollbackRehearsalAttested(capb) {
			t.Fatal("precondition: record must attest for its own build")
		}
		prev := buildCommit
		buildCommit = "ffff9999ffff" // a DIFFERENT commit ⇒ different identity
		t.Cleanup(func() { buildCommit = prev })
		if r.coordinatorRollbackRehearsalAttested(capb) {
			t.Fatal("SECURITY: a record from a different build must NOT attest (stale coordinator semantics)")
		}
	})

	t.Run("not_routed_record_fails_closed", func(t *testing.T) {
		r := withCoordinatorRehearsalEnv(t)
		rec := canary.CoordinatorRollbackRehearsalRecord{
			SchemaVersion: canary.CoordinatorRollbackRehearsalSchemaVersion,
			Capability:    capb.String(),
			Identity:      currentRuntimeIdentity(),
			Routed:        false, // NOT coordinator-routed — must never satisfy row 20
			Steps:         canary.RequiredRollbackPath(),
			RecoveredMode: canary.CoordinatorRecoveredMode(),
		}
		if err := saveCoordinatorRehearsal(capb, &rec); err != nil {
			t.Fatalf("write: %v", err)
		}
		if r.coordinatorRollbackRehearsalAttested(capb) {
			t.Fatal("SECURITY: a not-routed record must never satisfy the coordinator prerequisite")
		}
	})

	t.Run("corrupt_record_quarantined_fails_closed", func(t *testing.T) {
		r := withCoordinatorRehearsalEnv(t)
		path := coordinatorRehearsalPath(capb)
		if err := os.WriteFile(path, []byte(`{"schema_version":1,"unknown_field":true}`), 0o600); err != nil {
			t.Fatalf("write corrupt: %v", err)
		}
		if r.coordinatorRollbackRehearsalAttested(capb) {
			t.Fatal("SECURITY: a corrupt record must not attest")
		}
		// It must be quarantined (moved aside), not left in place.
		if _, serr := os.Stat(path); !os.IsNotExist(serr) {
			t.Fatal("a corrupt record must be quarantined (moved aside), not left at the live path")
		}
	})
}

// TestCoordinatorRehearsal_PersistFailureRecordsNoValidEvidence proves that when the evidence write
// lands but cannot be crash-synced (fileutil.ErrReplacedNotSynced), recordCoordinatorRehearsal reports
// failure and leaves NO valid record — a rehearsal the operator was told failed can never satisfy row 20
// after a restart.
func TestCoordinatorRehearsal_PersistFailureRecordsNoValidEvidence(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway
	prev := coordinatorRehearsalAtomicWrite
	coordinatorRehearsalAtomicWrite = func(path string, data []byte, mode os.FileMode) error {
		_ = fileutil.AtomicWrite(path, data, mode) // land the bytes (visible), then report not-synced
		return fileutil.ErrReplacedNotSynced
	}
	t.Cleanup(func() { coordinatorRehearsalAtomicWrite = prev })
	if err := r.recordCoordinatorRehearsal(capb); err == nil {
		t.Fatal("a not-synced evidence write must be reported as a failure")
	}
	if r.coordinatorRollbackRehearsalAttested(capb) {
		t.Fatal("SECURITY: a rehearsal whose evidence was not crash-durable must leave row 20 unmet")
	}
}

// TestCoordinatorRehearsal_ConcurrentIsRaceCleanAndDeadlockFree hammers the durableMu-serialized paths —
// repeated rehearsals, concurrent row-20 reads (locked and unlocked), and concurrent emergency-kill
// toggles — to prove the coordinator core routed by the rehearsal never re-enters the non-reentrant
// durableMu (deadlock) and is race-clean under -race. It is deterministic: every goroutine does a fixed
// amount of work and the test only asserts completion (all goroutines return), never an interleaving.
func TestCoordinatorRehearsal_ConcurrentIsRaceCleanAndDeadlockFree(t *testing.T) {
	r := withCoordinatorRehearsalEnv(t)
	capb := rollout.CapabilityGateway
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ { // repeated rehearsal writers
		wg.Add(1)
		go func() { defer wg.Done(); _ = r.recordCoordinatorRehearsal(capb) }()
	}
	for i := 0; i < 4; i++ { // concurrent readers (row-20 fact + dry-run readiness)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_ = r.coordinatorRollbackRehearsalAttested(capb)
				_ = evaluateCanaryNodeReadiness(capb)
			}
		}()
	}
	wg.Add(1) // concurrent kill toggler on the durable path
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			r.stateFor(capb).EngageKillSwitch("t", int64(i))
			r.stateFor(capb).ClearKillSwitch()
		}
	}()
	wg.Wait() // completes ⇒ no deadlock; -race ⇒ no data race
}

// TestCoordinatorRehearsalMutationCampaign_Roster is the §8 red-team roster: each mutation that would
// weaken the authoritative rehearsal is caught by a NAMED gate/test. It is a completeness check — every
// entry must map to a guarding proof — so a future change that drops one is visible here. The proofs are
// the tests in this package; this roster asserts the roster itself is complete and non-empty.
func TestCoordinatorRehearsalMutationCampaign_Roster(t *testing.T) {
	roster := map[string]string{
		"rehearsal_bypasses_coordinator_core":     "TestCoordinatorRehearsal_RoutingThroughCoreIsLoadBearing (mechanics bypass loses the kill gate; coordinator-routed enforces it)",
		"shadow_preflight_removed_from_rehearsal": "TestCoordinatorRehearsal_RejectionCases/shadow_preflight_fails + Parity/shadow_preflight",
		"emergency_kill_ignored_by_rehearsal":     "TestCoordinatorRehearsal_RejectionCases/emergency_kill_active + Parity/emergency_kill",
		"config_revision_check_ignored":           "TestCoordinatorRehearsal_InvalidConfigRejected (cfg.Validate via SetConfig in the core)",
		"durability_check_ignored":                "TestCoordinatorRehearsal_RejectionCases/durability_unhealthy + Parity/durability",
		"rehearsal_mutates_live_state":            "TestCoordinatorRehearsal_EndToEndPassThroughRealCoordinator (live mode + live file untouched; scratch removed)",
		"production_and_rehearsal_diverge":        "TestCoordinatorRehearsalParity_ProductionAndRehearsalAgree (shared core ⇒ identical verdicts)",
		"stale_evidence_after_build_change":       "TestCoordinatorRehearsal_EvidenceEdges/build_change_fails_closed",
		"corrupt_evidence_accepted":               "TestCoordinatorRehearsal_EvidenceEdges/corrupt_record_quarantined_fails_closed",
		"row20_true_without_a_successful_drill":   "TestCoordinatorRehearsal_RejectionCases (no evidence on failure) + ProductionFailsClosed (no evidence ⇒ false)",
	}
	if len(roster) != 10 {
		t.Fatalf("the mutation campaign must cover exactly the 10 required mutations, got %d", len(roster))
	}
	for mutation, proof := range roster {
		if proof == "" {
			t.Fatalf("mutation %q has no guarding proof", mutation)
		}
	}
}
