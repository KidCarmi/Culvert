package main

import (
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canary"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	"github.com/KidCarmi/Culvert/internal/mcp/tooltrust"
)

func canaryUnmetHas(rd canary.Readiness, want canary.Reason) bool {
	for _, r := range rd.Unmet {
		if r == want {
			return true
		}
	}
	return false
}

// TestCanaryNodeReadiness_DormantDefault is the load-bearing dormancy proof: in the shipped
// build the Canary node is NEVER ready, and the blocker set always includes
// live_executor_absent (the unarmed live tier). This is what keeps Canary unreachable.
func TestCanaryNodeReadiness_DormantDefault(t *testing.T) {
	rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway)
	if rd.Ready {
		t.Fatal("SECURITY: Canary node readiness must be false in the shipped build (live tier unarmed)")
	}
	if !canaryUnmetHas(rd, canary.ReasonLiveExecutorAbsent) {
		t.Fatalf("dormant Canary must report live_executor_absent, got %v", rd.Unmet)
	}
	// The live-execution-specific facts must all be unmet together (they compose as one unit).
	for _, want := range []canary.Reason{
		canary.ReasonLiveExecutorAbsent, canary.ReasonUpstreamCallerAbsent,
		canary.ReasonCredentialPathNotReady, canary.ReasonKillBoundaryGuardAbsent,
		canary.ReasonToolFreshnessGuardAbsent,
	} {
		if !canaryUnmetHas(rd, want) {
			t.Errorf("dormant Canary must report %s", want)
		}
	}
	// Management is a category error for Canary — never executes upstream.
	if rd := evaluateCanaryNodeReadiness(rollout.CapabilityManagement); rd.Ready ||
		len(rd.Unmet) != 1 || rd.Unmet[0] != canary.ReasonCapabilityNotGateway {
		t.Fatalf("Management Canary must fail with exactly capability_not_gateway, got %v", rd.Unmet)
	}
	// The boolean gate a future arming would consult must agree: never ready in this build.
	if canaryActivationReady(rollout.CapabilityGateway) {
		t.Fatal("SECURITY: canaryActivationReady must be false in the shipped build")
	}
}

// validCanaryActivationInput builds an activation input whose SCOPE / APPROVAL / BUDGET /
// server / fingerprint facts are all satisfied — so any of those reasons appearing in Unmet
// proves the wiring, and their ABSENCE proves a valid input is honoured (the node facts still
// block via live_executor_absent).
func validCanaryActivationInput(now time.Time) CanaryActivationInput {
	exp := now.Add(time.Hour)
	var digest tooltrust.FingerprintDigest
	for i := range digest {
		digest[i] = 0x11
	}
	fpHex := hex.EncodeToString(digest[:]) // scope tool fingerprint == hex of the digest
	return CanaryActivationInput{
		Capability: rollout.CapabilityGateway,
		Scope: rollout.ScopeSpec{
			Capability: rollout.CapabilityGateway,
			Tenants:    []string{"t1"},
			Servers:    []string{"srv-canary"},
			Tools:      []rollout.ToolSel{{Server: "srv-canary", Name: "echo", Fingerprint: fpHex}},
			Principals: []string{"synthetic"},
			Operations: []rollout.RiskClass{rollout.RiskRead},
		},
		ScopeRev: 1,
		// One live_execution approval bound to the EXACT scoped tool (server+name+fingerprint).
		ToolApprovals: []canary.ToolApprovalBinding{{
			Target: canary.LiveTarget{Tenant: "t1", ServerID: "srv-canary", ToolName: "echo", Fingerprint: digest, FingerprintFormat: 1},
			Approval: &tooltrust.ToolApproval{
				Tenant: "t1", ServerID: "srv-canary", ToolName: "echo",
				Fingerprint: digest, FingerprintFormatVersion: 1,
				Purpose: tooltrust.PurposeLiveExecution, Status: tooltrust.StatusActive,
				RequestedBy: "alice", ApprovedBy: "bob", ApprovedAt: now, ExpiresAt: &exp,
			},
		}},
		Budget: canary.Budget{
			MaxTotalExecutions: 50, MaxExecutionsPerMinute: 5, MaxConcurrentExecutions: 1,
			MaxPrincipals: 1, MaxTools: 1, MaxServers: 1, Window: time.Hour,
		},
		ServerUsable: true, FingerprintCurrent: true, Now: now,
	}
}

// TestCanaryActivationPreflight_WiresScopeApprovalBudget proves the root preflight correctly
// maps activation inputs to facts: with valid inputs the scope/approval/budget/server/
// fingerprint reasons are ABSENT (satisfied); flipping any input surfaces exactly its reason.
// The overall verdict stays not-ready via the node facts (live tier absent) throughout — no
// activation input can make Canary ready by itself.
func TestCanaryActivationPreflight_WiresScopeApprovalBudget(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	base := evaluateCanaryActivationPreflight(validCanaryActivationInput(now))
	if base.Ready {
		t.Fatal("SECURITY: no set of activation inputs may make Canary ready while the live tier is unarmed")
	}
	for _, notWanted := range []canary.Reason{
		canary.ReasonScopeNotBounded, canary.ReasonScopeNotReadFirst, canary.ReasonLiveApprovalInvalid,
		canary.ReasonServerNotUsable, canary.ReasonToolFingerprintStale, canary.ReasonBudgetNotConfigured,
	} {
		if canaryUnmetHas(base, notWanted) {
			t.Errorf("valid activation input should satisfy %s, but it is unmet", notWanted)
		}
	}

	flips := []struct {
		name   string
		mutate func(*CanaryActivationInput)
		reason canary.Reason
	}{
		{"unbounded_scope", func(in *CanaryActivationInput) { in.Scope.Servers = nil }, canary.ReasonScopeNotBounded},
		{"non_read_first", func(in *CanaryActivationInput) { in.Scope.Operations = []rollout.RiskClass{rollout.RiskWrite} }, canary.ReasonScopeNotReadFirst},
		{"shadow_approval", func(in *CanaryActivationInput) {
			in.ToolApprovals[0].Approval.Purpose = tooltrust.PurposeShadowEvaluation
		}, canary.ReasonLiveApprovalInvalid},
		{"nil_approval", func(in *CanaryActivationInput) { in.ToolApprovals[0].Approval = nil }, canary.ReasonLiveApprovalInvalid},
		{"tool_unapproved", func(in *CanaryActivationInput) { in.ToolApprovals = nil }, canary.ReasonLiveApprovalInvalid},
		{"approval_outside_scope", func(in *CanaryActivationInput) {
			in.ToolApprovals[0].Target.ToolName = "other"
			in.ToolApprovals[0].Approval.ToolName = "other"
		}, canary.ReasonLiveApprovalInvalid},
		{"server_not_usable", func(in *CanaryActivationInput) { in.ServerUsable = false }, canary.ReasonServerNotUsable},
		{"stale_fingerprint", func(in *CanaryActivationInput) { in.FingerprintCurrent = false }, canary.ReasonToolFingerprintStale},
		{"no_budget", func(in *CanaryActivationInput) { in.Budget = canary.Budget{} }, canary.ReasonBudgetNotConfigured},
	}
	for _, tc := range flips {
		t.Run(tc.name, func(t *testing.T) {
			in := validCanaryActivationInput(now)
			tc.mutate(&in)
			rd := evaluateCanaryActivationPreflight(in)
			if rd.Ready {
				t.Fatalf("%s must keep Canary not-ready", tc.name)
			}
			if !canaryUnmetHas(rd, tc.reason) {
				t.Fatalf("%s must surface %s, got %v", tc.name, tc.reason, rd.Unmet)
			}
		})
	}
}

// TestRollbackPathHealthy_DurableRehearsalAndRace proves the Codex P1 fix: RollbackPathHealthy
// is false until a rollback is DURABLY rehearsed, true after, and reads persistStatus + the
// rehearsal evidence as one consistent snapshot under durableMu (no torn read of an in-flight
// rehearsal). The concurrent half is a race-detector gate.
func TestRollbackPathHealthy_DurableRehearsalAndRace(t *testing.T) {
	pinTestBuildVersion(t) // a valid rehearsal record requires a non-placeholder build stamp
	_ = getMCPRollout()    // fire the sync.Once before swapping
	prevR := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	prevDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { globalMCPRollout = prevR; dataDir = prevDir })

	capb := rollout.CapabilityGateway
	if rollbackPathHealthy(capb) {
		t.Fatal("an unrehearsed rollback path must be unhealthy")
	}
	if err := globalMCPRollout.recordRehearsal(capb); err != nil {
		t.Fatalf("recordRehearsal: %v", err)
	}
	if !rollbackPathHealthy(capb) {
		t.Fatal("a durably-rehearsed rollback path must be healthy")
	}

	// Concurrent rehearsals and readiness reads must not race and must never panic (the fix
	// reads both facts under durableMu, the same lock recordRehearsal holds).
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); _ = globalMCPRollout.recordRehearsal(capb) }()
		go func() { defer wg.Done(); _ = rollbackPathHealthy(capb) }()
	}
	wg.Wait()
	if !rollbackPathHealthy(capb) {
		t.Fatal("rollback path must remain healthy after concurrent rehearsals")
	}
}

// TestRollbackPathHealthy_ClearsStaleWriteFailed proves the Codex P2 fix: a successful durable
// rehearsal clears a prior write_failed persistence status, so the rollback path is not stuck
// reporting unhealthy forever after one transient write failure.
func TestRollbackPathHealthy_ClearsStaleWriteFailed(t *testing.T) {
	pinTestBuildVersion(t) // a valid rehearsal record requires a non-placeholder build stamp
	_ = getMCPRollout()
	prevR := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	prevDir := dataDir
	dataDir = t.TempDir()
	t.Cleanup(func() { globalMCPRollout = prevR; dataDir = prevDir })

	capb := rollout.CapabilityGateway
	globalMCPRollout.setPersistStatus(capb, "write_failed") // an earlier rehearsal write failed
	if rollbackPathHealthy(capb) {
		t.Fatal("a write_failed persistence status must report the rollback path unhealthy")
	}
	if err := globalMCPRollout.recordRehearsal(capb); err != nil {
		t.Fatalf("recordRehearsal: %v", err)
	}
	if got := globalMCPRollout.persistStatus(capb); got != "recovered" {
		t.Fatalf("a successful rehearsal must clear stale write_failed, got %q", got)
	}
	if !rollbackPathHealthy(capb) {
		t.Fatal("rollback path must be healthy after a durable rehearsal cleared the stale failure")
	}
}

// TestCanaryRollbackCoordinatorRehearsal_OpenPrerequisiteBlocksReadiness is the owner-directed proof
// for finding CANARY-ROLLBACK-COORDINATOR-REHEARSAL: the executable persist/restore rehearsal proves
// rollback MECHANICS only, so a node that has satisfied EVERY OTHER node prerequisite — including the
// mechanics rehearsal (rollback_path_healthy) — is STILL not Canary-ready while the authoritative
// coordinator-routed rollback rehearsal is OPEN. No transition can become READY merely because the
// mechanics rehearsal passed; it fails closed with rollback_coordinator_rehearsal_pending.
func TestCanaryRollbackCoordinatorRehearsal_OpenPrerequisiteBlocksReadiness(t *testing.T) {
	withTempDataDir(t)
	withCanaryReadyNode(t) // arms EVERYTHING, including the coordinator-rehearsal seam
	// Sanity (non-vacuity): with the seam armed the node IS Canary-ready.
	if rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway); !rd.Ready {
		t.Fatalf("precondition: a fully-armed node must be node-ready, unmet=%v", rd.Unmet)
	}
	// Now restore the PRODUCTION posture for the coordinator-rehearsal seam only — the authoritative
	// rollback rehearsal is OPEN. Everything else (incl. the mechanics rehearsal) stays satisfied.
	prev := coordinatorRollbackRehearsedFn
	coordinatorRollbackRehearsedFn = productionCoordinatorRollbackRehearsed
	t.Cleanup(func() { coordinatorRollbackRehearsedFn = prev })

	rd := evaluateCanaryNodeReadiness(rollout.CapabilityGateway)
	if rd.Ready {
		t.Fatal("SECURITY: a node whose MECHANICS rehearsal passed must NOT be Canary-ready while the authoritative coordinator-routed rehearsal is open")
	}
	if !canaryUnmetHas(rd, canary.ReasonRollbackCoordinatorRehearsalPending) {
		t.Fatalf("the open prerequisite must surface rollback_coordinator_rehearsal_pending, got %v", rd.Unmet)
	}
	// The mechanics rehearsal stays satisfied — proving this is a SEPARATE hard prerequisite, not a
	// regression of rollback_path_healthy.
	if canaryUnmetHas(rd, canary.ReasonRollbackPathUnhealthy) {
		t.Fatalf("rollback_path_healthy (mechanics) must remain satisfied; the sole rollback block is the coordinator rehearsal, got %v", rd.Unmet)
	}
}

// TestCanaryRollbackCoordinatorRehearsal_ProductionFailsClosed proves the production seam certifies the
// authoritative rollback rehearsal ONLY from durable coordinator-routed evidence: with no such evidence
// (a fresh node — the shipped default, where no coordinator drill has run) it returns false for every
// capability, so the mechanics rehearsal can never substitute for it. Both the locked and locking
// accessors agree.
func TestCanaryRollbackCoordinatorRehearsal_ProductionFailsClosed(t *testing.T) {
	withTempDataDir(t) // no coordinator-rehearsal record on disk
	_ = getMCPRollout()
	prevR := globalMCPRollout
	globalMCPRollout = &mcpRollout{
		gateway:    rollout.NewState(rollout.CapabilityGateway, rollout.DefaultLimits()),
		management: rollout.NewState(rollout.CapabilityManagement, rollout.DefaultLimits()),
	}
	t.Cleanup(func() { globalMCPRollout = prevR })
	for _, capb := range []rollout.Capability{rollout.CapabilityGateway, rollout.CapabilityManagement} {
		if productionCoordinatorRollbackRehearsed(globalMCPRollout, capb, false) {
			t.Fatalf("production (locking) must not certify the rehearsal for %s with no durable evidence", capb)
		}
		if productionCoordinatorRollbackRehearsed(globalMCPRollout, capb, true) {
			t.Fatalf("production (locked) must not certify the rehearsal for %s with no durable evidence", capb)
		}
	}
	// The node dry-run must advertise the prerequisite in its full vocabulary even when everything is unmet.
	all := canary.AllReasons()
	found := false
	for _, r := range all {
		if r == canary.ReasonRollbackCoordinatorRehearsalPending {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("rollback_coordinator_rehearsal_pending must be in the advertised prerequisite vocabulary")
	}
}

// TestMCPCanaryStatus_ReadOnlyContract proves the admin surface reports the contract honestly:
// defined but not ready, a non-empty unmet list, the full prerequisite vocabulary, and the
// live tier unarmed.
func TestMCPCanaryStatus_ReadOnlyContract(t *testing.T) {
	st := mcpCanaryStatus()
	if st["defined"] != true {
		t.Error("canary status must report defined=true")
	}
	if st["node_ready"] != false {
		t.Error("canary status must report node_ready=false in this build")
	}
	if st["live_execution_armed"] != false {
		t.Error("canary status must report live_execution_armed=false")
	}
	unmet, _ := st["unmet"].([]string)
	if len(unmet) == 0 {
		t.Error("canary status unmet list must be non-empty in the dormant build")
	}
	all, _ := st["all_prerequisites"].([]string)
	if len(all) != len(canary.AllReasons()) {
		t.Errorf("all_prerequisites must advertise the full vocabulary (%d), got %d", len(canary.AllReasons()), len(all))
	}
}
