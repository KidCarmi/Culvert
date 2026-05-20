package main

// recover_cluster_update_completeness_test.go — coverage for the four
// previously-unmapped Phase strings in recoverClusterUpdate.
//
// Background
// ==========
// Before this PR, recoverClusterUpdate (update_cluster.go) handled only
// five of the nine documented Phase strings declared on
// ClusterUpdateState.Phase (`canary`, `canary_soak`, `updating_dps`,
// `updating_cp`, `complete`, `failed`, `halted`, `cp_rolled_back`,
// `auto_rollback`). The four unmapped phases — `canary`, `canary_soak`,
// `auto_rollback`, `cp_rolled_back` — left Active=true on the
// in-memory state after recovery, which would cause apiClusterUpdate
// to reject any subsequent admin POST with "update already in
// progress" even though no orchestrator was running.
//
// This file pins the new recovery semantics for those four phases AND
// keeps the pre-existing recovery semantics under guard (regression
// suite for the five already-mapped phases plus the "inactive" branch).
//
// Recovery design (rationale per the brief — no guessing)
// =======================================================
//
//	canary         → Phase=halted, Active=false       (mirror updating_dps)
//	canary_soak    → Phase=halted, Active=false       (soak verification didn't run)
//	auto_rollback  → Phase preserved, Active=false    (preserve operator context)
//	cp_rolled_back → Phase preserved, Active=false    (already terminal in normal flow)
//
// canary / canary_soak transition to halted because they represent
// interrupted in-progress operations (a batch was being updated, or
// the soak's post-sleep failure check was pending). The admin must
// re-issue. Per-node Status values in the Nodes map are preserved so
// the operator can see which canary nodes were already updated.
//
// auto_rollback / cp_rolled_back preserve Phase because they carry
// operator-visible context that "halted" would erase:
//   - auto_rollback: the rollback was running when killed; the per-
//     node Status map carries rolling_back / rolled_back /
//     rollback_failed. The operator needs to know it was a rollback
//     (not a forward update halt) to decide next steps.
//   - cp_rolled_back: the CP updater HTTP failed before container
//     restart; the system is in a known-bad-but-functional state
//     (DPs updated, CP not). Preserving the Phase preserves that
//     signal.
//
// In neither case does recoverClusterUpdate spawn a new orchestrator
// or attempt to continue any in-flight work — out of scope per the
// brief.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeAndRecover is a small test helper: writes the given on-disk
// state, points clusterUpdateFile at it, resets in-memory state, then
// calls recoverClusterUpdate(). Snapshot/restore of the package
// global is the caller's responsibility (use snapshotClusterUpdateState).
func writeAndRecover(t *testing.T, state ClusterUpdateState) {
	t.Helper()
	dir := t.TempDir()
	clusterUpdateFile = filepath.Join(dir, "cluster_update.json")

	data, err := json.MarshalIndent(&state, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(clusterUpdateFile, data, 0o600); err != nil {
		t.Fatalf("write %q: %v", clusterUpdateFile, err)
	}

	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = false
	clusterUpdateState.Phase = ""
	clusterUpdateState.Nodes = nil
	clusterUpdateState.TargetTag = ""
	clusterUpdateState.PreviousTag = ""
	clusterUpdateState.mu.Unlock()

	recoverClusterUpdate()
}

// recoverSnap is a copy of recovery-relevant fields, captured under
// the lock so assertions don't race with concurrent mutators.
type recoverSnap struct {
	Active     bool
	Phase      string
	NodesLen   int
	NodeStatus map[string]string
}

func snapshotAfterRecover() recoverSnap {
	clusterUpdateState.mu.Lock()
	defer clusterUpdateState.mu.Unlock()
	s := recoverSnap{
		Active:     clusterUpdateState.Active,
		Phase:      clusterUpdateState.Phase,
		NodesLen:   len(clusterUpdateState.Nodes),
		NodeStatus: make(map[string]string, len(clusterUpdateState.Nodes)),
	}
	for k, n := range clusterUpdateState.Nodes {
		s.NodeStatus[k] = n.Status
	}
	return s
}

// ─── Phase matrix: all 9 Phase strings + the inactive branch ────────

// TestRecoverClusterUpdate_PhaseMatrix is the single guard for every
// branch of recoverClusterUpdate's switch. It covers:
//   - the five pre-existing phases (complete, failed, halted,
//     updating_cp, updating_dps) — regression coverage
//   - the four new phases (canary, canary_soak, auto_rollback,
//     cp_rolled_back) — the work surface of this PR
//   - the inactive-Active branch (Active=false → recovery is a no-op)
//
// Each row asserts (Phase, Active) after recovery. Per-node status
// preservation is asserted separately in the dedicated tests below.
func TestRecoverClusterUpdate_PhaseMatrix(t *testing.T) {
	snapshotClusterUpdateState(t)

	cases := []struct {
		name       string
		diskPhase  string
		diskActive bool
		wantPhase  string
		wantActive bool
	}{
		// Pre-existing terminal phases — Phase preserved, Active cleared.
		{"complete_terminal", "complete", true, "complete", false},
		{"failed_terminal", "failed", true, "failed", false},
		{"halted_terminal", "halted", true, "halted", false},

		// Pre-existing interrupted-in-progress phases.
		{"updating_cp_becomes_complete", "updating_cp", true, "complete", false},
		{"updating_dps_becomes_halted", "updating_dps", true, "halted", false},

		// NEW: previously-unmapped phases.
		{"canary_becomes_halted", "canary", true, "halted", false},
		{"canary_soak_becomes_halted", "canary_soak", true, "halted", false},
		{"auto_rollback_preserves_phase", "auto_rollback", true, "auto_rollback", false},
		{"cp_rolled_back_preserves_phase", "cp_rolled_back", true, "cp_rolled_back", false},

		// Active=false: recovery is a no-op; nothing should change.
		{"inactive_is_noop_canary", "canary", false, "canary", false},
		{"inactive_is_noop_auto_rollback", "auto_rollback", false, "auto_rollback", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writeAndRecover(t, ClusterUpdateState{
				Active:    tc.diskActive,
				Phase:     tc.diskPhase,
				TargetTag: "v1.2.3-matrix",
				StartedAt: time.Now().Add(-1 * time.Minute),
			})

			snap := snapshotAfterRecover()
			if snap.Phase != tc.wantPhase {
				t.Errorf("Phase after recovery = %q; want %q", snap.Phase, tc.wantPhase)
			}
			if snap.Active != tc.wantActive {
				t.Errorf("Active after recovery = %v; want %v", snap.Active, tc.wantActive)
			}
		})
	}
}

// ─── Per-phase deep tests: per-node status preservation ─────────────

// TestRecoverClusterUpdate_Canary_PreservesPerNodeStatus pins the
// contract that per-node Status values from the canary batch are NOT
// reset by recovery. The admin needs to see which canary nodes were
// updated before the interruption.
func TestRecoverClusterUpdate_Canary_PreservesPerNodeStatus(t *testing.T) {
	snapshotClusterUpdateState(t)

	writeAndRecover(t, ClusterUpdateState{
		Active:    true,
		Phase:     "canary",
		TargetTag: "v9.9.9-canary",
		StartedAt: time.Now().Add(-2 * time.Minute),
		Nodes: map[string]*NodeUpdateStatus{
			"dp-canary-1": {NodeID: "dp-canary-1", Status: "complete", NewVersion: "v9.9.9-canary"},
			"dp-canary-2": {NodeID: "dp-canary-2", Status: "updating"},
			"dp-canary-3": {NodeID: "dp-canary-3", Status: "pending"},
		},
	})

	snap := snapshotAfterRecover()
	if snap.Phase != "halted" {
		t.Errorf("Phase = %q; want %q", snap.Phase, "halted")
	}
	if snap.Active {
		t.Errorf("Active = true; want false (no orchestrator should be running post-recovery)")
	}
	wantStatus := map[string]string{
		"dp-canary-1": "complete", // truly completed
		"dp-canary-2": "updating", // mid-update — left as-is for operator inspection
		"dp-canary-3": "pending",  // never started
	}
	for nodeID, want := range wantStatus {
		if got := snap.NodeStatus[nodeID]; got != want {
			t.Errorf("post-recovery Nodes[%q].Status = %q; want %q (per-node status must be preserved for operator)", nodeID, got, want)
		}
	}
}

// TestRecoverClusterUpdate_CanarySoak_NoOrchestratorRunning pins that
// recovery during the soak period produces a halted, non-active state
// with NO orchestrator side effects (no per-node mutations — the
// orchestrator was just sleeping).
func TestRecoverClusterUpdate_CanarySoak_NoOrchestratorRunning(t *testing.T) {
	snapshotClusterUpdateState(t)

	writeAndRecover(t, ClusterUpdateState{
		Active:    true,
		Phase:     "canary_soak",
		TargetTag: "v9.9.9-soak",
		StartedAt: time.Now().Add(-3 * time.Minute),
		Nodes: map[string]*NodeUpdateStatus{
			"dp-canary-1":    {NodeID: "dp-canary-1", Status: "complete", NewVersion: "v9.9.9-soak"},
			"dp-canary-2":    {NodeID: "dp-canary-2", Status: "complete", NewVersion: "v9.9.9-soak"},
			"dp-remaining-1": {NodeID: "dp-remaining-1", Status: "pending"},
		},
	})

	snap := snapshotAfterRecover()
	if snap.Phase != "halted" {
		t.Errorf("Phase = %q; want %q", snap.Phase, "halted")
	}
	if snap.Active {
		t.Errorf("Active = true; want false")
	}
	wantStatus := map[string]string{
		"dp-canary-1":    "complete",
		"dp-canary-2":    "complete",
		"dp-remaining-1": "pending",
	}
	for nodeID, want := range wantStatus {
		if got := snap.NodeStatus[nodeID]; got != want {
			t.Errorf("post-recovery Nodes[%q].Status = %q; want %q", nodeID, got, want)
		}
	}
}

// TestRecoverClusterUpdate_AutoRollback_PreservesPhase pins the
// design choice that auto_rollback's operator-visible Phase string is
// preserved across recovery so apiClusterUpdateStatus continues to
// show "rollback was running" context. Per-node rollback Status
// values (rolling_back / rolled_back / rollback_failed) are also
// preserved for operator inspection.
func TestRecoverClusterUpdate_AutoRollback_PreservesPhase(t *testing.T) {
	snapshotClusterUpdateState(t)

	writeAndRecover(t, ClusterUpdateState{
		Active:      true,
		Phase:       "auto_rollback",
		TargetTag:   "v9.9.9-failed",
		PreviousTag: "v9.9.8-good",
		StartedAt:   time.Now().Add(-5 * time.Minute),
		Nodes: map[string]*NodeUpdateStatus{
			"dp-a": {NodeID: "dp-a", Status: "rolled_back"},
			"dp-b": {NodeID: "dp-b", Status: "rolling_back"}, // mid-rollback
			"dp-c": {NodeID: "dp-c", Status: "rollback_failed"},
			"dp-d": {NodeID: "dp-d", Status: "complete"}, // updated before rollback triggered
		},
	})

	snap := snapshotAfterRecover()
	if snap.Phase != "auto_rollback" {
		t.Errorf("Phase = %q; want %q (auto_rollback must be PRESERVED — operator-visible rollback context)", snap.Phase, "auto_rollback")
	}
	if snap.Active {
		t.Errorf("Active = true; want false (no orchestrator running)")
	}
	wantStatus := map[string]string{
		"dp-a": "rolled_back",
		"dp-b": "rolling_back", // operator must inspect; recovery does NOT re-attempt
		"dp-c": "rollback_failed",
		"dp-d": "complete",
	}
	for nodeID, want := range wantStatus {
		if got := snap.NodeStatus[nodeID]; got != want {
			t.Errorf("post-recovery Nodes[%q].Status = %q; want %q (per-node rollback status must be preserved)", nodeID, got, want)
		}
	}
}

// TestRecoverClusterUpdate_CPRolledBack_PreservesPhase pins the
// design choice that cp_rolled_back preserves Phase so operators see
// the "DPs updated, CP not" terminal state. The phase is set by
// updateCPDirect when the updater HTTP fails BEFORE container
// restart, so the cluster is in a known-bad-but-functional state.
func TestRecoverClusterUpdate_CPRolledBack_PreservesPhase(t *testing.T) {
	snapshotClusterUpdateState(t)

	writeAndRecover(t, ClusterUpdateState{
		Active:      true,
		Phase:       "cp_rolled_back",
		TargetTag:   "v9.9.9-cp-failed",
		PreviousTag: "v9.9.8-prior",
		StartedAt:   time.Now().Add(-10 * time.Minute),
		Nodes: map[string]*NodeUpdateStatus{
			"dp-a": {NodeID: "dp-a", Status: "complete", NewVersion: "v9.9.9-cp-failed"},
			"dp-b": {NodeID: "dp-b", Status: "complete", NewVersion: "v9.9.9-cp-failed"},
		},
	})

	snap := snapshotAfterRecover()
	if snap.Phase != "cp_rolled_back" {
		t.Errorf("Phase = %q; want %q (cp_rolled_back must be PRESERVED — DPs-ahead-of-CP context)", snap.Phase, "cp_rolled_back")
	}
	if snap.Active {
		t.Errorf("Active = true; want false")
	}
	for _, nodeID := range []string{"dp-a", "dp-b"} {
		if got := snap.NodeStatus[nodeID]; got != "complete" {
			t.Errorf("post-recovery Nodes[%q].Status = %q; want %q (DPs ARE on the new version)", nodeID, got, "complete")
		}
	}
}

// ─── Operator-visible contract: post-recovery Active must be false ──

// TestRecoverClusterUpdate_AllPhasesUnblockNextUpdate pins the
// operator-visible contract that no zombie Active=true state can
// block a subsequent admin POST. startClusterUpdate (and the
// apiClusterUpdate handler that wraps it) rejects with "update
// already in progress" when clusterUpdateState.Active is true; that
// rejection was the user-facing symptom of the four-phase gap.
//
// This test exercises each of the four new phases AND the five
// pre-existing phases under recovery, then asserts Active=false in
// every case so the next admin POST is admissible.
func TestRecoverClusterUpdate_AllPhasesUnblockNextUpdate(t *testing.T) {
	snapshotClusterUpdateState(t)

	for _, phase := range []string{
		"complete", "failed", "halted",
		"updating_cp", "updating_dps",
		"canary", "canary_soak", "auto_rollback", "cp_rolled_back",
	} {
		t.Run(phase, func(t *testing.T) {
			writeAndRecover(t, ClusterUpdateState{
				Active:    true,
				Phase:     phase,
				TargetTag: "v0.0.0-unblock-check",
				StartedAt: time.Now(),
			})

			snap := snapshotAfterRecover()
			if snap.Active {
				t.Errorf("after recovery of Phase=%q: Active = true; want false (blocks next admin POST)", phase)
			}
		})
	}
}
