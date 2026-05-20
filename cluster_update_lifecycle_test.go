package main

// cluster_update_lifecycle_test.go — CL-3 regression coverage for
// runClusterUpdate's lifecycle ownership.
//
// Background
// ==========
// roadmap/CLUSTER-RUNTIME-DISCOVERY.md §13 CL-3 flagged that the
// cluster rolling-update orchestrator was spawned as a detached
// goroutine — `go runClusterUpdate()` at update_cluster.go:315, with
// no parent context and no shutdown hook. The orchestrator silently
// survived appLifecycleCancel and could start new node-update phases
// while the process was already shutting down.
//
// Fix (this PR)
// =============
// runClusterUpdate now takes a context.Context (parented at the
// spawn site to appLifecycleCtx). A small helper —
// clusterUpdateAbortOnShutdown — checks ctx.Err() at four phase
// boundaries:
//
//   boundary 1: top of runClusterUpdate (shutdown raced startup)
//   boundary 2: after the canary batch, before the canary soak
//   boundary 3: after the canary soak, before the remaining batch
//   boundary 4: before Phase 2 (CP self-update)
//
// On cancellation the orchestrator marks Phase="halted", persists,
// and returns. The deferred cleanup (CompletedAt / Active=false /
// persist / generateUpdateReport) then runs as it does on any other
// terminal path. Inner loops (drain sleep, gRPC, healthcheck poll,
// updater HTTP, canary soak time.Sleep) are intentionally NOT plumbed
// with ctx — the persistence + recoverClusterUpdate contract handles
// abrupt termination, and changing those loops would be the broad
// "update protocol redesign" CL-3 explicitly scopes out.
//
// Tests in this file
// ==================
//   1. Pre-cancelled-ctx round-trip: runClusterUpdate exits cleanly
//      within a tight bounded time, on-disk state shows Phase=halted
//      + Active=false.
//   2. Direct unit coverage of clusterUpdateAbortOnShutdown — cancel
//      and not-cancel branches, plus persistence verification.
//
// No sleeps, no retries, no reliance on update timing — the
// pre-cancelled ctx makes boundary 1 fire deterministically and the
// orchestrator exits in O(microseconds) of actual work.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// snapshotClusterUpdateState captures and restores the package-global
// clusterUpdateState and clusterUpdateFile for the duration of the
// test. Same whitebox idiom as PR #241 / #245 / #251 / CL-2.
func snapshotClusterUpdateState(t *testing.T) {
	t.Helper()
	clusterUpdateState.mu.Lock()
	savedState := ClusterUpdateState{
		Active:       clusterUpdateState.Active,
		TargetTag:    clusterUpdateState.TargetTag,
		PreviousTag:  clusterUpdateState.PreviousTag,
		Initiator:    clusterUpdateState.Initiator,
		StartedAt:    clusterUpdateState.StartedAt,
		CompletedAt:  clusterUpdateState.CompletedAt,
		Phase:        clusterUpdateState.Phase,
		ErrorBudget:  clusterUpdateState.ErrorBudget,
		Failures:     clusterUpdateState.Failures,
		ConsecFails:  clusterUpdateState.ConsecFails,
		CanaryCount:  clusterUpdateState.CanaryCount,
		CanarySoak:   clusterUpdateState.CanarySoak,
		AutoRollback: clusterUpdateState.AutoRollback,
	}
	if clusterUpdateState.Nodes != nil {
		savedState.Nodes = make(map[string]*NodeUpdateStatus, len(clusterUpdateState.Nodes))
		for k, v := range clusterUpdateState.Nodes {
			cp := *v
			savedState.Nodes[k] = &cp
		}
	}
	clusterUpdateState.mu.Unlock()

	savedPath := clusterUpdateFile

	t.Cleanup(func() {
		clusterUpdateState.mu.Lock()
		clusterUpdateState.Active = savedState.Active
		clusterUpdateState.TargetTag = savedState.TargetTag
		clusterUpdateState.PreviousTag = savedState.PreviousTag
		clusterUpdateState.Initiator = savedState.Initiator
		clusterUpdateState.StartedAt = savedState.StartedAt
		clusterUpdateState.CompletedAt = savedState.CompletedAt
		clusterUpdateState.Phase = savedState.Phase
		clusterUpdateState.ErrorBudget = savedState.ErrorBudget
		clusterUpdateState.Failures = savedState.Failures
		clusterUpdateState.ConsecFails = savedState.ConsecFails
		clusterUpdateState.CanaryCount = savedState.CanaryCount
		clusterUpdateState.CanarySoak = savedState.CanarySoak
		clusterUpdateState.AutoRollback = savedState.AutoRollback
		clusterUpdateState.Nodes = savedState.Nodes
		clusterUpdateState.mu.Unlock()
		clusterUpdateFile = savedPath
	})
}

// TestCL3_RunClusterUpdate_HaltsOnPreCancelledCtx is the regression
// guard for the CL-3 fix. With a context cancelled BEFORE the
// orchestrator runs, runClusterUpdate must:
//
//   1. Return within a tight bounded time (the boundary-1 check fires
//      before any node work happens).
//   2. Persist Phase="halted" and Active=false to disk via the defer.
//   3. Not attempt any updater-sidecar / gRPC / health-check work.
//
// Without the CL-3 ctx parameter the orchestrator would have ignored
// the cancelled context, called updateCPDirect, and tried to reach the
// updater on localhost:7123 — surfacing as a long delay and a
// connection-refused log line. With the fix, the boundary check at the
// top exits immediately.
func TestCL3_RunClusterUpdate_HaltsOnPreCancelledCtx(t *testing.T) {
	snapshotClusterUpdateState(t)
	snapshotGlobalClusterStore(t)

	dir := t.TempDir()
	clusterUpdateFile = filepath.Join(dir, "cluster_update.json")

	// Fresh cluster store with no nodes — even if the boundary-1
	// check were somehow skipped, ListNodes() returning empty would
	// fall through, but we explicitly do NOT want to rely on that.
	// The boundary-1 check is what the test pins.
	globalClusterStore = &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}

	// Set up a realistic in-flight state — the kind that startClusterUpdate
	// would have written to disk just before spawning the goroutine.
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = true
	clusterUpdateState.TargetTag = "v9.9.9-cl3-test"
	clusterUpdateState.Initiator = "cl3-test"
	clusterUpdateState.StartedAt = time.Now()
	clusterUpdateState.Phase = "updating_dps"
	clusterUpdateState.ErrorBudget = ErrorBudgetConfig{MaxConsecutive: 3, MaxPercent: 20}
	clusterUpdateState.Nodes = map[string]*NodeUpdateStatus{
		"dp-cl3-1": {NodeID: "dp-cl3-1", Status: "pending"},
	}
	clusterUpdateState.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel: boundary 1 must fire immediately

	done := make(chan struct{})
	go func() {
		runClusterUpdate(ctx)
		close(done)
	}()

	select {
	case <-done:
		// expected — boundary 1 caught the cancellation
	case <-time.After(2 * time.Second):
		t.Fatal("runClusterUpdate did not return within 2s on pre-cancelled ctx — boundary-1 check is missing or the orchestrator entered an inner loop without observing ctx")
	}

	// Read state from disk: the defer must have persisted the
	// halted/inactive terminal state.
	data, err := os.ReadFile(clusterUpdateFile)
	if err != nil {
		t.Fatalf("read %q: %v", clusterUpdateFile, err)
	}
	var disk ClusterUpdateState
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatalf("unmarshal cluster update state: %v", err)
	}
	if disk.Phase != "halted" {
		t.Errorf("on-disk Phase = %q; want %q (CL-3 abort-on-shutdown helper failed to mark halted)", disk.Phase, "halted")
	}
	if disk.Active {
		t.Errorf("on-disk Active = true; want false (runClusterUpdate's defer cleanup did not run)")
	}
	if disk.CompletedAt.IsZero() {
		t.Errorf("on-disk CompletedAt is zero; want non-zero (defer cleanup did not record completion time)")
	}
}

// TestCL3_AbortOnShutdown_HelperContract pins the small helper's two
// branches directly. Useful both as documentation of the contract and
// as a fast-feedback test that doesn't spin a goroutine.
func TestCL3_AbortOnShutdown_HelperContract(t *testing.T) {
	snapshotClusterUpdateState(t)

	dir := t.TempDir()
	clusterUpdateFile = filepath.Join(dir, "cluster_update.json")

	// Reset to a known starting Phase that is NOT "halted" so we can
	// observe the helper's mutation.
	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = true
	clusterUpdateState.Phase = "updating_dps"
	clusterUpdateState.mu.Unlock()

	// Branch 1: not cancelled — helper returns false, no mutation.
	if clusterUpdateAbortOnShutdown(context.Background()) {
		t.Fatal("clusterUpdateAbortOnShutdown returned true for an uncancelled context")
	}
	clusterUpdateState.mu.Lock()
	phase := clusterUpdateState.Phase
	clusterUpdateState.mu.Unlock()
	if phase != "updating_dps" {
		t.Errorf("Phase mutated on uncancelled ctx: got %q, want %q", phase, "updating_dps")
	}
	// File must not exist (nothing persisted).
	if _, err := os.Stat(clusterUpdateFile); !os.IsNotExist(err) {
		t.Errorf("clusterUpdateFile exists after no-op helper call (err=%v)", err)
	}

	// Branch 2: cancelled — helper returns true, Phase=halted, persisted.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !clusterUpdateAbortOnShutdown(ctx) {
		t.Fatal("clusterUpdateAbortOnShutdown returned false for a cancelled context")
	}
	clusterUpdateState.mu.Lock()
	phase = clusterUpdateState.Phase
	clusterUpdateState.mu.Unlock()
	if phase != "halted" {
		t.Errorf("Phase after cancelled-ctx helper: got %q, want %q", phase, "halted")
	}
	// File must now exist with Phase="halted" on disk.
	data, err := os.ReadFile(clusterUpdateFile)
	if err != nil {
		t.Fatalf("read %q: %v", clusterUpdateFile, err)
	}
	var disk ClusterUpdateState
	if err := json.Unmarshal(data, &disk); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if disk.Phase != "halted" {
		t.Errorf("on-disk Phase = %q; want %q", disk.Phase, "halted")
	}
}

// TestCL3_RunClusterUpdate_IsConcurrencySafe pins that the
// orchestrator can be spawned and observed via a done channel without
// deadlocking against its own mutex. Belt-and-suspenders against a
// future refactor that accidentally moves persist() inside a held
// lock at the boundary-check site.
func TestCL3_RunClusterUpdate_IsConcurrencySafe(t *testing.T) {
	snapshotClusterUpdateState(t)
	snapshotGlobalClusterStore(t)

	dir := t.TempDir()
	clusterUpdateFile = filepath.Join(dir, "cluster_update.json")

	globalClusterStore = &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}

	clusterUpdateState.mu.Lock()
	clusterUpdateState.Active = true
	clusterUpdateState.Phase = "updating_dps"
	clusterUpdateState.Nodes = map[string]*NodeUpdateStatus{}
	clusterUpdateState.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runClusterUpdate(ctx)
	}()

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		// pass
	case <-time.After(2 * time.Second):
		t.Fatal("runClusterUpdate goroutine did not finish within 2s under -race")
	}
}
