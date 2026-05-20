package main

// cluster_store_flush_hook_test.go — CL-2 regression coverage for the
// `cluster-store-flush` late-phase shutdown hook.
//
// Background
// ==========
// roadmap/CLUSTER-RUNTIME-DISCOVERY.md §13 CL-2 flagged that
// globalClusterStore was not flushed at shutdown. UpdateNodeSeen
// (enrollment.go:360–376) only persists every 10th heartbeat
// (`shouldSave := cs.heartbeatCount%10 == 0`); checkHeartbeats
// (enrollment.go:582–598) only saves when liveness/GC actually
// changed something. In the gap between throttle boundaries — and
// for any in-memory mutation that didn't trigger a save — a graceful
// shutdown loses the freshest LastSeen/Status data.
//
// Fix (this PR)
// =============
// main.go registers a `cluster-store-flush` hook first in the late
// shutdown phase (order shutdownOrderClusterStoreFlush = 55, just
// above the early/late boundary of 50). At that point the gRPC
// server has already stopped (no incoming heartbeats) and
// appLifecycleCancel has fired (heartbeat monitor stopped), so
// `globalClusterStore.Save()` races with no concurrent mutator.
// Save() uses the existing RLock + atomicWriteFile path; no new
// persistence framework, no change to Save semantics.
//
// What this file asserts
// ======================
//   1. Round-trip: a mutation made directly under cs.mu.Lock without
//      triggering Save (simulating the throttle gap) IS persisted to
//      disk after the late-phase registry runs.
//   2. The flush hook tolerates a nil globalClusterStore without
//      panicking (regression guard for the explicit nil-check in the
//      hook body).
//
// Pattern note
// ============
// This file follows the audit_close_hook_test.go pattern (P3.3 /
// S7): snapshot all late-shutdown globals so the registry can run
// in a test without nuking unrelated state, then exercise just the
// hook under test via the registry. The new helper
// snapshotGlobalClusterStore extends snapshotLateShutdownGlobals
// for the one global that file does not yet cover.
//
// No sleeps, no retries, no reliance on heartbeat timing — the
// mutation is whitebox under the same mutex Save acquires, so the
// before/after state is fully deterministic.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// snapshotGlobalClusterStore captures and restores the package-global
// globalClusterStore pointer for the duration of the test. PR #241 /
// #245 / #251 whitebox snapshot idiom.
func snapshotGlobalClusterStore(t *testing.T) {
	t.Helper()
	orig := globalClusterStore
	t.Cleanup(func() {
		globalClusterStore = orig
	})
}

// TestClusterStoreFlushHook_PersistsThrottledMutation proves the
// cluster-store-flush late hook closes the heartbeat-throttle window.
// The setup deliberately mirrors the CL-2 failure mode:
//
//  1. RegisterNode (writes initial state via Save).
//  2. Direct whitebox mutation under cs.mu.Lock — same lock Save would
//     hold but WITHOUT calling Save (this is exactly what UpdateNodeSeen
//     does between throttle boundaries: enrollment.go:362–369 mutates
//     LastSeen + Status under the lock, then only calls Save every 10th
//     tick).
//  3. Read the file from disk: assert the throttled mutation is NOT yet
//     present (proves the test setup actually simulates the bug).
//  4. Run the late registry. Other late hooks no-op because
//     snapshotLateShutdownGlobals zeroed their globals.
//  5. Read the file again: the mutation IS present.
//
// This is the property the CL-2 fix guarantees, and the test fails if
// the hook is removed from the late registry.
func TestClusterStoreFlushHook_PersistsThrottledMutation(t *testing.T) {
	snapshotLateShutdownGlobals(t)
	snapshotGlobalClusterStore(t)

	dir := t.TempDir()
	path := filepath.Join(dir, "cluster.json")

	cs := &ClusterStore{
		st: ClusterState{
			Nodes:   make(map[string]*EnrolledNode),
			Tokens:  make(map[string]*EnrollToken),
			Revoked: []RevokedCert{},
		},
	}
	if err := cs.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	globalClusterStore = cs

	// Step 1: seed the store via the production API. RegisterNode calls
	// Save under the hood; the file on disk now contains the node with
	// its initial (zero-value) LastSeen.
	node := &EnrolledNode{
		NodeID:     "dp-cl2-test",
		Status:     "connected",
		CertSerial: "cl2-serial-1",
	}
	cs.RegisterNode(node)

	// A discriminator timestamp we'll write into LastSeen under the
	// throttle-gap pattern. Choose a value distinct from the zero time
	// (RegisterNode does NOT set LastSeen — it's only set by
	// UpdateNodeSeen) so a missed flush would show as the JSON zero
	// time in the on-disk payload.
	marker := time.Date(2025, 7, 4, 12, 34, 56, 0, time.UTC)

	// Step 2: mutate directly under the same lock Save would acquire,
	// but DO NOT call Save. This is the exact pattern from
	// UpdateNodeSeen on the 9/10 ticks where shouldSave is false.
	cs.mu.Lock()
	cs.st.Nodes["dp-cl2-test"].LastSeen = marker
	cs.mu.Unlock()

	// Step 3: confirm the throttled mutation has NOT reached disk yet.
	// This proves the test setup actually simulates the CL-2 bug — if
	// some other code path persisted before the hook ran, the test
	// would be vacuous.
	got := readNodeLastSeen(t, path, "dp-cl2-test")
	if !got.IsZero() {
		t.Fatalf("pre-flush: LastSeen on disk = %v; want zero (RegisterNode does not set LastSeen, and the in-memory mutation has not been Save()d yet)", got)
	}

	// Step 4: run the late shutdown registry. The cluster-store-flush
	// hook (order 55) executes first; the remaining hooks no-op via
	// snapshotLateShutdownGlobals.
	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll: %v", err)
	}

	// Step 5: the throttled mutation must now be on disk. If the hook
	// were removed (or scheduled after a hook that closes the file
	// system, etc.), this assertion fails.
	got = readNodeLastSeen(t, path, "dp-cl2-test")
	if !got.Equal(marker) {
		t.Fatalf("post-flush: LastSeen on disk = %v; want %v (cluster-store-flush hook failed to persist the in-memory mutation)", got, marker)
	}
}

// TestClusterStoreFlushHook_NilStoreIsNoOp verifies the hook is safe
// when globalClusterStore happens to be nil (only achievable via test
// swap — production always initialises it — but the hook's explicit
// nil-check is the documented contract and is regression-tested here).
func TestClusterStoreFlushHook_NilStoreIsNoOp(t *testing.T) {
	snapshotLateShutdownGlobals(t)
	snapshotGlobalClusterStore(t)

	globalClusterStore = nil

	var late shutdownRegistry
	registerLateShutdownHooks(&late, &startupState{}, testInertHTTPServer())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := late.RunAll(ctx); err != nil {
		t.Fatalf("late.RunAll with nil globalClusterStore: %v", err)
	}
}

// readNodeLastSeen unmarshals the on-disk cluster state and returns the
// LastSeen value for nodeID. Helper kept local to this test file
// because no other test needs disk-side inspection of LastSeen.
func readNodeLastSeen(t *testing.T, path, nodeID string) time.Time {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	var st ClusterState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("unmarshal %q: %v", path, err)
	}
	n, ok := st.Nodes[nodeID]
	if !ok {
		t.Fatalf("node %q missing from on-disk state (payload: %s)", nodeID, string(data))
	}
	return n.LastSeen
}
