package main

// mcp_tooltrust_harness_test.go — deterministic regression coverage for the
// MCP tool-trust TEST HARNESS (2F-B correction round 2, blocker 3). The root
// -race gate reported a DATA RACE between TestShadowSoak's coordinator clock
// swap and the periodic reconcile loop leaked by an earlier gap environment:
//
//   Write  shadow_soak_test.go   soakSwapToolTrustClock (nowFn, no lock)
//   Read   mcp_tooltrust.go:80   (*mcpToolTrustCoordinator).now (under RLock)
//   by a goroutine started from shadow_exit_gap_test.go newGapEnv →
//   initMCPToolTrust → startToolTrustReconcileLoop, never cancelled.
//
// Two ownership rules, each pinned deterministically (channels only, no
// sleeps): the coordinator clock is swapped ONLY under the coordinator's own
// mutex, and a test environment's cleanup cancels AND joins the reconcile
// loop it started. Under -race the first test fails on the rejected
// candidate 16858885 (the swap helper there is the verbatim unsynchronized
// assignment); the second fails there because the loop outlives the
// environment. Neither touches MCP production behavior.

import (
	"testing"
	"time"
)

func TestMCPHarness_ToolTrustClockSwapIsOwnedByCoordinator(t *testing.T) {
	resetMCPToolTrustForTest()
	t.Cleanup(resetMCPToolTrustForTest)
	// A concurrent reader — exactly what the reconcile loop does — with no
	// happens-before relation to the harness swap. The race detector reports
	// the conflict whichever access lands first.
	read := make(chan struct{})
	go func() {
		defer close(read)
		_ = mcpToolTrust.now()
	}()
	t0 := time.Unix(1_700_000_000, 0)
	restore := soakSwapToolTrustClock(func() time.Time { return t0 })
	<-read
	if got := mcpToolTrust.now(); !got.Equal(t0) {
		t.Fatalf("swapped clock must be observed: %v", got)
	}
	restore()
	if got := mcpToolTrust.now(); got.Equal(t0) {
		t.Fatal("restore must reinstate the previous clock")
	}
}

func TestMCPHarness_GapEnvCleanupStopsReconcileLoop(t *testing.T) {
	t.Run("env", func(t *testing.T) {
		var hits int64
		resetShadowGlobalsForRun(t)
		env := newGapEnv(t, &hits, controlledInventoryJSON, gwPolicyDoc(1, allowDiscoveryRule+","+allowEchoRule), nil)
		if env == nil {
			t.Fatal("gap env")
		}
		if !toolTrustReconcileLoopRunning() {
			t.Fatal("precondition: the environment started a reconcile loop")
		}
	})
	// Every cleanup of the environment has run: the loop it started must have
	// been cancelled and joined, not left ticking against the next test's
	// coordinator state.
	if toolTrustReconcileLoopRunning() {
		t.Fatal("the reconcile loop started by the environment outlived its cleanup (leaked goroutine)")
	}
}
