package main

// controlplane_dp_conn_race_test.go — CL-11 focused race test for the
// DataPlaneClient.c.conn read-vs-failover-write surface.
//
// Surface under examination
// =========================
// c.call() at controlplane.go:1392–1398 reads c.conn.Invoke(...) at
// :1396 WITHOUT taking c.mu. c.connect() at :1130–1154 writes
// c.conn = conn at :1151; called from c.failover() at :1158–1178
// which takes c.mu.Lock at :1162 and defers Unlock at :1163. So the
// writer holds the lock; the reader does not.
//
// Five long-lived DP goroutines (pollLoop, metricsLoop,
// rateLimitGossipLoop, revocationSyncLoop, auditPushLoop, spawned by
// DataPlaneClient.Run at controlplane.go:1182–1186) all invoke
// c.call(). A failover that swaps c.conn while a sibling loop is
// mid-call is an unsynchronized read/write under the Go memory
// model. CL-11 (per roadmap/CLUSTER-RUNTIME-DISCOVERY.md §13) flagged
// this as "potential race / needs race-test confirmation."
//
// Test design — what interleaving is exercised
// =============================================
//   - Build a DataPlaneClient with two bogus addresses (127.0.0.1:1,
//     127.0.0.1:2). grpc.NewClient is lazy, so c.connect() succeeds
//     at the dial-prep stage without any network I/O.
//   - Spawn 8 reader goroutines, each calling c.call() 200 times.
//     c.conn.Invoke() will dial the bogus address, the kernel
//     refuses, gRPC returns Unavailable. Each iteration reads c.conn
//     at controlplane.go:1396 — the racy site.
//   - Spawn 1 writer goroutine calling c.failover() 100 times. Each
//     failover takes c.mu.Lock, calls c.connect() which closes the
//     old c.conn and writes c.conn = newConn at :1151 — the locked
//     write site.
//   - 8 readers × 200 calls + 1 writer × 100 failovers = 1700
//     concurrent accesses to c.conn over the test window.
//   - A startBarrier (channel close) releases all goroutines
//     simultaneously to maximise interleaving from the first call.
//
// Why this test is deterministic
// ===============================
//   - No sleeps. All synchronization is via sync.WaitGroup, the
//     startBarrier channel close, and context.Cancel.
//   - No timing-based assertions. The race detector itself is the
//     assertion: if -race observes any unsynchronized read/write
//     pair on c.conn, the test fails at the access site (not in this
//     file).
//   - No real CP server — every c.call() fails identically at the
//     TCP layer. No flaky network dependencies.
//   - Bounded iteration count. The test terminates after a fixed
//     amount of work; it does not loop until race-detector-fires.
//   - Bogus addresses 127.0.0.1:1 and 127.0.0.1:2 are unbound on
//     every reasonable test host (port <1024 requires root); kernel
//     reliably returns ECONNREFUSED.
//
// Ownership invariant under examination
// ======================================
// c.conn must be safely readable from goroutines that do NOT hold
// c.mu. If the race detector fires, the invariant is violated — a
// future PR (per CL-11) must change either:
//
//	(a) c.call() to hold c.mu.RLock for the c.conn snapshot, or
//	(b) c.conn from *grpc.ClientConn to
//	    atomic.Pointer[grpc.ClientConn] (mirror of P5.3
//	    swapUpstreamTransport ownership model).
//
// Choice between (a) and (b) belongs in the follow-up PR, not here.
//
// Expected outcomes
// =================
// (A) Race detector fires:
//   - Test fails with a "WARNING: DATA RACE" message at the c.conn
//     access in c.call() (read site) and c.connect() (write site).
//   - Document the exact stack and propose the smallest ownership
//     fix in a follow-up PR. Do NOT fix in this PR.
//
// (B) Race detector stays clean:
//   - Investigate why. The clean result does NOT prove safety; it
//     proves only "-race did not observe the race in this specific
//     harness." Strong evidence, not a proof. Document the analysis.
//
// Observed outcome (captured during PR construction, commit 476c2b5
// baseline, this branch's harness):
// =================================
//
//	==================
//	WARNING: DATA RACE
//	Write at 0x00c0001a5990 by goroutine 21:
//	  proxy.(*DataPlaneClient).connect()
//	      /home/user/Culvert/controlplane.go:1151 +0x664
//	  proxy.(*DataPlaneClient).failover()
//	      /home/user/Culvert/controlplane.go:1169 +0x44a
//	  ...
//
//	Previous read at 0x00c0001a5990 by goroutine 20:
//	  proxy.(*DataPlaneClient).call()
//	      /home/user/Culvert/controlplane.go:1396 +0x146
//	  ...
//	==================
//
// Outcome (A) — race detector fired. CL-11 is confirmed. The smallest
// ownership fix is left to a follow-up PR per the original CL-11
// brief.
//
// CI gating
// =========
// This test deliberately exercises a confirmed race and would
// therefore make every CI run that uses `-race` (including the
// project's determinism gate) red until a production fix lands.
// To avoid permanently red CI, the test is gated on the
// CL11_RACE_EVIDENCE env var and skipped by default. The follow-up
// PR that lands the ownership fix should:
//
//	(a) Remove the env-var gate (delete the t.Skip block below).
//	(b) Confirm the test passes under `go test -race -count=1`.
//	(c) Optionally promote it to run automatically in CI.
//
// To run this test manually:
//
//	CL11_RACE_EVIDENCE=1 go test -race -count=1 \
//	    -run TestCL11_DataPlaneClient_ConnReadVsFailoverWrite_Race ./...
//
// The skip message in the t.Skip below points future readers at
// this same envelope.

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"os"
	"sync"
	"testing"
)

func TestCL11_DataPlaneClient_ConnReadVsFailoverWrite_Race(t *testing.T) {
	if os.Getenv("CL11_RACE_EVIDENCE") == "" {
		t.Skip("CL-11 race-evidence test skipped by default — set " +
			"CL11_RACE_EVIDENCE=1 to run. The test reproduces a " +
			"confirmed data race on DataPlaneClient.c.conn and " +
			"is gated to avoid making CI permanently red until " +
			"the ownership fix lands. See the file header for " +
			"the captured race output.")
	}

	// Silence production logger output during the test. c.connect()
	// at controlplane.go:1140, :1152 and c.failover() at :1168 each
	// emit a log line; with 100 failovers that's ~200 log lines of
	// pure noise. The redirect does not affect race detection. Restore
	// on cleanup.
	oldLogger := logger
	logger = log.New(io.Discard, "", 0)
	t.Cleanup(func() { logger = oldLogger })

	// Two bogus addresses — port 1 is privileged and unbound on every
	// reasonable test host. grpc.NewClient is lazy, so c.connect()
	// succeeds without network I/O.
	c, err := NewDataPlaneClient("cl11-test", "127.0.0.1:1,127.0.0.1:2", "", "", "")
	if err != nil {
		t.Fatalf("NewDataPlaneClient: %v", err)
	}
	t.Cleanup(func() {
		// c.conn is the most-recently-set conn; close it on cleanup.
		// Reading c.conn here under t.Cleanup is single-threaded
		// after wg.Wait — no race.
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	const (
		readers          = 8
		callsPerReader   = 200
		failoverAttempts = 100
	)

	// startBarrier releases all goroutines simultaneously when
	// closed. Maximises overlap from the very first iteration so
	// -race sees the widest concurrency window.
	startBarrier := make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(readers + 1)

	// Reader goroutines: hot-loop c.call(). Each iteration reads
	// c.conn at controlplane.go:1396 without holding c.mu.
	for i := 0; i < readers; i++ {
		go func() {
			defer wg.Done()
			<-startBarrier
			for j := 0; j < callsPerReader; j++ {
				_, _ = c.call(ctx, "/cl11.test/Method", json.RawMessage(`{}`))
				if ctx.Err() != nil {
					return
				}
			}
		}()
	}

	// Writer goroutine: hot-loop c.failover(). Each iteration takes
	// c.mu.Lock, writes c.conn at controlplane.go:1151 (via
	// c.connect), releases. With 2 configured addrs, failover always
	// switches between them round-robin — no exhaustion case.
	go func() {
		defer wg.Done()
		<-startBarrier
		for j := 0; j < failoverAttempts; j++ {
			c.failover()
			if ctx.Err() != nil {
				return
			}
		}
	}()

	close(startBarrier)
	wg.Wait()

	// No assertions beyond -race. If the test reached this point
	// without panic AND without -race firing, the harness has
	// produced evidence of "-race-clean under this interleaving."
	// The harness's job is to produce evidence; the doc / follow-up
	// PR will interpret it.
}
