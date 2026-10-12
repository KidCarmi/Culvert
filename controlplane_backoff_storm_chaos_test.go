package main

// controlplane_backoff_storm_chaos_test.go — CHAOS-71 gates: chaos coverage for the DP→CP
// retry ladder (controlplane_client.go: dpBackoffDelay / backoff / pollConfig /
// failover) under a TOTAL Control-Plane-tier outage: every configured CP
// address is down at once (bad rollout, shared-dependency failure, network
// partition, node reboot).
//
// The failure mode these tests pin is a metastable retry storm. Three separate
// defects combined to keep the ladder pinned near its floor forever:
//
//  1. failover() cleared failCount on a connection that was never verified.
//     grpc.NewClient dials LAZILY, so connect() succeeds against a dead
//     address — meaning in any multi-CP (i.e. every HA) deployment the
//     rotation every dpFailoverThreshold failures zeroed the ladder before it
//     could ever reach the 60s ceiling. Steady state was a ~2s/8s oscillation
//     for the whole outage, with a fresh TCP+TLS handshake per rotation (which
//     also resets gRPC's own transport-level reconnect backoff).
//  2. failCount was incremented TWICE per failed poll (once in pollConfig,
//     once in backoff), so the single-CP ladder double-stepped to the ceiling
//     and the documented "failover after 3 consecutive failures" fired on the
//     second.
//  3. No jitter, so every DP in the fleet — all failing on the same outage,
//     all walking the same deterministic ladder — retried in lockstep and
//     landed on the CP together at the moment it was least able to serve
//     (cold start, snapshot rebuild).
//
// The contract under test: the ladder advances exactly one step per failed poll
// cycle, keeps escalating ACROSS failover rotations, and only a CP call that
// actually returned a reply clears it.

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// newStormClient builds a DP client whose CP calls always fail, with addrs
// configured so the failover rotation path is live. Registers cleanup for the
// CP-poll probe globals and for any gRPC ClientConn failover constructs.
func newStormClient(t *testing.T, addrs ...string) (*DataPlaneClient, *int) {
	t.Helper()
	swapCPPollState(t, false, time.Time{}) // never leak probe state
	calls := 0
	c := &DataPlaneClient{addrs: addrs}
	c.callForTest = func(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		calls++
		return nil, errors.New("control plane unavailable")
	}
	t.Cleanup(func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
	return c, &calls
}

// deadCtx is a already-cancelled context: backoff's select then takes the
// ctx.Done() arm immediately, so a test can drive many poll cycles without
// sleeping the real ladder. The RPC seam is callForTest, which ignores ctx.
func deadCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// TestDPBackoffDelay_EscalatesToCapAndStaysBounded pins the ladder shape:
// 2s, 4s, 8s, 16s, 32s, then the 60s ceiling — each within the jitter band,
// and never past the ceiling plus jitter no matter how long the outage runs.
func TestDPBackoffDelay_EscalatesToCapAndStaysBounded(t *testing.T) {
	bases := []time.Duration{
		2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, dpBackoffCap, dpBackoffCap,
	}
	for i, base := range bases {
		failCount := i + 1
		lo := time.Duration(float64(base) * (1 - dpBackoffJitterFrac))
		hi := time.Duration(float64(base) * (1 + dpBackoffJitterFrac))
		for draw := 0; draw < 200; draw++ {
			got := dpBackoffDelay(failCount)
			if got < lo || got > hi {
				t.Fatalf("dpBackoffDelay(%d) = %s, want within [%s, %s] (base %s)",
					failCount, got, lo, hi, base)
			}
		}
	}
	// A long outage must not overflow the shift or climb past the ceiling.
	maxDelay := time.Duration(float64(dpBackoffCap) * (1 + dpBackoffJitterFrac))
	for _, failCount := range []int{7, 32, 63, 64, 65, 1 << 20} {
		got := dpBackoffDelay(failCount)
		if got <= 0 || got > maxDelay {
			t.Fatalf("dpBackoffDelay(%d) = %s, want 0 < d <= %s", failCount, got, maxDelay)
		}
	}
	// Defensive: a zero/negative count must still yield a usable delay rather
	// than a zero-delay hot loop.
	for _, failCount := range []int{0, -1, -1 << 20} {
		if got := dpBackoffDelay(failCount); got <= 0 {
			t.Fatalf("dpBackoffDelay(%d) = %s, want a positive delay", failCount, got)
		}
	}
}

// TestDPBackoffDelay_DecorrelatesFleetRetries is the anti-stampede property:
// two nodes at the same ladder step must not retry at the same instant. With a
// deterministic ladder every DP that failed on the same outage retries
// together; the jitter draw is what breaks the phase lock.
func TestDPBackoffDelay_DecorrelatesFleetRetries(t *testing.T) {
	const fleet = 200
	seen := make(map[time.Duration]int, fleet)
	for i := 0; i < fleet; i++ {
		seen[dpBackoffDelay(6)]++ // every node pinned at the ceiling step
	}
	if len(seen) < fleet/2 {
		t.Fatalf("fleet of %d nodes drew only %d distinct retry instants — "+
			"retries are still phase-locked", fleet, len(seen))
	}
	// No single instant may hold a large share of the fleet.
	for d, n := range seen {
		if n > fleet/10 {
			t.Fatalf("%d/%d nodes share retry delay %s — stampede risk", n, fleet, d)
		}
	}
}

// TestPollConfig_LadderEscalatesAcrossFailoverRotations is the core regression.
// Two CP addresses, both down. Every rotation used to zero the ladder, so it
// oscillated near its floor forever and never reached the ceiling. The ladder
// must now advance exactly one step per failed poll cycle regardless of how
// many times the client rotates CP addresses.
func TestPollConfig_LadderEscalatesAcrossFailoverRotations(t *testing.T) {
	c, _ := newStormClient(t, "127.0.0.1:1", "127.0.0.1:2")
	ctx := deadCtx(t)

	const cycles = 10
	prev := 0
	for i := 1; i <= cycles; i++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("cycle %d: pollConfig reported success while every CP is down", i)
		}
		if c.failCount != i {
			t.Fatalf("cycle %d: failCount = %d, want %d — the ladder must advance "+
				"exactly one step per failed poll, including across rotations", i, c.failCount, i)
		}
		if c.failCount <= prev {
			t.Fatalf("cycle %d: ladder went backwards (%d after %d) — a rotation "+
				"must not clear the backoff", i, c.failCount, prev)
		}
		prev = c.failCount
	}
	// By cycle 10 the client must be sitting at the ceiling, not at the floor.
	if got := dpBackoffDelay(c.failCount); got < time.Duration(float64(dpBackoffCap)*(1-dpBackoffJitterFrac)) {
		t.Fatalf("after %d consecutive failures the delay is %s, want the %s ceiling — "+
			"the fleet is still hot-retrying a dead control plane", cycles, got, dpBackoffCap)
	}
}

// TestPollConfig_RotatesOnThresholdNotSooner pins the documented rotation
// cadence: one failover attempt every dpFailoverThreshold consecutive
// failures. The old double increment made it fire on the second failure.
func TestPollConfig_RotatesOnThresholdNotSooner(t *testing.T) {
	c, _ := newStormClient(t, "127.0.0.1:1", "127.0.0.1:2")
	ctx := deadCtx(t)

	for i := 1; i < dpFailoverThreshold; i++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("cycle %d: unexpected success", i)
		}
		if c.activeIdx != 0 {
			t.Fatalf("cycle %d: rotated to idx %d after only %d consecutive failures, "+
				"want no rotation before %d", i, c.activeIdx, i, dpFailoverThreshold)
		}
	}
	if _, ok := c.pollConfig(ctx); ok {
		t.Fatal("threshold cycle: unexpected success")
	}
	if c.activeIdx == 0 {
		t.Fatalf("no rotation after %d consecutive failures", dpFailoverThreshold)
	}
	// The rotation counter resets so the next rotation is another full
	// threshold away, while the ladder keeps climbing.
	if c.sinceFailover != 0 {
		t.Fatalf("sinceFailover = %d after a rotation, want 0", c.sinceFailover)
	}
	if c.failCount != dpFailoverThreshold {
		t.Fatalf("failCount = %d after %d failed polls, want %d",
			c.failCount, dpFailoverThreshold, dpFailoverThreshold)
	}
}

// TestPollConfig_SingleCPAdvancesOneStepPerPoll pins the single-CP ladder (no
// rotation path available). The old double increment reached the ceiling in
// three polls instead of six, so a transient CP blip cost up to a full minute
// of stale policy enforcement.
func TestPollConfig_SingleCPAdvancesOneStepPerPoll(t *testing.T) {
	c, calls := newStormClient(t, "127.0.0.1:1")
	ctx := deadCtx(t)

	for i := 1; i <= 6; i++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("cycle %d: unexpected success", i)
		}
		if c.failCount != i {
			t.Fatalf("cycle %d: failCount = %d, want %d", i, c.failCount, i)
		}
	}
	// One RPC per cycle: a single-address client must never attempt a rotation
	// (and so must never spend a second RPC on one).
	if *calls != 6 {
		t.Fatalf("made %d RPCs over 6 failed polls, want 6 — a single-address "+
			"client must not attempt failover", *calls)
	}
	if c.activeIdx != 0 {
		t.Fatalf("activeIdx = %d, want 0 — nothing to rotate to", c.activeIdx)
	}
}

// TestPollConfig_SuccessClearsLadder is the recovery path: once the CP answers,
// both the ladder and the rotation counter clear, so the next outage starts
// from the floor again rather than from a stale ceiling.
func TestPollConfig_SuccessClearsLadder(t *testing.T) {
	c, _ := newStormClient(t, "127.0.0.1:1", "127.0.0.1:2")
	ctx := deadCtx(t)

	for i := 0; i < 4; i++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("cycle %d: unexpected success", i)
		}
	}
	if c.failCount == 0 {
		t.Fatal("ladder did not advance during the outage")
	}

	c.callForTest = func(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{"version":1}`), nil
	}
	raw, ok := c.pollConfig(ctx)
	if !ok || len(raw) == 0 {
		t.Fatalf("pollConfig after CP recovery: ok=%v raw=%q, want a successful poll", ok, raw)
	}
	if c.failCount != 0 || c.sinceFailover != 0 {
		t.Fatalf("after a successful poll failCount=%d sinceFailover=%d, want 0/0",
			c.failCount, c.sinceFailover)
	}
}

// TestFailover_ConnectSucceedsAgainstDeadAddress documents the hazard the fix
// rests on: grpc.NewClient dials lazily, so connect() — and therefore
// failover() — reports success against an address with nothing listening.
// A successful failover is NOT evidence the CP is reachable, which is why it
// must not clear the retry ladder.
func TestFailover_ConnectSucceedsAgainstDeadAddress(t *testing.T) {
	c, _ := newStormClient(t, "127.0.0.1:1", "127.0.0.1:2")
	c.failCount = 5
	c.sinceFailover = 3

	if !c.failover() {
		t.Skip("grpc.NewClient refused a dead address; the lazy-dial hazard this " +
			"test documents no longer applies")
	}
	if c.activeIdx != 1 {
		t.Fatalf("activeIdx = %d after failover, want 1", c.activeIdx)
	}
	if c.failCount != 5 {
		t.Fatalf("failover cleared the ladder (failCount %d, want 5) — it only "+
			"proved grpc.NewClient accepted a target, not that the CP answered", c.failCount)
	}
}
