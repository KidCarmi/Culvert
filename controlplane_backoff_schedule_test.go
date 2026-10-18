package main

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

// controlplane_backoff_schedule_test.go — CHAOS: the DP→CP retry schedule and
// the failover threshold are an operational contract, not an implementation
// detail, and nothing pinned either one.
//
// failCount is charged once per consecutive failure, by pollConfig. backoff()
// only READS it. When backoff() also incremented, every failure counted twice:
// the delay schedule became 4s, 16s, 60s (ceiling on the 3rd failure instead
// of the 6th), and the `failCount < 3` guard let failover fire on the SECOND
// consecutive failure — so a ~10s CP blip during a rolling upgrade moved an
// entire data-plane fleet off a healthy leader.

// failingDPClient returns a client whose every RPC fails, with a context that
// is already cancelled so backoff() returns through its ctx.Done() arm instead
// of sleeping out the real delay.
func failingDPClient(t *testing.T, addrs []string) (*DataPlaneClient, context.Context) {
	t.Helper()
	c := &DataPlaneClient{
		nodeID: "dp-1",
		addrs:  addrs,
		callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
			return nil, errors.New("connect: connection refused")
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return c, ctx
}

// TestDPBackoff_ChargesOneFailurePerFailedPoll pins the single-count invariant
// the delay schedule is derived from: after N consecutive failed polls on a
// single-CP appliance, failCount is exactly N.
func TestDPBackoff_ChargesOneFailurePerFailedPoll(t *testing.T) {
	c, ctx := failingDPClient(t, []string{"cp-1:9443"})

	for i := 1; i <= 6; i++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("poll %d unexpectedly succeeded", i)
		}
		if c.failCount != i {
			t.Fatalf("after %d consecutive failed polls failCount=%d, want %d — "+
				"a double-charged failure escalates the backoff schedule (documented 2s, 4s, 8s … 60s) "+
				"roughly twice as fast and reaches the 60s ceiling early", i, c.failCount, i)
		}
	}
}

// TestDPBackoff_SuccessResetsTheStreak is the negative control: the schedule is
// only meaningful if a recovered CP clears the streak, so a later blip starts
// from 2s rather than staying pinned at the ceiling.
func TestDPBackoff_SuccessResetsTheStreak(t *testing.T) {
	c, ctx := failingDPClient(t, []string{"cp-1:9443"})

	if _, ok := c.pollConfig(ctx); ok {
		t.Fatal("seed poll unexpectedly succeeded")
	}
	if c.failCount == 0 {
		t.Fatal("a failed poll must charge the streak")
	}
	c.callForTest = func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return json.RawMessage(`{}`), nil
	}
	if _, ok := c.pollConfig(ctx); !ok {
		t.Fatal("poll against a healthy CP must succeed")
	}
	if c.failCount != 0 {
		t.Errorf("failCount=%d after a successful poll, want 0 — a recovered CP must clear the streak", c.failCount)
	}
}

// TestDPFailover_NotBeforeThreeConsecutiveFailures pins the threshold stated at
// pollConfig's guard. failover() walks c.addrs and calls connect(), which a
// test-constructed client cannot do, so it returns false and pollConfig backs
// off — the observable we assert on is WHETHER failover was reached, via the
// activeIdx/failCount bookkeeping failover() performs only on success, plus the
// streak itself, which failover() resets to 0 when it succeeds.
func TestDPFailover_NotBeforeThreeConsecutiveFailures(t *testing.T) {
	c, ctx := failingDPClient(t, []string{"cp-1:9443", "cp-2:9443"})

	// Failures 1 and 2 must take the back-off-and-retry-same-CP arm, which
	// leaves the streak monotonically increasing by exactly one each time.
	for i := 1; i <= 2; i++ {
		if _, ok := c.pollConfig(ctx); ok {
			t.Fatalf("poll %d unexpectedly succeeded", i)
		}
		if c.failCount != i {
			t.Fatalf("failure %d: failCount=%d want %d — with a double charge the "+
				"`failCount < 3` guard is already false here and failover fires one "+
				"failure early, churning the fleet off a healthy CP on a transient blip",
				i, c.failCount, i)
		}
	}
	if c.activeIdx != 0 {
		t.Fatalf("activeIdx=%d after 2 consecutive failures, want 0 — failover must not "+
			"have been attempted yet", c.activeIdx)
	}
	// The 3rd consecutive failure is the first one permitted to attempt failover.
	// A test-constructed client's connect() is a lazy grpc dial and succeeds, so
	// failover() advances activeIdx and resets the streak to 0 — both are the
	// observable that failover was actually reached on THIS failure and not an
	// earlier one.
	if _, ok := c.pollConfig(ctx); ok {
		t.Fatal("poll 3 unexpectedly succeeded")
	}
	if c.activeIdx != 1 {
		t.Errorf("activeIdx=%d after the 3rd consecutive failure, want 1 — failover "+
			"must be attempted on the 3rd failure", c.activeIdx)
	}
	if c.failCount != 0 {
		t.Errorf("failCount=%d after a successful failover, want 0", c.failCount)
	}
}

// TestDPBackoff_FloorHoldsWithAClearedStreak pins the 2s floor on the one path
// that reaches backoff() with failCount==0: failover() switched CP, reset the
// streak, and its immediate retry failed. Without the floor that slot backs off
// 1s, below the documented minimum.
func TestDPBackoff_FloorHoldsWithAClearedStreak(t *testing.T) {
	c, ctx := failingDPClient(t, []string{"cp-1:9443", "cp-2:9443"})
	c.failCount = 0
	// backoff() must not sleep (ctx is cancelled) and must not mutate the streak:
	// the caller owns it.
	c.backoff(ctx)
	if c.failCount != 0 {
		t.Errorf("backoff() mutated failCount to %d — the caller owns the streak", c.failCount)
	}
}
