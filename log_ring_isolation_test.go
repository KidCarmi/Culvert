package main

import (
	"net"
	"testing"
	"time"
)

// The ring-isolation gap the Deep determinism job hit (seed
// 1791014615135233342): a hijacked tunnel left behind by an earlier test
// writes its close accounting into the request log AFTER the next test has
// swapped in its isolated ring. isolateLogRing must wait for in-flight
// tunnels before swapping. This reproduces the race deterministically: a
// registered tunnel whose accounting lands 50 ms after isolation begins,
// in the production order (log entry first, registry release second).
func TestIsolateLogRing_WaitsForInFlightTunnelAccounting(t *testing.T) {
	resetTunnelDrainRegistryForTest()
	t.Cleanup(resetTunnelDrainRegistryForTest)
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	release := registerDrainableTunnel(tunnelClassConnectBypass, c1, c2)
	if getActiveConns() < 1 {
		t.Fatalf("fixture: tunnel not registered (activeConns=%d)", getActiveConns())
	}
	landed := make(chan struct{})
	go func() {
		defer close(landed)
		time.Sleep(50 * time.Millisecond)
		logAdd(LogEntry{TS: 1, Method: "CONNECT", Host: "straggler.example", Status: "TUNNEL_CLOSED", Level: "INFO"})
		release()
	}()
	isolateLogRing(t)
	<-landed
	if n := len(logGet()); n != 0 {
		t.Fatalf("a straggling tunnel's accounting landed in the isolated ring (%d entries) — isolateLogRing swapped before in-flight tunnels drained", n)
	}
}

// Control: with nothing in flight the helper must not wait at all — a fixed
// sleep would pass the gate above while slowing every ring-isolated test.
func TestIsolateLogRing_DoesNotWaitWhenQuiescent(t *testing.T) {
	resetTunnelDrainRegistryForTest()
	t.Cleanup(resetTunnelDrainRegistryForTest)
	start := time.Now()
	isolateLogRing(t)
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Fatalf("isolateLogRing waited %s with no tunnel in flight", d)
	}
	logAdd(LogEntry{TS: 2, Method: "GET", Host: "own.example", Status: "OK", Level: "INFO"})
	if n := len(logGet()); n != 1 {
		t.Fatalf("the isolated ring must still record this test's own entries, got %d", n)
	}
}
