package main

import (
	"strings"
	"testing"
	"time"
)

// trippedPooledFake returns a pooled fake whose breaker has tripped open with
// the given reset timeout (time.Hour keeps it unavailable; a nanosecond lets
// Available admit a recovery probe while State still reads open).
func trippedPooledFake(t *testing.T, name string, reset time.Duration) *cdrPooledClient {
	t.Helper()
	pc, stop := newPooledFake(t, name, &fakeSluice{})
	t.Cleanup(stop)
	pc.Breaker = newCDRCircuitBreaker(cdrBreakerConfig{FailureThreshold: 1, ResetTimeout: reset})
	pc.Breaker.OnFailure(cdrReserveForTest(pc.Breaker))
	if pc.Breaker.State() != cbStateOpen {
		t.Fatalf("breaker state = %s, want open", breakerStateName(pc.Breaker.State()))
	}
	return pc
}

// A pool with one tripped and one serving instance used to read
// enabled-healthy because the row only asked whether ANY instance can scan.
// It must now warn about the reduced capacity, without touching breaker state.
func TestCheckCDR_PartiallyTrippedPoolReportsReduced(t *testing.T) {
	down := trippedPooledFake(t, "down", time.Hour)
	up, stopUp := newPooledFake(t, "up", &fakeSluice{})
	t.Cleanup(stopUp)
	withTempPool(t, down, up)
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "closed", DefaultProfile: "default"})
	staleBefore := down.Breaker.staleProbes.Load()

	got := checkCDR()

	if got.Status != diagWarn || !strings.HasPrefix(got.Message, "enabled-reduced") {
		t.Fatalf("checkCDR() = %s %q, want WARN enabled-reduced", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "1 of 2") {
		t.Errorf("message %q must state 1 of 2 instances", got.Message)
	}
	if got.OperatorAction == "" {
		t.Error("reduced-capacity row must carry an operator action")
	}
	if strings.Contains(got.Message, "down") {
		t.Errorf("message %q must not name instances (viewer-visible row)", got.Message)
	}
	if down.Breaker.State() != cbStateOpen || up.Breaker.State() != cbStateClosed {
		t.Errorf("diagnostics read changed breaker state: down=%s up=%s",
			breakerStateName(down.Breaker.State()), breakerStateName(up.Breaker.State()))
	}
	if n := down.Breaker.staleProbes.Load(); n != staleBefore {
		t.Errorf("staleProbes = %d, want %d: the diagnostics read must not reserve a probe", n, staleBefore)
	}
}

// Every breaker tripped but past its reset timeout: the pool is "available"
// only for recovery probes. That is not healthy, and not yet dark.
func TestCheckCDR_AllTrippedAwaitingProbeReportsRecovering(t *testing.T) {
	pc := trippedPooledFake(t, "probing", time.Nanosecond)
	withTempPool(t, pc)
	withActiveCDRConfig(t, CDRConfig{Enabled: true, FailMode: "open", DefaultProfile: "default"})
	time.Sleep(time.Millisecond) // let the 1ns reset timeout elapse on the monotonic clock
	if !pc.Breaker.Available() {
		t.Fatal("precondition: breaker past its reset timeout must be Available")
	}

	got := checkCDR()

	if got.Status != diagWarn || !strings.HasPrefix(got.Message, "enabled-recovering") {
		t.Fatalf("checkCDR() = %s %q, want WARN enabled-recovering", got.Status, got.Message)
	}
	if pc.Breaker.State() != cbStateOpen {
		t.Errorf("breaker state = %s after the diagnostics read, want open (no probe taken)", breakerStateName(pc.Breaker.State()))
	}
}
