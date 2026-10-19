package main

import (
	"fmt"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Gates for isolateLogRing (events_livefeed_test.go). The ring-isolation gap
// the Deep determinism job hit (seed 1791014615135233342): a hijacked tunnel
// left behind by an earlier test writes its close accounting into the request
// log AFTER the next test swapped in its isolated ring. None of these gates
// sleeps or measures wall time: every ordering is established by an explicit
// signal, and the clock is a seam.

// straggler is the production-shaped late write: accounting first, registry
// release second (handleTunnelBypass records TUNNEL_CLOSED, then its deferred
// registerDrainableTunnel release runs).
func ringTestStraggler(release func()) {
	logAdd(LogEntry{TS: 1, Method: "CONNECT", Host: "straggler.example", Status: "TUNNEL_CLOSED", Level: "INFO"})
	release()
}

func ringTestRegisterTunnel(t *testing.T) (release func()) {
	t.Helper()
	resetTunnelDrainRegistryForTest()
	t.Cleanup(resetTunnelDrainRegistryForTest)
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })
	release = registerDrainableTunnel(tunnelClassConnectBypass, c1, c2)
	if getActiveConns() < 1 {
		t.Fatalf("fixture: tunnel not registered (activeConns=%d)", getActiveConns())
	}
	return release
}

func setRingQuiescenceProbe(t *testing.T, fn func()) {
	t.Helper()
	prev := ringQuiescenceProbe
	ringQuiescenceProbe = fn
	t.Cleanup(func() { ringQuiescenceProbe = prev })
}

// The straggler is released only once the helper has PROVABLY started
// waiting (the probe), or — against a helper that does not wait — once it
// has already returned. Either way the write happens at the one moment that
// distinguishes the two shapes, with no timing involved.
func TestIsolateLogRing_WaitsForInFlightTunnelAccounting(t *testing.T) {
	release := ringTestRegisterTunnel(t)
	waiting := make(chan struct{})
	var once sync.Once
	setRingQuiescenceProbe(t, func() { once.Do(func() { close(waiting) }) })
	returned := make(chan struct{})
	landed := make(chan struct{})
	go func() {
		defer close(landed)
		select {
		case <-waiting:
		case <-returned:
		}
		ringTestStraggler(release)
	}()
	isolateLogRing(t)
	close(returned)
	<-landed
	if n := len(logGet()); n != 0 {
		t.Fatalf("a straggling tunnel's accounting landed in the isolated ring (%d entries) — isolateLogRing swapped before in-flight tunnels drained", n)
	}
}

// fatalRecordingTB lets a gate observe isolateLogRing's refusal without
// failing the gate itself: Fatalf records and stops the goroutine exactly as
// testing.T would, Cleanup is counted (a registered cleanup means the ring
// WAS swapped).
type fatalRecordingTB struct {
	testing.TB
	mu       sync.Mutex
	fatal    string
	cleanups int
}

func (f *fatalRecordingTB) Helper() {}

func (f *fatalRecordingTB) Fatalf(format string, args ...any) {
	f.mu.Lock()
	f.fatal = fmt.Sprintf(format, args...)
	f.mu.Unlock()
	runtime.Goexit()
}

func (f *fatalRecordingTB) Cleanup(fn func()) {
	f.mu.Lock()
	f.cleanups++
	f.mu.Unlock()
	f.TB.Cleanup(fn)
}

// A tunnel that never drains must make the helper FAIL BEFORE SWAPPING. The
// deadline is reached on a fake clock that the injected sleep advances, so
// the gate is instant and independent of runner speed.
func TestIsolateLogRing_FailsBeforeSwappingWhenTunnelsDoNotDrain(t *testing.T) {
	isolateLogRing(t) // a clean ring of this test's own, taken while nothing is in flight
	logAdd(LogEntry{TS: 3, Method: "GET", Host: "marker.example", Status: "OK", Level: "INFO"})
	release := ringTestRegisterTunnel(t)
	defer release()

	fake := time.Unix(1_700_000_000, 0)
	prevNow, prevSleep := ringQuiescenceNow, ringQuiescenceSleep
	ringQuiescenceNow = func() time.Time { return fake }
	ringQuiescenceSleep = func(d time.Duration) { fake = fake.Add(d) }
	t.Cleanup(func() { ringQuiescenceNow, ringQuiescenceSleep = prevNow, prevSleep })

	ftb := &fatalRecordingTB{TB: t}
	done := make(chan struct{})
	go func() {
		defer close(done)
		isolateLogRing(ftb)
	}()
	<-done
	ftb.mu.Lock()
	fatal, cleanups := ftb.fatal, ftb.cleanups
	ftb.mu.Unlock()
	if fatal == "" {
		t.Fatal("isolateLogRing must fail when hijacked tunnels do not drain within the bound")
	}
	if cleanups != 0 {
		t.Fatalf("isolateLogRing registered %d cleanup(s) — it swapped the ring before failing", cleanups)
	}
	if got := logGet(); len(got) != 1 || got[0].Host != "marker.example" {
		t.Fatalf("the ring must be left exactly as it was (the marker entry only), got %d entries", len(got))
	}
}

// Control: with nothing in flight the helper must return on its first check —
// no probe, no sleep — and the isolated ring must still record the test's own
// entries. A helper that always waited a fixed interval would pass the two
// gates above; this one fails it, without measuring time.
func TestIsolateLogRing_DoesNotWaitWhenQuiescent(t *testing.T) {
	resetTunnelDrainRegistryForTest()
	t.Cleanup(resetTunnelDrainRegistryForTest)
	probes, sleeps := 0, 0
	setRingQuiescenceProbe(t, func() { probes++ })
	prevSleep := ringQuiescenceSleep
	ringQuiescenceSleep = func(time.Duration) { sleeps++ }
	t.Cleanup(func() { ringQuiescenceSleep = prevSleep })
	isolateLogRing(t)
	if probes != 0 || sleeps != 0 {
		t.Fatalf("isolateLogRing waited with nothing in flight (probes=%d sleeps=%d)", probes, sleeps)
	}
	logAdd(LogEntry{TS: 2, Method: "GET", Host: "own.example", Status: "OK", Level: "INFO"})
	if n := len(logGet()); n != 1 {
		t.Fatalf("the isolated ring must still record this test's own entries, got %d", n)
	}
}
