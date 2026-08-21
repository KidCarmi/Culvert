package main

// chaos_worker_panic_test.go — CHAOS-24: background-worker panic containment.
//
// Go terminates the process on an unrecovered panic in ANY goroutine, so before
// this change a panic in a feed sync, a health poller, or a cert-renewal tick
// was a total outage of an in-line gateway. These tests pin the two halves of
// the fix:
//
//  1. containment — the round is contained and RECORDED (it reaches the same
//     crash metric/audit pipeline as a proxy or admin panic), and the loop
//     keeps running rather than exiting into a silent permanent stall;
//  2. fail-closed — where "keep going" is NOT the safe answer, the caller
//     branches on the panic and fails closed. The fencing-lease keepalive is
//     the case that matters: a contained-but-ignored panic there would let a
//     node keep write authority it can no longer confirm, i.e. panic
//     containment would have MANUFACTURED a split brain.

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
	"github.com/KidCarmi/Culvert/internal/obs"
)

// ── 1. Containment plane ─────────────────────────────────────────────────────

func TestChaos24_RunGuarded_ContainsAndReportsRound(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	if panicked := runGuarded("worker_test", func() {}); panicked {
		t.Error("a clean round must report panicked=false")
	}
	if got := atomic.LoadInt64(&statCrashRecords); got != 0 {
		t.Errorf("clean round recorded %d crashes, want 0", got)
	}

	if panicked := runGuarded("worker_test", func() { panic("worker exploded") }); !panicked {
		t.Fatal("a panicking round must report panicked=true so fail-closed callers can branch")
	}
	if got := atomic.LoadInt64(&statCrashRecords); got != 1 {
		t.Errorf("crash records = %d, want 1 — a contained panic must stay observable", got)
	}

	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record stored for the contained worker panic")
	}
	if rec.Component != "worker_test" {
		t.Errorf("component = %q, want %q", rec.Component, "worker_test")
	}
	if rec.Category != "crash" {
		t.Errorf("category = %q, want %q", rec.Category, "crash")
	}
}

// The loop must survive EVERY round — the guard exists so a deterministic fault
// costs one interval, not the worker.
func TestChaos24_RunGuarded_LoopSurvivesDeterministicFault(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	rounds := 0
	for i := 0; i < 10; i++ {
		runGuarded("worker_test", func() { rounds++; panic("every round fails") })
	}
	if rounds != 10 {
		t.Errorf("completed rounds = %d, want 10 — the loop must not stop on panic", rounds)
	}
}

// The internal/* workers cannot import package main (ADR-0003), so they report
// through the obs seam. This pins the wiring end to end: a panic contained
// inside a leaf package must land in main's crash pipeline, not vanish.
func TestChaos24_ObsSeamRoutesLeafPanicsIntoTheCrashPipeline(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	// obs.SafeCall is exactly what internal/threatfeed, internal/feedsync,
	// internal/reqlog et al. call.
	if panicked := obs.SafeCall("feedsync", func() { panic("bad feed row") }); !panicked {
		t.Fatal("obs.SafeCall must report the panic")
	}

	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("REGRESSION: a leaf-package worker panic never reached recordCrash — " +
			"the obs.SetPanicSink wiring in crashguard.go is not installed")
	}
	if rec.Component != "feedsync" {
		t.Errorf("component = %q, want %q", rec.Component, "feedsync")
	}
	if got := atomic.LoadInt64(&statCrashRecords); got != 1 {
		t.Errorf("crash records = %d, want 1", got)
	}
}

// The panic value is attacker-adjacent in the feed workers (it can carry a
// parsed feed line) and can embed a secret. recordCrash owns that contract;
// this pins that routing a worker panic through it does not bypass the scrub.
func TestChaos24_ContainedPanicTextIsScrubbedForLogInjection(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	runGuarded("worker_test", func() { panic("evil\nADMIN LOGIN OK\r\ninjected") })

	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record")
	}
	if strings.ContainsAny(rec.Summary, "\n\r") {
		t.Errorf("CWE-117: contained panic text kept control characters: %q", rec.Summary)
	}
}

// ── 2. Fail-closed plane: the fencing-lease keepalive ────────────────────────

// panickingProvider panics inside Renew — modelling a latent nil-deref or a
// bad type assertion on the keepalive path.
type panickingProvider struct {
	halease.Provider
	renewCalls atomic.Int64
	armed      atomic.Bool
}

func (p *panickingProvider) Renew(ctx context.Context, holderID string, epoch int64) (bool, time.Duration, error) {
	p.renewCalls.Add(1)
	if p.armed.Load() {
		panic("simulated fault on the lease keepalive path")
	}
	return p.Provider.Renew(ctx, holderID, epoch)
}

// THE headline gate. A keepalive that panics every round must NOT keep write
// authority: the panic is charged against the last etcd-CONFIRMED validity
// window exactly like a transport failure, and the node self-fences.
//
// Without this, panic containment would be a REGRESSION in safety versus
// crashing: a crashed node cannot dual-write, but a node that silently stops
// renewing while still reporting WriteAllowed()==true is one half of a split
// brain — precisely what ADR-0005's fence exists to make impossible.
func TestChaos24_LeaseKeepalivePanic_FailsClosed(t *testing.T) {
	tempHADir(t)
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	// TTL must exceed haLeaseWriteMargin for the node to hold write authority
	// at all; keep it short so the confirmed window closes within the test.
	// Keepalive tick is validFor/3 ≈ 666ms, so the window (validFor minus the
	// 1s margin) lapses on the second panicking round.
	p := &panickingProvider{Provider: halease.NewFake(2 * time.Second)}
	h := leaseStandby(p, "cp-me")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer h.Stop()

	if !h.WriteAllowed() || !h.IsLeader() {
		t.Fatal("harness: a freshly-granted leader must start as leader with write authority")
	}
	p.armed.Store(true) // every keepalive round now panics

	// DEMOTION is the discriminating signal. WriteAllowed() alone would go
	// false anyway once the validity window lapsed, so asserting on it would
	// pass even for a guard that swallowed the panic and never fenced. Only
	// selfFence flips the role to standby and zeroes the epoch.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if !h.IsLeader() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if h.IsLeader() {
		t.Fatal("REGRESSION (split-brain vector): the node is still leader after its keepalive " +
			"stopped confirming the lease. A contained panic must be charged against the " +
			"confirmed-validity window and self-fence, never be silently retried forever.")
	}
	if h.WriteAllowed() {
		t.Error("a self-fenced node must not report write authority")
	}
	h.mu.RLock()
	epoch := h.leaseEpoch
	h.mu.RUnlock()
	if epoch != 0 {
		t.Errorf("fenced node kept leaseEpoch=%d, want 0", epoch)
	}
	if p.renewCalls.Load() == 0 {
		t.Error("harness: keepalive never ran")
	}
	// Containment must stay observable — a fence with no crash record would be
	// an unexplained demotion for the operator on call.
	if got := atomic.LoadInt64(&statCrashRecords); got == 0 {
		t.Error("the contained keepalive panic was not recorded")
	}
}

// The other half of the contract: a SINGLE transient panic inside a still-valid
// confirmed window must NOT fence. Fail-closed must not mean trigger-happy —
// a spurious demotion on one bad tick is its own availability incident.
func TestChaos24_LeaseWindowStillValid_PanicDoesNotFence(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Hour)

	h := &HAState{}
	h.mu.Lock()
	h.role = "leader"
	h.stopCh = make(chan struct{})
	h.lease = f
	h.leaseCandidateID = "cp-me"
	h.leaseEpoch = 7
	h.leaseConfirmedAt = time.Now() // just confirmed
	h.leaseValidFor = time.Hour     // window wide open
	h.mu.Unlock()

	if fenced := h.fenceIfLeaseWindowElapsed("simulated contained panic"); fenced {
		t.Fatal("a contained panic INSIDE the confirmed validity window must not self-fence")
	}
	if !h.IsLeader() {
		t.Error("node must still be leader")
	}

	// Age the confirmation past the window: now it MUST fence.
	h.mu.Lock()
	h.leaseConfirmedAt = time.Now().Add(-2 * time.Hour)
	h.mu.Unlock()

	if fenced := h.fenceIfLeaseWindowElapsed("simulated contained panic"); !fenced {
		t.Fatal("a contained panic past the confirmed validity window MUST self-fence")
	}
	if h.WriteAllowed() {
		t.Error("a fenced node must not report write authority")
	}
}

// The safety margin is load-bearing: authority must end haLeaseWriteMargin
// BEFORE the lease actually expires, so an in-flight write cannot land after
// another node has legitimately acquired the lease.
func TestChaos24_LeaseFenceRespectsWriteMargin(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Hour)

	h := &HAState{}
	h.mu.Lock()
	h.role = "leader"
	h.stopCh = make(chan struct{})
	h.lease = f
	h.leaseCandidateID = "cp-me"
	h.leaseEpoch = 7
	h.leaseValidFor = 10 * time.Second
	// Inside the raw validity window, but INSIDE the write margin too.
	h.leaseConfirmedAt = time.Now().Add(-(10*time.Second - haLeaseWriteMargin/2))
	h.mu.Unlock()

	if fenced := h.fenceIfLeaseWindowElapsed("simulated contained panic"); !fenced {
		t.Fatal("fence must trigger once inside haLeaseWriteMargin of expiry, not at expiry")
	}
}

// A node with no lease left to renew has no write authority to protect; the
// loop must simply stop rather than spin.
func TestChaos24_LeaseFenceStopsLoopWhenNoLeaseHeld(t *testing.T) {
	tempHADir(t)
	h := &HAState{}
	h.mu.Lock()
	h.role = "leader"
	h.stopCh = make(chan struct{})
	h.lease = nil
	h.leaseEpoch = 0
	h.mu.Unlock()

	if stop := h.fenceIfLeaseWindowElapsed("simulated contained panic"); !stop {
		t.Error("with no lease held the keepalive loop must exit")
	}
}

// ── 3. Concurrency ───────────────────────────────────────────────────────────

// Several workers contain panics at once (a shared dependency fails for all of
// them). The sink is process-wide, so this pins that containment is race-free
// and every round is accounted for.
func TestChaos24_ConcurrentContainmentIsRaceFree(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	const workers, rounds = 8, 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < rounds; i++ {
				runGuarded("worker_test", func() { panic("concurrent fault") })
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt64(&statCrashRecords); got != workers*rounds {
		t.Errorf("crash records = %d, want %d — containment must count every round",
			got, workers*rounds)
	}
}
