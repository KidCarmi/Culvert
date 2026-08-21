package main

// chaos_ha_sync_panic_test.go — CHAOS-25: HA standby sync-loop panic
// containment, and the fail-closed rule that makes the containment safe.
//
// CHAOS-24 (§12 of roadmap/CHAOS-ENGINEERING-REVIEW.md) guarded 15 background
// workers per ROUND and deliberately left the HA sync loops for a follow-up,
// because "keep the loop alive" is not by itself the safe answer here. These
// tests pin the answer:
//
//	a CONTAINED panic must never be read as evidence that the leader is gone.
//
// The gate that would fail against a naive fix is
// TestChaos25_PanickingRoundsDoNotPromote: a guard that simply counted a
// panicking round as a failed sync would auto-promote this standby after
// haStandbyMaxFail ticks while the real leader is alive and healthy — a
// remotely-triggerable split brain, strictly worse than the crash it replaced.

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// panicStandby builds a legacy-mode (no fencing lease) standby with
// auto-failover ON — the configuration in which an unwanted promotion is
// genuinely unfenced, i.e. the split-brain-capable one.
func panicStandby(t *testing.T) *HAState {
	t.Helper()
	tempHADir(t)
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.token = "test-token"
	h.autoFailover = true
	h.peerAddr = "live-leader:50051"
	h.pc = promoteContext{set: true, onPromote: func() error { return nil }}
	h.mu.Unlock()
	t.Cleanup(h.Stop)
	return h
}

// loopState builds a standbyLoopState wired to the injected sync seam, with a
// non-nil client so tick() does not try to dial.
func loopState(h *HAState, sync func() bool) *standbyLoopState {
	return &standbyLoopState{
		h:          h,
		ctx:        context.Background(),
		leaderAddr: "live-leader:50051",
		token:      "test-token",
		client:     &DataPlaneClient{},
		syncFn:     sync,
	}
}

// TestChaos25_PanickingRoundContained proves the process survives and the loop
// keeps running: a panicking round returns normally and does not exit the loop.
func TestChaos25_PanickingRoundContained(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	h := panicStandby(t)
	s := loopState(h, func() bool { panic("simulated apply-path fault in the HA bundle") })

	for i := 0; i < 3; i++ {
		if s.guardedTick() {
			t.Fatalf("round %d: a panicking round must never report loop-exit (promotion)", i)
		}
	}
	if got := h.Status().SyncPanics; got != 3 {
		t.Errorf("expected 3 contained rounds recorded, got %d", got)
	}
	if got := atomic.LoadInt64(&statCrashRecords); got != 3 {
		t.Errorf("expected 3 crash records in the shared crash plane, got %d", got)
	}
	rec, ok := lastCrashSnapshot()
	if !ok || rec.Component != haStandbySyncComponent {
		t.Errorf("contained HA panic must be attributed to %q, got %+v (ok=%v)",
			haStandbySyncComponent, rec.Component, ok)
	}
}

// TestChaos25_PanickingRoundsDoNotPromote is THE split-brain gate.
//
// The standby's own apply path is broken (a deterministic, leader-content-
// triggered panic), but the leader is alive. Legacy mode + auto-failover ON
// means nothing else stops a promotion. Far more rounds than haStandbyMaxFail
// are run: the node must still be a standby, and the failure streak must be
// untouched, because a panic says "this node is broken", not "the leader is
// gone".
func TestChaos25_PanickingRoundsDoNotPromote(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	h := panicStandby(t)
	s := loopState(h, func() bool { panic("deterministic fault, every single tick") })

	for i := 0; i < haStandbyMaxFail*4; i++ {
		if s.guardedTick() {
			t.Fatalf("round %d: contained panic promoted the standby — split brain against a live leader", i)
		}
	}
	if h.IsLeader() {
		t.Fatal("standby self-promoted on its OWN fault: unfenced split brain (CHAOS-25 regression)")
	}
	if s.failCount != 0 {
		t.Errorf("a contained panic must not advance the promotion streak; failCount=%d", s.failCount)
	}
	if got := h.Status().SyncFailCount; got != 0 {
		t.Errorf("mirrored sync_fail_count must stay 0 on contained panics, got %d", got)
	}
}

// TestChaos25_GenuineFailuresStillPromote proves the guard is not
// trigger-happy: real sync failures (the leader IS unreachable) must still
// reach haStandbyMaxFail and promote, exactly as before CHAOS-25.
func TestChaos25_GenuineFailuresStillPromote(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	h := panicStandby(t)
	s := loopState(h, func() bool { return false }) // RPC error, no panic

	var promoted bool
	for i := 0; i < haStandbyMaxFail; i++ {
		promoted = s.guardedTick()
	}
	if !promoted {
		t.Fatal("genuine consecutive sync failures must still trip auto-failover")
	}
	if !h.IsLeader() {
		t.Fatal("node should have promoted to leader after the real leader went silent")
	}
}

// TestChaos25_PanicDoesNotMaskARealOutage proves the two signals compose: a
// standby that panics for a while and THEN sees genuine failures still
// promotes on the genuine ones. The panic suppression must not be a permanent
// latch that disables failover forever.
func TestChaos25_PanicDoesNotMaskARealOutage(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	h := panicStandby(t)
	mode := "panic"
	s := loopState(h, func() bool {
		if mode == "panic" {
			panic("transient apply fault")
		}
		return false
	})

	for i := 0; i < haStandbyMaxFail*2; i++ {
		s.guardedTick()
	}
	if h.IsLeader() {
		t.Fatal("panicking rounds must not promote")
	}

	mode = "fail"
	var promoted bool
	for i := 0; i < haStandbyMaxFail; i++ {
		promoted = s.guardedTick()
	}
	if !promoted || !h.IsLeader() {
		t.Fatal("after the panics stopped, genuine leader silence must still trigger failover")
	}
}

// TestChaos25_SuccessRearmsThePanicAlert pins the fire-once latch: the
// cumulative counter never resets (it is the durable "this happened" signal),
// but a healthy round re-arms the alert so a LATER stall is not swallowed.
func TestChaos25_SuccessRearmsThePanicAlert(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	h := panicStandby(t)
	fail := true
	s := loopState(h, func() bool {
		if fail {
			panic("apply fault")
		}
		return true
	})

	s.guardedTick()
	h.mu.RLock()
	latched := h.syncPanicAlerted
	h.mu.RUnlock()
	if !latched {
		t.Fatal("first contained panic must latch the fire-once alert")
	}

	fail = false
	s.guardedTick()
	h.mu.RLock()
	latched = h.syncPanicAlerted
	h.mu.RUnlock()
	if latched {
		t.Fatal("a healthy sync round must re-arm the alert latch")
	}
	if got := h.Status().SyncPanics; got != 1 {
		t.Errorf("cumulative contained-round counter must NOT reset on recovery, got %d", got)
	}
}

// TestChaos25_ImmediateSyncPanicIsContained covers the loop's very first
// attempt (guardedSyncOnce). An unguarded panic there kills the process during
// startup — a crash-loop that never reaches the retry the loop provides.
func TestChaos25_ImmediateSyncPanicIsContained(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	h := panicStandby(t)
	s := loopState(h, func() bool { panic("first bundle, cold local state") })

	s.guardedSyncOnce() // must not panic out

	if got := h.Status().SyncPanics; got != 1 {
		t.Errorf("expected the immediate try to be recorded as contained, got %d", got)
	}
	if s.failCount != 0 {
		t.Errorf("the immediate try's panic must not seed the promotion streak, got %d", s.failCount)
	}
}

// TestChaos25_PromotePanicStaysStandby covers the onPromote hook: a panic
// while starting the CP gRPC server must be handled exactly like the error it
// already handles — no leadership, guard reset, retryable — instead of killing
// the gateway.
func TestChaos25_PromotePanicStaysStandby(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	tempHADir(t)
	h := &HAState{}
	attempts := 0
	h.mu.Lock()
	h.role = "standby"
	h.token = "test-token"
	h.autoFailover = true
	h.pc = promoteContext{set: true, onPromote: func() error {
		attempts++
		if attempts == 1 {
			panic("CP gRPC listener blew up")
		}
		return nil
	}}
	h.mu.Unlock()
	t.Cleanup(h.Stop)

	h.promote("first attempt")
	if h.IsLeader() {
		t.Fatal("a panicking onPromote must not leave the node believing it is leader")
	}
	if h.promoted.Load() {
		t.Fatal("the once-guard must be reset so a later promotion can retry")
	}

	h.promote("retry")
	if !h.IsLeader() {
		t.Fatal("a contained promote panic must stay RETRYABLE — the retry should succeed")
	}
	if attempts != 2 {
		t.Errorf("expected the hook to be retried, attempts=%d", attempts)
	}
}

// TestChaos25_LeaseModePanicIsAlsoFenced proves the rule holds in lease mode
// too: even with a free lease (the fence would GRANT), a contained panic never
// reaches promote, so this node cannot take leadership on the strength of its
// own broken parser.
func TestChaos25_LeaseModePanicIsAlsoFenced(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	tempHADir(t)
	h := leaseStandby(halease.NewFake(time.Minute), "cp-standby")
	h.markSyncOK() // fresh state: the freshness gate would otherwise refuse anyway
	t.Cleanup(h.Stop)

	s := loopState(h, func() bool { panic("apply fault under a free lease") })
	for i := 0; i < haStandbyMaxFail*3; i++ {
		s.guardedTick()
	}
	if h.IsLeader() {
		t.Fatal("a contained panic must not acquire the fencing lease and promote")
	}
}

// TestChaos25_FailedPromoteKeepsTheLoopAlive covers the level above the guard
// (Codex review, PR #1066): legacy auto-failover mode used to report loop-exit
// unconditionally after calling promote(), so a promotion that did NOT happen —
// an onPromote error, or a CHAOS-25-contained panic — ended standbyLoop for
// good. The node then stopped replicating AND stopped watching the leader while
// still reporting role="standby": the exact silent stall the per-round guard
// exists to prevent, reached one level up.
//
// The loop must keep ticking until a promotion actually succeeds.
func TestChaos25_FailedPromoteKeepsTheLoopAlive(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	tempHADir(t)

	h := &HAState{}
	attempts := 0
	h.mu.Lock()
	h.role = "standby"
	h.token = "test-token"
	h.autoFailover = true // legacy unfenced auto-failover
	h.pc = promoteContext{set: true, onPromote: func() error {
		attempts++
		switch attempts {
		case 1:
			return fmt.Errorf("CP gRPC listener: address already in use")
		case 2:
			panic("CP gRPC listener blew up")
		}
		return nil
	}}
	h.mu.Unlock()
	t.Cleanup(h.Stop)

	s := loopState(h, func() bool { return false }) // the leader really is gone

	// Drive past the threshold: rounds 1..3 trip onMaxFail (error), then the
	// next rounds retry (panic, then success).
	for i := 0; i < haStandbyMaxFail; i++ {
		if s.guardedTick() {
			t.Fatalf("round %d: loop exited before a promotion succeeded", i)
		}
	}
	if attempts != 1 || h.IsLeader() {
		t.Fatalf("expected one FAILED promote attempt and no leadership, attempts=%d leader=%v", attempts, h.IsLeader())
	}

	if s.guardedTick() { // attempt 2: panics, contained
		t.Fatal("loop exited after a CONTAINED promote panic — replication and leader monitoring would stop")
	}
	if h.IsLeader() {
		t.Fatal("a contained promote panic must not leave the node believing it is leader")
	}

	if !s.guardedTick() { // attempt 3: succeeds
		t.Fatal("loop must exit once the promotion actually succeeds")
	}
	if !h.IsLeader() {
		t.Fatal("node should be leader after the successful retry")
	}
	if attempts != 3 {
		t.Errorf("expected the promotion to be retried on every round, attempts=%d", attempts)
	}
}
