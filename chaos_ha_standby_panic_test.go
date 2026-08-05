package main

// chaos_ha_standby_panic_test.go — CHAOS-25: HA standby-loop panic containment
// and the two promotion-path stalls it exposed.
//
// CHAOS-24 deliberately left the HA sync loop unguarded because containment
// there is NOT mechanical: the standby loop's failure counter is not an error
// tally, it is EVIDENCE THAT THE LEADER IS UNREACHABLE, and at haStandbyMaxFail
// it promotes this node. Charging a locally-raised panic to that counter — the
// obvious per-round guard — would promote a standby while a healthy leader is
// still serving writes, i.e. panic containment would MANUFACTURE the split
// brain ADR-0004/ADR-0005 exist to prevent.
//
// These tests pin the adopted semantics:
//
//  1. a faulted round is contained and RECORDED, and the loop keeps running;
//  2. a faulted round produces NO EVIDENCE — it never advances the
//     leader-unreachable streak, and never exits the loop (an exit is
//     indistinguishable from "promoted");
//  3. a faulted PROMOTION hands the `promoted` latch back, so containment
//     cannot permanently disable failover on this node; and
//  4. (HA-16) a promotion that does not take must not end the sync loop.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
)

// newPanickingStandbyLoop builds a standby loop state whose round faults inside
// the REAL production path (syncFromLeader → client.call), using the existing
// callForTest seam rather than a test-only hook in the loop.
func newPanickingStandbyLoop(t *testing.T, h *HAState, boom string) *standbyLoopState {
	t.Helper()
	c := &DataPlaneClient{}
	c.callForTest = func(_ context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		panic(boom)
	}
	return &standbyLoopState{h: h, ctx: context.Background(), leaderAddr: "leader.test:9443", client: c}
}

func newStandbyHA() *HAState {
	h := &HAState{}
	h.role = "standby"
	h.token = "t"
	return h
}

// ── 1. Containment ───────────────────────────────────────────────────────────

func TestChaos25_StandbyRoundPanic_IsContainedAndRecorded(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	s := newPanickingStandbyLoop(t, newStandbyHA(), "poisoned HA bundle")

	// Must not propagate: an unrecovered panic here kills an in-line gateway.
	if exit := s.tickGuarded(); exit {
		t.Fatal("a faulted round must never report exit=true — the caller cannot tell that apart from a promotion")
	}
	if got := atomic.LoadInt64(&statCrashRecords); got != 1 {
		t.Errorf("crash records = %d, want 1 — a contained round must stay observable", got)
	}
	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record for the contained standby round")
	}
	if rec.Component != "ha-standby" {
		t.Errorf("component = %q, want %q", rec.Component, "ha-standby")
	}
}

// The loop must survive a DETERMINISTIC fault — a poisoned field in the leader's
// bundle faults on every round, which is exactly the case that would otherwise
// restart-loop the gateway.
func TestChaos25_StandbyLoopSurvivesDeterministicRoundFault(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	h := newStandbyHA()
	s := newPanickingStandbyLoop(t, h, "every round faults")
	for i := 0; i < 10; i++ {
		if s.tickGuarded() {
			t.Fatalf("round %d exited the loop", i)
		}
	}
	if got := h.Status().SyncRoundFaults; got != 10 {
		t.Errorf("sync_round_faults = %d, want 10 — a stalled standby must be visible to an operator", got)
	}
}

// ── 2. THE SPLIT-BRAIN GATE ──────────────────────────────────────────────────

// A locally-raised fault is evidence about THIS node, not about the leader. If
// it advanced failCount it would reach haStandbyMaxFail in ~15s and promote a
// standby against a live, healthy leader. This is the assertion that fails if
// someone "simplifies" the guard into the mechanical per-round shape.
func TestChaos25_StandbyRoundPanic_DoesNotAdvanceLeaderUnreachableStreak(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	h := newStandbyHA()
	h.autoFailover = true // legacy ADR-0004 mode: no fence arbitrates promotion
	promoteCalls := 0
	h.pc = promoteContext{set: true, onPromote: func() error { promoteCalls++; return nil }}

	s := newPanickingStandbyLoop(t, h, "poisoned HA bundle")
	for i := 0; i < haStandbyMaxFail*3; i++ {
		if s.tickGuarded() {
			t.Fatalf("round %d exited the loop", i)
		}
	}

	if s.failCount != 0 {
		t.Errorf("failCount = %d, want 0 — a contained local fault is NOT evidence that the leader is unreachable",
			s.failCount)
	}
	if promoteCalls != 0 || h.IsLeader() {
		t.Fatalf("SPLIT BRAIN: %d contained local faults promoted this standby (promoteCalls=%d, isLeader=%v) "+
			"while the leader may be perfectly healthy", haStandbyMaxFail*3, promoteCalls, h.IsLeader())
	}
	if got := h.Status().SyncFailCount; got != 0 {
		t.Errorf("sync_fail_count = %d, want 0 — the leader-unreachable streak must stay clean", got)
	}
	if got := h.Status().SyncRoundFaults; got == 0 {
		t.Error("sync_round_faults = 0 — containment must not be silent; a locally stalled standby is stale state")
	}
}

// A faulted round must not look like a SUCCESS either: it must never mark the
// state fresh, so the lease-mode freshness gate keeps ageing and refuses to
// auto-promote a standby that cannot apply state.
func TestChaos25_StandbyRoundPanic_NeverMarksStateFresh(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	h := newStandbyHA()
	s := newPanickingStandbyLoop(t, h, "poisoned HA bundle")
	s.failCount = 2
	s.tickGuarded()

	if s.failCount != 2 {
		t.Errorf("failCount = %d, want it left at 2 — a faulted round is neither a success nor a failure", s.failCount)
	}
	h.mu.RLock()
	lastOK := h.lastSyncOK
	h.mu.RUnlock()
	if !lastOK.IsZero() {
		t.Error("a faulted round marked the state freshly synced — it would then pass the auto-promotion freshness gate")
	}
}

// ── 3. Promotion latch ───────────────────────────────────────────────────────

// promote() latches `promoted` before doing any work and every error branch
// clears it. A panic must be treated as one more failed attempt: leaving the
// latch set would permanently disable auto-failover, PromoteManually AND the
// planned handoff on this node, silently.
func TestChaos25_PromotePanic_ReleasesLatchSoFailoverStaysPossible(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	h := newStandbyHA()
	attempts := 0
	h.pc = promoteContext{set: true, onPromote: func() error {
		attempts++
		if attempts == 1 {
			panic("CP gRPC server start exploded")
		}
		return nil
	}}

	h.promote("first attempt")

	if h.IsLeader() {
		t.Fatal("a faulted promotion must not leave the node believing it is leader")
	}
	if h.promoted.Load() {
		t.Fatal("REGRESSION: the promotion latch stayed set after a contained fault — every future promotion " +
			"path on this node (auto-failover, manual, planned handoff) is now permanently disabled in silence")
	}
	rec, ok := lastCrashSnapshot()
	if !ok || rec.Component != "ha-promote" {
		t.Errorf("faulted promotion not recorded under component ha-promote (ok=%v rec=%+v)", ok, rec)
	}

	// The whole point of releasing the latch: a later attempt can still succeed.
	h.promote("retry")
	if !h.IsLeader() {
		t.Fatal("the retry after a contained promotion fault did not promote — failover capability was lost")
	}
}

// ── 4. HA-16: a promotion that does not take must not end the sync loop ──────

// The legacy auto-failover branch used to `return true` unconditionally after
// calling promote(), so a promotion that bailed (no promote context, a denied
// fence, an onPromote error) ended standbyLoop — the ONLY goroutine that syncs
// state or ever retries failover. The node kept serving as a standby but froze
// on last-good config forever, with no alert and no resync when the leader came
// back. A later manual failover would then promote arbitrarily stale policy.
func TestChaos25_FailedPromotionDoesNotEndTheStandbySyncLoop(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	h := newStandbyHA()
	h.autoFailover = true
	h.pc = promoteContext{set: true, onPromote: func() error { return errors.New("bind: address already in use") }}

	s := &standbyLoopState{h: h, ctx: context.Background(), leaderAddr: "leader.test:9443"}
	s.failCount = haStandbyMaxFail

	if exit := s.onMaxFail(); exit {
		t.Fatal("REGRESSION: a failed promotion ended the standby sync loop — this node would never resync " +
			"or retry failover again, silently serving frozen config")
	}
	if h.IsLeader() {
		t.Fatal("promote() reported failure but the node considers itself leader")
	}
	// And the retry path is still armed.
	if h.promoted.Load() {
		t.Error("the promotion latch was not released after an onPromote error — no retry is possible")
	}
}

// A promotion that DOES take must still exit the loop (the loop is pointless on
// a leader, and promote() has already signalled stopLoops).
func TestChaos25_SuccessfulPromotionStillExitsTheStandbyLoop(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	h := newStandbyHA()
	h.autoFailover = true
	h.pc = promoteContext{set: true, onPromote: func() error { return nil }}

	s := &standbyLoopState{h: h, ctx: context.Background(), leaderAddr: "leader.test:9443"}
	s.failCount = haStandbyMaxFail

	if exit := s.onMaxFail(); !exit {
		t.Fatal("a successful promotion must exit the standby loop")
	}
	if !h.IsLeader() {
		t.Fatal("promotion did not take")
	}
}

// ── 5. Log hygiene ───────────────────────────────────────────────────────────

// The panic value on this path can carry leader-supplied bundle content, so it
// must go through the same CWE-117 scrub as every other contained panic.
func TestChaos25_ContainedStandbyPanicTextIsScrubbed(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)

	s := newPanickingStandbyLoop(t, newStandbyHA(), "bundle\nHA: forged log line")
	s.tickGuarded()

	rec, ok := lastCrashSnapshot()
	if !ok {
		t.Fatal("no crash record")
	}
	if strings.ContainsAny(rec.Summary, "\n\r") {
		t.Errorf("crash summary carries raw control characters: %q", rec.Summary)
	}
}
