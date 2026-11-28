package main

// ha_legacy_refused_bundle_test.go — in legacy (unfenced) mode a sync round in
// which the leader ANSWERED but its bundle was not applied is not evidence
// that the leader is gone, and must not move the standby toward promotion.
//
// The defect: tick() counted every sync()==false toward haStandbyMaxFail. A
// standby that had synced a moment ago and then met a bundle it refuses
// (POL-005: the admin saved a ruleset this build cannot enforce) reached the
// threshold in three ticks, passed the freshness check (its sync was seconds
// old) and promoted — with the old leader alive, serving, and nothing in legacy
// mode to fence it. Two leaders, both publishing. The CHAOS-25 guard already
// made this decision for a panicking round; these tests pin it for a refused one.
//
// Real path throughout (guardedTick → syncFromLeader → applyHABundle); fixture
// in ha_failover_sync_eligibility_test.go.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/KidCarmi/Culvert/internal/halease"
)

func eligSyncAlertLatched(h *HAState) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.syncRefusedAlerted
}

// The exact sequence: good sync at T, then the live leader serves a bundle the
// standby refuses, for many rounds.
func TestLegacyAutoFailover_LiveLeaderRefusedBundleNeverPromotes(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	if blocked, _ := haStatusJSON(t)["auto_promote_blocked"].(string); blocked != "" {
		t.Fatalf("precondition: the standby must be freshly synced and eligible; blocked=%q", blocked)
	}

	const rounds = haStandbyMaxFail * 4
	p.leader.serve(p.refused)
	for i := 0; i < rounds; i++ {
		if p.s.guardedTick() {
			t.Fatalf("round %d: the standby PROMOTED against a live leader that was answering every round — "+
				"unfenced split brain (two leaders publishing)", i)
		}
	}
	if p.h.IsLeader() || p.promotes.Load() != 0 {
		t.Fatalf("split brain: leader=%v activations=%d while the real leader is alive", p.h.IsLeader(), p.promotes.Load())
	}

	// The stall is visible, not silent.
	st := haStatusJSON(t)
	if n, _ := st["sync_refused"].(float64); int(n) != rounds {
		t.Errorf("sync_refused = %v, want %d", st["sync_refused"], rounds)
	}
	if n, _ := st["sync_fail_count"].(float64); n != 0 {
		t.Errorf("sync_fail_count = %v, want 0: an answered round is not a step toward the unreachable threshold", n)
	}
	if !eligSyncAlertLatched(p.h) {
		t.Error("the stalled replication must page (its own fire-once latch)")
	}
	diag := diagnoseClusterFrom(clusterInputs{haStatus: p.h.Status()}, time.Now())
	if diag.OK || diag.Detail == "" {
		t.Errorf("diagnostics must report the standby unhealthy; got ok=%v detail=%q", diag.OK, diag.Detail)
	}

	// The operator fixes the ruleset: one good round clears it and re-arms the alert.
	p.leader.serve(p.good)
	if p.s.guardedTick() {
		t.Fatal("a successful round exited the loop")
	}
	st = haStatusJSON(t)
	if n, _ := st["sync_refused"].(float64); n != 0 {
		t.Errorf("sync_refused = %v after a successful sync, want 0", n)
	}
	if eligSyncAlertLatched(p.h) {
		t.Error("a successful sync must re-arm the alert latch")
	}
}

// No availability regression: after a recent good sync, a leader that truly
// stops answering is replaced exactly at the threshold — also when refused
// rounds preceded the outage.
func TestLegacyAutoFailover_UnreachableLeaderAfterRefusedRoundsStillPromotes(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	p.leader.serve(p.refused)
	for i := 0; i < 2; i++ {
		if p.s.guardedTick() {
			t.Fatalf("refused round %d promoted", i)
		}
	}

	p.leader.down()
	for i := 1; i < haStandbyMaxFail; i++ {
		if p.s.guardedTick() {
			t.Fatalf("promoted after %d unreachable round(s); threshold is %d", i, haStandbyMaxFail)
		}
	}
	if !p.s.guardedTick() || !p.h.IsLeader() {
		t.Fatal("a recently synced standby must promote when the leader stops answering (availability regression)")
	}
	if p.promotes.Load() != 1 {
		t.Fatalf("activations = %d, want 1", p.promotes.Load())
	}
}

// The streak means CONSECUTIVE rounds without contact: an answered round in
// the middle of a flaky outage proves the leader was alive and restarts it.
func TestLegacyAutoFailover_AnsweredRoundRestartsTheUnreachableStreak(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()

	if p.outage(haStandbyMaxFail - 1) {
		t.Fatal("promoted below the threshold")
	}
	p.leader.serve(p.refused) // the leader answers: it is alive
	if p.s.guardedTick() {
		t.Fatal("promoted on an answered round")
	}
	if p.outage(haStandbyMaxFail - 1) {
		t.Fatal("promoted on 2+2 unreachable rounds split by a round the leader answered")
	}
	if !p.outage(1) {
		t.Fatal("the third consecutive unreachable round must promote")
	}
}

// Lease mode is deliberately UNCHANGED: every failed round counts, because a
// leader that answers after losing the fence is the one a standby must be able
// to replace, and Acquire — not the streak — arbitrates.
func TestLeaseMode_AnsweredButRejectedRoundsStillCountTowardFailover(t *testing.T) {
	p := newEligPair(t)
	f := halease.NewFake(time.Minute) // nobody holds the lease: the answering leader is a zombie
	p.h.mu.Lock()
	p.h.stopCh = make(chan struct{})
	p.h.mu.Unlock()
	p.h.SetLeaseProvider(f, "cp-standby")
	p.h.markSyncOK()

	p.leader.serve(p.good) // answered; rejected by the puller-side epoch check (no live holder)
	for i := 1; i < haStandbyMaxFail; i++ {
		if p.s.guardedTick() {
			t.Fatalf("promoted after %d round(s)", i)
		}
		if got := p.h.Status().SyncFailCount; got != i {
			t.Fatalf("lease mode: sync_fail_count = %d after %d rejected round(s), want %d", got, i, i)
		}
	}
	if !p.s.guardedTick() || !p.h.IsLeader() {
		t.Fatal("lease mode: a standby must still replace a leader that answers without the fence")
	}
}

// A refusal and a panic are different faults with separate fire-once latches:
// one must not swallow the other's alert.
func TestLegacyAutoFailover_RefusalDoesNotSwallowALaterPanicAlert(t *testing.T) {
	resetCrashGuardStateForTest()
	t.Cleanup(resetCrashGuardStateForTest)
	p := newEligPair(t)
	p.leader.serve(p.refused)
	p.s.guardedSyncOnce()
	p.h.mu.RLock()
	refused, panicked := p.h.syncRefusedAlerted, p.h.syncPanicAlerted
	p.h.mu.RUnlock()
	if !refused || panicked {
		t.Fatalf("after a refused round: refused latch=%v panic latch=%v, want true/false", refused, panicked)
	}
	p.s.syncFn = func() bool { panic("apply-path fault after the refusal") }
	p.s.guardedTick()
	p.h.mu.RLock()
	panicked = p.h.syncPanicAlerted
	p.h.mu.RUnlock()
	if !panicked {
		t.Fatal("a panic after a refusal fired no alert: the refusal's latch swallowed it")
	}
}

// A leader that rejects the HA token is definitely alive: an answered round.
func TestLegacyAutoFailover_TokenRejectedByLiveLeaderIsAnAnsweredRound(t *testing.T) {
	p := newEligPair(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	p.s.client = &DataPlaneClient{callForTest: func(context.Context, string, json.RawMessage) (json.RawMessage, error) {
		return nil, status.Error(codes.PermissionDenied, "invalid HA token")
	}}
	for i := 0; i < haStandbyMaxFail*2; i++ {
		if p.s.guardedTick() || p.h.IsLeader() {
			t.Fatalf("round %d: promoted against a leader that answered PermissionDenied", i)
		}
	}
	if got := p.h.Status().SyncRefused; got != haStandbyMaxFail*2 {
		t.Errorf("sync_refused = %d, want %d", got, haStandbyMaxFail*2)
	}
}
