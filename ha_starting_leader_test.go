package main

// ha_starting_leader_test.go — a standby and a leader that is STARTING.
//
// The leader in these tests is the REAL early listener
// (cp_starting_listener.go) reached over a real gRPC connection, so what the
// standby classifies is the status a restarting control plane actually sends.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// slStartingLeader starts the real early listener and points the standby's
// sync client at it. The returned func stops the listener (the leader's port
// closes).
func slStartingLeader(t *testing.T, p *eligPair) (stop func()) {
	t.Helper()
	cpInsecure(t)
	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	l := startCPStartingListener(cpListenerConfig{addr: addr})
	if l == nil {
		t.Fatal("the early listener did not bind")
	}
	t.Cleanup(l.stopEarlyListener)
	c, err := NewDataPlaneClient("ha-standby", addr, "", "", "")
	if err != nil {
		t.Fatalf("standby client: %v", err)
	}
	t.Cleanup(func() {
		c.mu.Lock()
		_ = c.conn.Close() //nolint:errcheck // test teardown
		c.mu.Unlock()
	})
	p.s.client = c
	return l.stopEarlyListener
}

// slClock replaces the clock the starting grace is measured on.
func slClock(t *testing.T) (advance func(time.Duration)) {
	t.Helper()
	now := time.Now()
	prev := haStartingNow
	haStartingNow = func() time.Time { return now }
	t.Cleanup(func() { haStartingNow = prev })
	return func(d time.Duration) { now = now.Add(d) }
}

func slLastSync(h *HAState) time.Time {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.lastSyncOK
}

func TestHALeaderAnswerOf_Classification(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want haLeaderAnswer
	}{
		"starting":                   {cpStartingStatus("HASync"), haAnsweredStarting},
		"publication not authorized": {cpPublishNotAuthorizedStatus("HASync", "gate closed"), haAnsweredHolding},
		"connection refused":         {status.Error(codes.Unavailable, "connection refused"), haNoAnswer},
		"a standby's own refusal":    {status.Error(codes.Unavailable, "HASync refused: this node is not the HA leader"), haNoAnswer},
		"deadline":                   {status.Error(codes.DeadlineExceeded, "timeout"), haNoAnswer},
		"plain error":                {errors.New("boom"), haNoAnswer},
	} {
		if got := haLeaderAnswerOf(tc.err); got != tc.want {
			t.Errorf("%s: classified %d, want %d", name, got, tc.want)
		}
	}
	if haStartingGrace != haPromoteFreshnessWindow/2 {
		t.Errorf("haStartingGrace = %s, want half the promote freshness window (%s): a standby synced when the leader went down must still be eligible when the grace ends",
			haStartingGrace, haPromoteFreshnessWindow/2)
	}
}

// TestLegacyStandby_SlowLeaderStartDoesNotPromote: a legacy pair with
// automatic failover. The leader restarts and takes far longer than three
// ticks to load its stores, answering CULVERT_NODE_STARTING throughout. The
// standby must not promote — a promotion here is two unfenced leaders the
// moment the old one finishes starting — must not count the rounds, and must
// not treat them as syncs. When the leader is ready the next round applies.
// The control at the end is the same standby against a CLOSED port: that
// still promotes at the threshold.
func TestLegacyStandby_SlowLeaderStartDoesNotPromote(t *testing.T) {
	p := newEligPair(t)
	advance := slClock(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce() // synced while the leader was up
	synced := slLastSync(p.h)
	if synced.IsZero() {
		t.Fatal("setup: the standby never synced")
	}
	scripted := p.s.client

	closePort := slStartingLeader(t, p) // the leader restarts: its early listener answers
	for i := 1; i <= 4*haStandbyMaxFail; i++ {
		advance(5 * time.Second)
		if p.s.guardedTick() || p.h.IsLeader() {
			t.Fatalf("the standby PROMOTED on round %d while its leader was answering %s", i, cpStartingStatusMarker)
		}
		if got := p.h.Status().SyncFailCount; got != 0 {
			t.Fatalf("round %d: sync_fail_count = %d; a starting answer must not count toward the threshold", i, got)
		}
	}
	if p.promotes.Load() != 0 {
		t.Fatalf("activations = %d, want 0", p.promotes.Load())
	}
	if got := slLastSync(p.h); !got.Equal(synced) {
		t.Errorf("a starting answer refreshed the last-sync time (%s → %s): it is proof of life, not a sync", synced, got)
	}

	// The leader is ready: the next round is an ordinary applied sync.
	p.s.client = scripted
	if p.s.guardedTick() || p.h.Status().SyncFailCount != 0 || !slLastSync(p.h).After(synced) {
		t.Fatal("the standby did not resume syncing once the leader was ready")
	}

	// Control: the same standby, the leader's port CLOSED. That is no answer.
	closePort()
	p.leader.down()
	for i := 1; i < haStandbyMaxFail; i++ {
		if p.s.guardedTick() {
			t.Fatalf("promoted after %d unreachable round(s); threshold is %d", i, haStandbyMaxFail)
		}
	}
	if !p.s.guardedTick() || !p.h.IsLeader() {
		t.Fatal("control: a synced standby must still promote when the leader does not answer at all")
	}
}

// TestLegacyStandby_LeaderHungInStartupPromotesAfterTheGrace: "starting" is
// taken as proof of life only for haStartingGrace of an unbroken run, measured
// on the standby's own clock from the first such answer. A leader hung in
// start-up past that is counted as unreachable again and the standby promotes
// — while it is still inside the freshness window that makes it eligible.
func TestLegacyStandby_LeaderHungInStartupPromotesAfterTheGrace(t *testing.T) {
	p := newEligPair(t)
	advance := slClock(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	slStartingLeader(t, p)

	if p.s.guardedTick() { // the first starting answer starts the clock
		t.Fatal("promoted on the first starting answer")
	}
	advance(haStartingGrace - time.Second)
	if p.s.guardedTick() || p.h.Status().SyncFailCount != 0 {
		t.Fatalf("a starting answer INSIDE the grace counted (fail count %d)", p.h.Status().SyncFailCount)
	}
	advance(2 * time.Second) // past the grace
	for i := 1; i < haStandbyMaxFail; i++ {
		if p.s.guardedTick() {
			t.Fatalf("promoted after %d post-grace round(s); threshold is %d", i, haStandbyMaxFail)
		}
		if got := p.h.Status().SyncFailCount; got != i {
			t.Fatalf("post-grace round %d: sync_fail_count = %d, want %d — past the grace a starting answer counts as a failure", i, got, i)
		}
	}
	if !p.s.guardedTick() || !p.h.IsLeader() {
		t.Fatal("a leader hung in start-up past the grace must not block failover forever")
	}
}

// TestLegacyStandby_StartingGraceRestartsAfterASync: the grace bounds ONE
// unbroken run. A sync in between ends it; a later restart of the leader gets
// a full grace of its own.
func TestLegacyStandby_StartingGraceRestartsAfterASync(t *testing.T) {
	p := newEligPair(t)
	advance := slClock(t)
	p.leader.serve(p.good)
	p.s.guardedSyncOnce()
	scripted := p.s.client
	slStartingLeader(t, p)
	starting := p.s.client

	p.s.guardedTick()
	advance(haStartingGrace - time.Second)
	p.s.client = scripted // the leader became ready
	if p.s.guardedTick() {
		t.Fatal("promoted on an applied sync")
	}
	p.s.client = starting // and restarts again, much later
	advance(haStartingGrace)
	for i := 0; i < 2*haStandbyMaxFail; i++ {
		if p.s.guardedTick() || p.h.Status().SyncFailCount != 0 {
			t.Fatalf("round %d of a NEW starting run was counted: the grace of the previous run was carried over", i)
		}
		advance(5 * time.Second)
	}
}

// TestLeaseStandby_StartingAnswerStillCounts: lease mode is unchanged. Every
// round that does not apply counts, and the lease arbitrates the promotion —
// here nobody holds it, so the synced standby takes over.
func TestLeaseStandby_StartingAnswerStillCounts(t *testing.T) {
	p := newEligPair(t)
	slClock(t)
	f := halease.NewFake(time.Minute)
	p.h.mu.Lock()
	p.h.stopCh = make(chan struct{})
	p.h.mu.Unlock()
	p.h.SetLeaseProvider(f, "cp-standby")
	p.h.markSyncOK()
	slStartingLeader(t, p)

	for i := 1; i < haStandbyMaxFail; i++ {
		if p.s.guardedTick() {
			t.Fatalf("promoted after %d round(s)", i)
		}
		if got := p.h.Status().SyncFailCount; got != i {
			t.Fatalf("lease mode: sync_fail_count = %d after %d starting answer(s), want %d", got, i, i)
		}
	}
	if !p.s.guardedTick() || !p.h.IsLeader() {
		t.Fatal("lease mode: the threshold must still be reached on starting answers; the lease decides who leads")
	}
	if held, _ := f.Read(context.Background()); held.Holder != "cp-standby" {
		t.Errorf("lease holder = %q, want the promoted standby", held.Holder)
	}
}
