package main

// ha_failover_test.go — ADR-0005 S4: lease-arbitrated automatic failover
// (fence-gated onMaxFail, freshness gate, self-fence hysteresis, and the
// demote → standby-resync path), tested against halease.Fake.

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// freshStandby builds a lease-mode standby whose last sync just succeeded.
func freshStandby(f halease.Provider) *HAState {
	h := leaseStandby(f, "cp-standby")
	h.markSyncOK()
	return h
}

func TestLeaseAutoPromote_PromotesWhenLeaseFree(t *testing.T) {
	tempHADir(t)
	h := freshStandby(halease.NewFake(time.Minute))
	s := &standbyLoopState{h: h, leaderAddr: "dead-leader:50051"}
	if !s.onMaxFail() {
		t.Fatal("lease-mode onMaxFail must promote when the lease is free and state is fresh")
	}
	defer h.Stop()
	if !h.IsLeader() {
		t.Fatal("node should be leader after lease-arbitrated auto-failover")
	}
}

func TestLeaseAutoPromote_DeniedWhileLeaderHoldsLease(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-leader"); !granted {
		t.Fatal("seed acquire")
	}
	h := freshStandby(f)
	s := &standbyLoopState{h: h, leaderAddr: "partitioned-leader:50051"}
	if s.onMaxFail() {
		t.Fatal("onMaxFail must NOT promote while the (partitioned) leader still holds the lease")
	}
	if h.IsLeader() {
		t.Fatal("standby must stay standby when the fence denies")
	}
}

func TestLeaseAutoPromote_IgnoresAutoFailoverFlag(t *testing.T) {
	tempHADir(t)
	// autoFailover=false (the ADR-0004 default): in lease mode the fence,
	// not the flag, arbitrates — promotion must still happen.
	h := freshStandby(halease.NewFake(time.Minute))
	h.mu.Lock()
	h.autoFailover = false
	h.mu.Unlock()
	s := &standbyLoopState{h: h, leaderAddr: "dead-leader:50051"}
	if !s.onMaxFail() {
		t.Fatal("lease mode must auto-promote regardless of --ha-auto-failover (the fence is the arbiter)")
	}
	h.Stop()
}

func TestLeaseAutoPromote_FreshnessGate(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)

	// Never synced: refused.
	h := leaseStandby(f, "cp-standby")
	if h.leaseAutoPromote() {
		t.Fatal("auto-promotion must refuse when no sync ever succeeded")
	}

	// Stale sync: refused.
	h.mu.Lock()
	h.lastSyncOK = time.Now().Add(-haPromoteFreshnessWindow - time.Minute)
	h.mu.Unlock()
	if h.leaseAutoPromote() {
		t.Fatal("auto-promotion must refuse on stale state (freshness gate)")
	}
	if h.IsLeader() {
		t.Fatal("node must still be standby")
	}

	// Manual promotion BYPASSES freshness (operator break-glass).
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("manual promotion must bypass the freshness gate: %v", err)
	}
	h.Stop()
}

func TestLeaseAutoPromote_SelfFenceHysteresis(t *testing.T) {
	tempHADir(t)
	h := freshStandby(halease.NewFake(time.Minute))
	h.mu.Lock()
	h.lastSelfFence = time.Now() // just fenced
	h.mu.Unlock()
	if h.leaseAutoPromote() {
		t.Fatal("auto-promotion must be suppressed inside the self-fence cooldown")
	}
	// Cooldown elapsed: allowed again.
	h.mu.Lock()
	h.lastSelfFence = time.Now().Add(-haRepromoteCooldown - time.Second)
	h.mu.Unlock()
	if !h.leaseAutoPromote() {
		t.Fatal("auto-promotion must resume after the cooldown")
	}
	h.Stop()
}

func TestLegacyOnMaxFail_Unchanged(t *testing.T) {
	tempHADir(t)
	// No lease provider: the ADR-0004 flag semantics must be untouched.
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.autoFailover = false
	h.mu.Unlock()
	s := &standbyLoopState{h: h, leaderAddr: "dead-leader:50051"}
	if s.onMaxFail() {
		t.Fatal("legacy mode with auto-failover OFF must stay standby")
	}
	if !s.manualWarned {
		t.Fatal("legacy mode must warn that manual failover is required")
	}
}

func TestSelfFence_EntersStandbyResync(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(200 * time.Millisecond)
	h := leaseStandby(f, "cp-me")
	h.SetResyncMaterial(context.Background(), ":50051", "", "", "")
	if err := h.PromoteManually(); err != nil {
		t.Fatalf("PromoteManually: %v", err)
	}
	defer h.Stop()
	// The leader records its ex-standby (S0) — the failback target.
	h.RecordStandbyAddr("ex-standby.example:50051")

	// Steal the lease: the keepalive loop self-fences, and S4 must re-enter
	// standby mode against the recorded address (pc.set + peerAddr flipped).
	f.ExpireForTest()
	if granted, _, _ := f.Acquire(context.Background(), "cp-usurper"); !granted {
		t.Fatal("usurper acquire")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !h.IsLeader() && h.Status().PeerAddr == "ex-standby.example:50051" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	st := h.Status()
	if st.Role != "standby" || st.PeerAddr != "ex-standby.example:50051" {
		t.Fatalf("after self-fence: role=%q peer=%q, want standby syncing from the recorded ex-standby", st.Role, st.PeerAddr)
	}
	h.mu.RLock()
	fenceAt := h.lastSelfFence
	h.mu.RUnlock()
	if fenceAt.IsZero() {
		t.Fatal("self-fence must record the hysteresis timestamp")
	}
}

func TestResumeDenied_EntersStandbyResync(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-usurper"); !granted {
		t.Fatal("seed acquire")
	}

	h := &HAState{}
	h.SetLeaseProvider(f, "cp-me")
	h.SetResyncMaterial(context.Background(), ":50051", "", "", "")
	h.ResumeAsLeader(&haConfig{
		Enabled: true, Token: "tok", PeerAddr: "peer:50051", Role: "leader",
		Term: 9, StandbyAddr: "ex-standby.example:50051",
	})
	defer h.Stop()

	st := h.Status()
	if st.Role != "standby" || st.PeerAddr != "ex-standby.example:50051" {
		t.Fatalf("unfenced resume: role=%q peer=%q, want standby resyncing from the S0-recorded address", st.Role, st.PeerAddr)
	}
}

func TestResumeDenied_NoTarget_KeepsS2Stance(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-usurper"); !granted {
		t.Fatal("seed acquire")
	}

	// No StandbyAddr recorded: fall back to S2 (role kept, no write authority).
	h := &HAState{}
	h.SetLeaseProvider(f, "cp-me")
	h.SetResyncMaterial(context.Background(), ":50051", "", "", "")
	h.ResumeAsLeader(&haConfig{Enabled: true, Token: "tok", PeerAddr: "peer:50051", Role: "leader", Term: 9})
	defer h.Stop()

	if !h.IsLeader() {
		t.Fatal("with no failback target the S2 stance keeps the persisted leader role")
	}
	if h.WriteAllowed() {
		t.Fatal("unfenced resume must have no write authority (S2 stance)")
	}
}
