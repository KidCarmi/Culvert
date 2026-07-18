package main

// ha_failover_test.go — ADR-0005 S4: lease-arbitrated automatic failover
// (fence-gated onMaxFail, freshness gate, self-fence hysteresis, and the
// demote → standby-resync path), tested against halease.Fake.

import (
	"context"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// freshStandby builds a lease-mode standby whose last sync just succeeded.
func freshStandby(f halease.Provider) *HAState {
	h := leaseStandby(f, "cp-standby")
	h.markSyncOK()
	return h
}

// resyncCtx returns the ctx to seed into SetResyncMaterial in tests,
// cancelled on test cleanup (RISK-018). Production seeds the process
// lifecycle ctx here (cluster_startup.go), so a standby loop restarted by
// an ASYNC self-fence always dies at shutdown — but a test that seeded
// context.Background() could leak that loop forever when the fence fired
// after the test's own h.Stop() (Stop closes the CURRENT stopCh; the
// post-Stop resync creates a fresh one nobody closes). The leaked loop
// then races later tests' logger swaps under -race (the flake pinned in
// TECHNICAL-RISK-REGISTER.md RISK-018). Cancelling on cleanup makes any
// such loop die with its test regardless of Stop/fence interleaving.
func resyncCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx
}

func TestReachableLeaderLocalSyncFailureCannotAutoPromote(t *testing.T) {
	h := &HAState{role: "standby", autoFailover: true}
	s := &standbyLoopState{
		h:         h,
		ctx:       context.Background(),
		failCount: haStandbyMaxFail - 1,
	}
	if s.handleSyncResult(false, outcomeRemoteRejected) {
		t.Fatal("local sync rejection exited the standby loop")
	}
	if s.failCount != 0 {
		t.Fatalf("local sync rejection counted as leader failure: %d", s.failCount)
	}
	if h.IsLeader() {
		t.Fatal("reachable leader plus local sync rejection promoted standby")
	}
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
	h.SetResyncMaterial(resyncCtx(t), ":50051", "", "", "")
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

func TestAcquireLeaseForResume_WaitsOutOwnGhost(t *testing.T) {
	tempHADir(t)
	// Simulate a fast leader restart: the PREVIOUS process's lease (same
	// candidate ID, nobody renewing it) still holds the key. The resume
	// acquire must recognize its own ghost, wait it out, and re-acquire —
	// never demote a healthy leader for restarting quickly (ADR-0005 S5).
	f := halease.NewFake(1200 * time.Millisecond)
	if granted, _, _ := f.Acquire(context.Background(), "cp-me"); !granted {
		t.Fatal("seed ghost acquire")
	}

	h := &HAState{}
	h.SetLeaseProvider(f, "cp-me")
	if !h.acquireLeaseForResume() {
		t.Fatal("resume must succeed once our own ghost lease expires")
	}
	if !h.WriteAllowed() {
		t.Fatal("a successful resume acquire must confer write authority")
	}
}

func TestAcquireLeaseForResume_OtherHolderDeniesImmediately(t *testing.T) {
	tempHADir(t)
	f := halease.NewFake(time.Minute)
	if granted, _, _ := f.Acquire(context.Background(), "cp-other"); !granted {
		t.Fatal("seed acquire")
	}

	h := &HAState{}
	h.SetLeaseProvider(f, "cp-me")
	start := time.Now()
	if h.acquireLeaseForResume() {
		t.Fatal("a lease held by ANOTHER node is a real denial — no ghost wait")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("other-holder denial must be immediate, took %s", elapsed)
	}

	// Legacy mode (nil provider): resume is always allowed.
	if !(&HAState{}).acquireLeaseForResume() {
		t.Fatal("nil provider must allow resume (legacy mode)")
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
	h.SetResyncMaterial(resyncCtx(t), ":50051", "", "", "")
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
	h.SetResyncMaterial(resyncCtx(t), ":50051", "", "", "")
	h.ResumeAsLeader(&haConfig{Enabled: true, Token: "tok", PeerAddr: "peer:50051", Role: "leader", Term: 9})
	defer h.Stop()

	if !h.IsLeader() {
		t.Fatal("with no failback target the S2 stance keeps the persisted leader role")
	}
	if h.WriteAllowed() {
		t.Fatal("unfenced resume must have no write authority (S2 stance)")
	}
}

func TestHARPCApplicationErrorsProveLeaderReachability(t *testing.T) {
	for _, code := range []codes.Code{codes.Unauthenticated, codes.PermissionDenied, codes.FailedPrecondition} {
		if got := classifyLeaderReachability(status.Error(code, "rejected")); got != outcomeRemoteRejected {
			t.Fatalf("%s response classified %v, want outcomeRemoteRejected (leader answered)", code, got)
		}
	}
	// Unavailable collapses leader-down with TLS/cert/DNS faults, so it is
	// Ambiguous — never proven-unreachable from a status code alone.
	if got := classifyLeaderReachability(status.Error(codes.Unavailable, "transport down")); got != outcomeAmbiguous {
		t.Fatalf("Unavailable classified %v, want outcomeAmbiguous", got)
	}
}
