package main

// ha_epoch_recheck_chaos_test.go — CHAOS-71, the two Codex P1s on #1645:
//
//   - 4302217586: "nothing to restamp" is not success. A fencing epoch is
//     exposed only once a COMMITTED snapshot carries it, including when the
//     store has published nothing (a rejected initial publish, or a fresh
//     standby whose first publish is its promote's activation).
//   - 4302217588: a keepalive round acts on the grant state as it is after its
//     blocking Renew returns, never on a copy taken before it; the same rule
//     for the lease-recovery round, whose Acquire blocks too.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/halease"
)

// cpRejectedInitialPublish models activateControlPlane on a config its
// initial Update cannot publish (the error is deliberately ignored there):
// the address source is owned and the role claimed, but nothing is published.
func cpRejectedInitialPublish(t *testing.T, myAddr string) {
	t.Helper()
	globalConfigStore.setCPAddressSource(buildCPAddressList)
	prev := snapshotWireBudget
	snapshotWireBudget = 16
	if err := globalConfigStore.Update(CurrentConfigSnapshot()); err == nil {
		t.Fatal("precondition: the initial publish was accepted")
	}
	snapshotWireBudget = prev
	s := &cpListenerSupervisor{cfg: cpListenerConfig{addr: myAddr}, stopping: make(chan struct{})}
	if outcome, _, err := s.commitActivation(); outcome != cpCommitted || err != nil {
		t.Fatalf("activation: outcome=%d err=%v", outcome, err)
	}
	if ok, _ := globalConfigStore.ServableConfig(); ok {
		t.Fatal("precondition: a snapshot is servable although the initial publish was rejected")
	}
}

// cpUnpublishedEpochHarness is cpEpochHarness over a store that has published
// nothing: activate (when non-nil) brings the Control Plane up first.
func cpUnpublishedEpochHarness(t *testing.T, activate func()) (h *HAState, f *halease.Fake, pages func() []cpEpochPage) {
	t.Helper()
	h = cpAddrTopologyFixture(t)
	f = halease.NewFake(time.Minute)
	h.SetLeaseProvider(f, "cp-a")
	_, _ = cpAddrPublishHarness(t)
	var mu sync.Mutex
	var got []cpEpochPage
	prev := fireAlert
	fireAlert = func(event string, p AlertPayload) {
		if event == "config_snapshot_rejected" {
			mu.Lock()
			got = append(got, cpEpochPage{p.Source, p.Detail})
			mu.Unlock()
		}
	}
	t.Cleanup(func() { fireAlert = prev })
	if activate != nil {
		activate()
	}
	globalConfigStore.addrPubMu.Lock()
	globalConfigStore.addrPub.retrying = true
	globalConfigStore.addrPubMu.Unlock()
	t.Cleanup(resetDPLastSeenEpochForTest())
	return h, f, func() []cpEpochPage { mu.Lock(); defer mu.Unlock(); return append([]cpEpochPage(nil), got...) }
}

// TestChaos71_NoCommittedSnapshotNeverAdvertisesTheEpoch — Codex P1
// 4302217586. A persisted leader boots on a config its initial publish could
// not commit. The restamp has nothing to restamp, and that is a refusal: the
// resume takes the ADR-0005 S2 read-only leader stance (role kept, no write
// authority, no epoch on any heartbeat), pages once, and arms no retry; an
// enable is refused; a recovery round stays read-only. The control: the same
// resume over a published store leads with a servable epoch.
func TestChaos71_NoCommittedSnapshotNeverAdvertisesTheEpoch(t *testing.T) {
	const (
		myAddr = "10.0.0.2:50051"
		peer   = "10.0.0.9:50051"
	)
	resume := func(h *HAState) {
		h.ResumeAsLeader(&haConfig{Enabled: true, Role: "leader", PeerAddr: peer, Token: "tok"})
	}
	t.Run("resume_takes_the_read_only_leader_stance", func(t *testing.T) {
		h, f, pages := cpUnpublishedEpochHarness(t, func() { cpRejectedInitialPublish(t, myAddr) })
		e := cpNextGrantEpoch(t, f)
		resume(h)
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if st := h.Status(); st.Role != "leader" || !st.Enabled {
			t.Errorf("role=%q enabled=%v, want the ADR-0005 S2 read-only leader", st.Role, st.Enabled)
		}
		if h.leaseRecoveryActive() {
			t.Error("the refused resume armed an auto-retry (ADR-0005 S2: none)")
		}
		cpAssertRefusalPagedOnce(t, pages)
	})
	t.Run("enable_is_refused", func(t *testing.T) {
		h, f, pages := cpUnpublishedEpochHarness(t, func() { cpRejectedInitialPublish(t, myAddr) })
		e := cpNextGrantEpoch(t, f)
		if _, err := h.EnableAsLeader(peer, false); err == nil {
			t.Fatal("enable succeeded although no committed snapshot carries its epoch")
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if st := h.Status(); st.Role != "" {
			t.Errorf("a refused enable took role %q", st.Role)
		}
		cpAssertRefusalPagedOnce(t, pages)
	})
	t.Run("lease_recovery_stays_read_only", func(t *testing.T) {
		h, f, pages := cpUnpublishedEpochHarness(t, func() { cpRejectedInitialPublish(t, myAddr) })
		resume(h) // the read-only leader; one page
		f.ExpireForTest()
		e := cpNextGrantEpoch(t, f)
		if cpRecoveryRound(h) {
			t.Fatal("the recovery round reported done although no committed snapshot carries its epoch")
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		cpAssertRefusalPagedOnce(t, pages) // the same episode as the resume's
	})
	t.Run("control_published_store_leads", func(t *testing.T) {
		h, f, pages := cpUnpublishedEpochHarness(t, func() { cpAddrActiveCP(t, myAddr) })
		want := cpNextGrantEpoch(t, f)
		resume(h)
		cpAssertEpochServable(t, h, want)
		if n := cpEpochPagesFrom(pages(), "ha"); n != 0 {
			t.Errorf("a resume over a published store paged %d time(s)", n)
		}
	})
}

// TestChaos71_PromoteWithNothingPublishedExposesOnlyItsCommittedFirstPublish —
// the promote half of the same class. A fresh standby has published nothing:
// its first publish is the Control Plane activation inside onPromote, stamped
// with the new epoch by the mirror. It is preflighted before the listener
// starts, and exposure verifies it committed.
func TestChaos71_PromoteWithNothingPublishedExposesOnlyItsCommittedFirstPublish(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	// activation is onPromote modelled on activateControlPlane: own the list,
	// then the initial publish, whose error is ignored.
	activation := func(starts *int, budget int) func() error {
		return func() error {
			*starts++
			globalConfigStore.setCPAddressSource(buildCPAddressList)
			if budget > 0 {
				snapshotWireBudget = budget // the config grew between the preflight and the activation
			}
			_ = globalConfigStore.Update(CurrentConfigSnapshot())
			return nil
		}
	}
	standby := func(t *testing.T, h *HAState, onPromote func() error) {
		t.Helper()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		h.StartAsStandby(ctx, "10.0.0.7:50051", "tok", myAddr, "", "", "", false, onPromote)
	}
	t.Run("control_first_publish_carries_the_epoch", func(t *testing.T) {
		h, f, pages := cpUnpublishedEpochHarness(t, nil)
		starts := 0
		standby(t, h, activation(&starts, 0))
		want := cpNextGrantEpoch(t, f)
		if err := h.PromoteManually(); err != nil {
			t.Fatalf("promote: %v", err)
		}
		cpAssertEpochServable(t, h, want)
		if n := cpEpochPagesFrom(pages(), "ha"); n != 0 {
			t.Errorf("a clean promote paged %d time(s)", n)
		}
	})
	t.Run("first_publish_that_cannot_fit_is_refused_before_the_listener", func(t *testing.T) {
		h, f, pages := cpUnpublishedEpochHarness(t, nil)
		starts := 0
		standby(t, h, activation(&starts, 0))
		e := cpNextGrantEpoch(t, f)
		prev := snapshotWireBudget
		snapshotWireBudget = 16
		t.Cleanup(func() { snapshotWireBudget = prev })
		if err := h.PromoteManually(); err == nil {
			t.Fatal("promote succeeded although its first publish cannot carry the epoch")
		}
		if starts != 0 {
			t.Fatalf("the Control Plane listener was started %d time(s) for a promote refused on its first publish", starts)
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if st := h.Status(); st.Role != "standby" || h.promoted.Load() {
			t.Errorf("role=%q promoted=%v, want a retryable standby", st.Role, h.promoted.Load())
		}
		cpAssertRefusalPagedOnce(t, pages)
	})
	t.Run("first_publish_rejected_after_the_preflight_is_not_exposed", func(t *testing.T) {
		h, f, pages := cpUnpublishedEpochHarness(t, nil)
		prev := snapshotWireBudget
		t.Cleanup(func() { snapshotWireBudget = prev })
		starts := 0
		standby(t, h, activation(&starts, 16))
		e := cpNextGrantEpoch(t, f)
		if err := h.PromoteManually(); err == nil {
			t.Fatal("promote succeeded although no committed snapshot carries its epoch")
		}
		if starts != 1 {
			t.Fatalf("precondition: the activation ran %d time(s)", starts)
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if st := h.Status(); st.Role != "standby" {
			t.Errorf("role = %q, want standby", st.Role)
		}
		cpAssertRefusalPagedOnce(t, pages)
	})
}

// cpGatedRenew blocks the first Renew it sees until released, so a test can
// land a transition while a keepalive round is inside the RPC.
type cpGatedRenew struct {
	halease.Provider
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func newCPGatedRenew(p halease.Provider) *cpGatedRenew {
	return &cpGatedRenew{Provider: p, entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *cpGatedRenew) Renew(ctx context.Context, holderID string, epoch int64) (bool, time.Duration, error) {
	first := false
	g.once.Do(func() { first = true })
	if first {
		close(g.entered)
		select {
		case <-g.release:
		case <-ctx.Done():
		}
	}
	return g.Provider.Renew(context.Background(), holderID, epoch)
}

// cpAwait polls cond until it holds or the deadline passes.
func cpAwait(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// cpKeepaliveHandleSet reports whether a keepalive handle is installed.
func cpKeepaliveHandleSet(h *HAState) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.leaseStopCh != nil
}

// TestChaos71_KeepaliveActsOnTheGrantStateAfterItsRenew — Codex P1
// 4302217588. A keepalive started on a STAGED grant blocks in Renew; the
// enable exposes the grant meanwhile; then Renew confirms the loss. The round
// must act on the state NOW: the grant is installed, so the node self-fences
// (no epoch, no write authority, no leader role) and the loop exits with its
// handle cleared. The negative control is the same loss landing while the
// grant is still staged: dropped, never self-fenced, and the enable refused.
func TestChaos71_KeepaliveActsOnTheGrantStateAfterItsRenew(t *testing.T) {
	const peer = "10.0.0.9:50051"
	setup := func(t *testing.T) (*HAState, *halease.Fake, *cpGatedRenew) {
		h, _, _ := cpEpochHarness(t, "10.0.0.2:50051")
		f := halease.NewFake(3 * time.Second) // keepalive tick = 1 s
		g := newCPGatedRenew(f)
		h.SetLeaseProvider(g, "cp-a")
		return h, f, g
	}
	supersede := func(t *testing.T, f *halease.Fake) {
		t.Helper()
		f.ExpireForTest()
		if granted, _, err := f.Acquire(context.Background(), "cp-b"); !granted || err != nil {
			t.Fatalf("precondition: the peer could not take the lease (granted=%v err=%v)", granted, err)
		}
	}
	awaitEntered := func(t *testing.T, g *cpGatedRenew) {
		t.Helper()
		select {
		case <-g.entered:
		case <-time.After(10 * time.Second):
			t.Fatal("the keepalive never renewed the staged grant")
		}
	}
	t.Run("installed_during_the_renew_self_fences", func(t *testing.T) {
		h, f, g := setup(t)
		e := cpNextGrantEpoch(t, f)
		prev := haRestampFenceEpoch
		haRestampFenceEpoch = func() error {
			awaitEntered(t, g) // the keepalive is inside Renew on the STAGED grant
			return prev()
		}
		t.Cleanup(func() { haRestampFenceEpoch = prev })
		if _, err := h.EnableAsLeader(peer, false); err != nil {
			t.Fatalf("enable: %v", err)
		}
		if st := h.Status(); st.Role != "leader" || h.CurrentEpoch() != e {
			t.Fatalf("precondition: role=%q epoch=%d, want the installed grant %d", st.Role, h.CurrentEpoch(), e)
		}
		supersede(t, f)
		close(g.release) // Renew now returns the confirmed loss
		cpAwait(t, "the self-fence", func() bool { return h.Status().Role != "leader" })
		if st := h.Status(); st.Role != "standby" {
			t.Errorf("role = %q after a confirmed loss of the installed grant, want standby", st.Role)
		}
		if got := h.CurrentEpoch(); got != 0 {
			t.Errorf("heartbeats still advertise the lost epoch %d", got)
		}
		if h.WriteAllowed() {
			t.Error("write authority survived a confirmed loss of the installed grant")
		}
		cpAwait(t, "the keepalive handle to clear", func() bool { return !cpKeepaliveHandleSet(h) })
	})
	t.Run("control_still_staged_is_dropped_not_fenced", func(t *testing.T) {
		h, f, g := setup(t)
		e := cpNextGrantEpoch(t, f)
		prev := haRestampFenceEpoch
		haRestampFenceEpoch = func() error {
			awaitEntered(t, g)
			supersede(t, f)
			close(g.release)
			cpAwait(t, "the staged grant to be dropped", func() bool {
				h.mu.RLock()
				defer h.mu.RUnlock()
				return h.heldEpochLocked() == 0
			})
			return prev()
		}
		t.Cleanup(func() { haRestampFenceEpoch = prev })
		if _, err := h.EnableAsLeader(peer, false); err == nil {
			t.Fatal("enable succeeded although its staged grant was lost")
		}
		if st := h.Status(); st.Role != "" {
			t.Errorf("role = %q, want none (a staged grant has no role to fence)", st.Role)
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if cpKeepaliveHandleSet(h) {
			t.Error("a keepalive handle survived the lost staged grant")
		}
	})
}

// cpHookedAcquire runs after() once, right after the first granted Acquire
// returns — inside the window between the RPC and its caller's decision.
type cpHookedAcquire struct {
	halease.Provider
	once  sync.Once
	after func()
}

func (p *cpHookedAcquire) Acquire(ctx context.Context, id string) (bool, halease.Status, error) {
	granted, st, err := p.Provider.Acquire(ctx, id)
	if granted && err == nil {
		p.once.Do(p.after)
	}
	return granted, st, err
}

// TestChaos71_LeaseRecoveryRechecksItsStateAfterTheAcquire — the same rule
// for the CHAOS-55 recovery round: it read "unfenced leader" before its
// blocking Acquire. When this node re-enters standby while the Acquire is in
// flight, the recovered grant must not be installed over the standby (an
// epoch, write authority and a keepalive on a standby would hold the fence
// against the real leader). The control (no transition) recovers.
func TestChaos71_LeaseRecoveryRechecksItsStateAfterTheAcquire(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	t.Run("standby_entered_during_the_acquire", func(t *testing.T) {
		h, f, _ := cpEpochHarness(t, myAddr)
		cpReadOnlyLeader(t, h, f)
		f.ExpireForTest()
		e := cpNextGrantEpoch(t, f)
		h.SetLeaseProvider(&cpHookedAcquire{Provider: f, after: func() {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			h.StartAsStandby(ctx, "10.0.0.7:50051", "tok", myAddr, "", "", "", false, func() error { return nil })
		}}, "cp-a")
		if !cpRecoveryRound(h) {
			t.Error("the round asked to retry although the state that armed it is gone")
		}
		if st := h.Status(); st.Role != "standby" {
			t.Fatalf("role = %q, want the standby entered during the acquire", st.Role)
		}
		cpAssertEpochNotAdvertised(t, h, e, 0)
		if cpKeepaliveHandleSet(h) {
			t.Error("a keepalive still renews the grant recovered for a leader that no longer exists")
		}
	})
	t.Run("control_recovers", func(t *testing.T) {
		h, f, _ := cpEpochHarness(t, myAddr)
		cpReadOnlyLeader(t, h, f)
		f.ExpireForTest()
		want := cpNextGrantEpoch(t, f)
		if !cpRecoveryRound(h) {
			t.Fatal("the recovery round did not complete")
		}
		cpAssertEpochServable(t, h, want)
	})
}
