package main

// cp_grpc_degraded_promotion_chaos_test.go — CHAOS-71 gates for two Codex
// findings on #1556: an address-only publish is not refused by the
// rewrite-identity degradation latch, which still refuses full publishes
// (P1 4314031064), and a terminal exit records the terminal state before the
// withdrawal (P2 4314031070).

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
)

// cpLatchRewriteDegradation sets the rewrite management-identity degradation
// latch for the test and restores whatever was there before.
func cpLatchRewriteDegradation(t *testing.T) {
	t.Helper()
	prev := rewriteIdentityDegradedState.Load()
	if prev != nil {
		t.Fatalf("precondition: the degradation latch is already set (%s) — an earlier test leaked it", prev.reason)
	}
	t.Cleanup(func() { rewriteIdentityDegradedState.Store(prev) })
	setRewriteIdentityDegraded("chaos71: injected rewrite-identity persistence fault")
}

// TestChaos71_PromotionCommitsAddressesWhileRewriteIdentityDegraded — Codex P1
// 4314031064. The store has already published (a node that led earlier in
// this process, or the boot path's first publish, which precedes
// LoadAdminSettings), then the rewrite-identity latch is set. A promotion's
// full publish is refused by Gate 0, as it must be — but the activation's
// address publish is the COMMITTED snapshot with only CPAddresses replaced,
// and refusing it too rolled the role back on every promotion until a
// restart. Mutation check: routing publishAddresses through Gate 0
// (validatePublishCandidate) fails this gate.
func TestChaos71_PromotionCommitsAddressesWhileRewriteIdentityDegraded(t *testing.T) {
	tempHADir(t)
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	const peer = "10.0.0.9:50051"
	cpWithGlobalHARole(t, "standby", peer)

	if err := globalConfigStore.Update(CurrentConfigSnapshot()); err != nil {
		t.Fatalf("precondition: the pre-latch publish failed: %v", err)
	}
	before := globalConfigStore.Version()
	cpLatchRewriteDegradation(t)

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	h := &HAState{}
	h.mu.Lock()
	h.role = "standby"
	h.term = 4
	h.peerAddr = peer
	h.stopCh = make(chan struct{})
	h.pc = promoteContext{
		grpcAddr:  addr,
		onPromote: func() error { return enableControlPlane(addr, "", "", "", clusterDB) },
		set:       true,
	}
	h.mu.Unlock()
	t.Cleanup(h.Stop)

	got := make(chan error, 1)
	go func() { got <- h.PromoteManually() }()
	select {
	case err := <-got:
		if err != nil {
			t.Fatalf("promotion failed while rewrite identity was degraded: %v — an unrelated "+
				"rewrite-persistence fault disabled HA failover", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("PromoteManually did not return")
	}
	if !h.IsLeader() {
		t.Fatalf("role after the promotion = %q, want leader", h.Status().Role)
	}
	if role := cpRoleNow(); role != "control-plane" {
		t.Errorf("cluster role after the promotion = %q, want control-plane (the activation was rolled back)", role)
	}
	if pub := globalConfigStore.Get().CPAddresses; !cpListNames(pub, addr) {
		t.Errorf("committed CP list %v does not name the promoted node %q", pub, addr)
	}
	if v := globalConfigStore.Version(); v <= before {
		t.Errorf("version %d after the promotion, want > %d: the address publish never committed", v, before)
	}
	// The activation's FULL publish is still refused, in the same flow.
	if msg, _ := globalConfigStore.LastPublishError(); !strings.Contains(msg, "rewrite management identity degraded") {
		t.Errorf("LastPublishError = %q, want the Gate 0 refusal of the activation's full publish", msg)
	}
}

// TestChaos71_FencedPromotionRestampsTheEpochWhileRewriteIdentityDegraded —
// the same P1 (4314031064) on the fenced path #1645 adds. With a fencing
// lease, a promote first commits the COMMITTED snapshot restamped with its new
// epoch (RestampFenceEpoch, publishEpoch) and only then advertises it. That
// candidate captures no live state, exactly like the address-only one, so the
// rewrite-identity latch must not refuse it: refusing it left the node standby
// on every promote until a restart. Mutation check: routing publishEpoch
// through Gate 0 (validatePublishCandidate) fails this gate.
func TestChaos71_FencedPromotionRestampsTheEpochWhileRewriteIdentityDegraded(t *testing.T) {
	const myAddr = "10.0.0.2:50051"
	h, f, pages := cpEpochHarness(t, myAddr)
	cpEnterStandby(t, h, myAddr)
	committed := globalConfigStore.Get()
	cpLatchRewriteDegradation(t)
	want := cpNextGrantEpoch(t, f)

	if err := h.PromoteManually(); err != nil {
		t.Fatalf("fenced promotion failed while rewrite identity was degraded: %v — an unrelated "+
			"rewrite-persistence fault disabled HA failover", err)
	}
	if st := h.Status(); st.Role != "leader" {
		t.Fatalf("role after the promotion = %q, want leader", st.Role)
	}
	cpAssertEpochServable(t, h, want)
	got := globalConfigStore.Get()
	if !slicesEqual(got.BlockedHosts, committed.BlockedHosts) {
		t.Errorf("the epoch restamp changed the committed content: BlockedHosts %d → %d entries",
			len(committed.BlockedHosts), len(got.BlockedHosts))
	}
	if p := pages(); len(p) != 0 {
		t.Errorf("a promote whose restamp is exempt from Gate 0 paged: %+v", p)
	}
	// Full publishes are still refused while the latch is set.
	if err := globalConfigStore.Update(CurrentConfigSnapshot()); err == nil ||
		!strings.Contains(err.Error(), "rewrite management identity degraded") {
		t.Errorf("full publish after the promotion: err = %v, want the Gate 0 refusal", err)
	}
}

// TestChaos71_RewriteDegradationStillRefusesFullPublishes is the other half of
// the P1 fix, on a bare store: with the latch set a full publish is refused and
// commits nothing, while an address-only publish commits onto the committed
// snapshot and carries none of the refused publish's content.
func TestChaos71_RewriteDegradationStillRefusesFullPublishes(t *testing.T) {
	s := &ConfigStore{}
	if err := s.Update(ConfigSnapshot{BlockedHosts: []string{"committed.example"}}); err != nil {
		t.Fatalf("precondition: the pre-latch publish failed: %v", err)
	}
	committed := s.Version()
	cpLatchRewriteDegradation(t)

	err := s.Update(ConfigSnapshot{BlockedHosts: []string{"captured-while-degraded.example"}})
	if err == nil || !strings.Contains(err.Error(), "rewrite management identity degraded") {
		t.Fatalf("full publish while degraded: err = %v, want the Gate 0 refusal", err)
	}
	if v := s.Version(); v != committed {
		t.Fatalf("a refused full publish moved the version %d → %d", committed, v)
	}

	const cp = "10.0.0.1:50051"
	changed, err := s.UpdateCPAddressesFrom(func() []string { return []string{cp} })
	if err != nil || !changed {
		t.Fatalf("address-only publish while degraded: changed=%v err=%v, want a commit", changed, err)
	}
	got := s.Get()
	if !slicesEqual(got.CPAddresses, []string{cp}) {
		t.Errorf("committed CP list = %v, want [%s]", got.CPAddresses, cp)
	}
	if !slicesEqual(got.BlockedHosts, []string{"committed.example"}) {
		t.Errorf("committed BlockedHosts = %v: the address publish carried content the refused full publish captured", got.BlockedHosts)
	}
	if msg, _ := s.LastPublishError(); !strings.Contains(msg, "rewrite management identity degraded") {
		t.Errorf("LastPublishError = %q: an address-only commit cleared the full publish's refusal", msg)
	}
}

// cpWithdrawalEntry is the health state the withdrawal saw when it started.
type cpWithdrawalEntry struct {
	snap     cpGRPCListenerSnapshot
	withheld bool
}

// TestChaos71_TerminalStateIsRecordedBeforeTheWithdrawal — Codex P2
// 4314031070. A seam inside the withdrawal observes health at its start: the
// listener is already down (not serving, supervisor down) and lease renewal is
// already withheld. Before the fix the terminal state was recorded only after
// the withdrawal, so for its whole (snapshot-sized) duration diagnostics said
// Serving=true and the HA lease kept renewing. Mutation check: moving
// noteCPGRPCSupervisorDown back after the withdrawal fails both rows.
func TestChaos71_TerminalStateIsRecordedBeforeTheWithdrawal(t *testing.T) {
	rows := []struct {
		name  string
		setup func(t *testing.T)
	}{
		{
			// The Codex scenario: the server had been serving; a panic after
			// its serve ended (here, while retiring it) reaches the panic edge
			// with health still recording it as serving.
			name: "panic_retiring_a_served_server",
			setup: func(t *testing.T) {
				prev := retireCPGRPCServer
				retireCPGRPCServer = func(srv *grpc.Server) {
					prev(srv) // abandonAfterPanic finds it already stopped
					panic("injected: while retiring a served server")
				}
				t.Cleanup(func() { retireCPGRPCServer = prev })
			},
		},
		{
			name: "panic_in_the_backoff_after_a_serve",
			setup: func(t *testing.T) {
				prev := cpGRPCSleep
				cpGRPCSleep = func(<-chan struct{}, time.Duration) bool { panic("injected: in the backoff after a serve") }
				t.Cleanup(func() { cpGRPCSleep = prev })
			},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			_ = cpIsolateActivation(t)
			cpChaosSetup(t)
			cpInsecure(t)
			clusterRoleMu.Lock()
			clusterRole.role = "standalone"
			clusterRoleMu.Unlock()

			var mu sync.Mutex
			var lns []net.Listener
			prevWrap := cpWrapListener
			cpWrapListener = func(ln net.Listener) net.Listener {
				mu.Lock()
				lns = append(lns, ln)
				mu.Unlock()
				return ln
			}
			t.Cleanup(func() { cpWrapListener = prevWrap })

			var entries []cpWithdrawalEntry
			prevWithdraw := cpWithdrawCPAddress
			cpWithdrawCPAddress = func(addr string) (bool, error) {
				_, withheld := cpGRPCLeaseRenewWithheld()
				mu.Lock()
				entries = append(entries, cpWithdrawalEntry{snap: cpGRPCListenerState(), withheld: withheld})
				mu.Unlock()
				return prevWithdraw(addr)
			}
			t.Cleanup(func() { cpWithdrawCPAddress = prevWithdraw })
			row.setup(t)

			cfg := cpListenerConfig{addr: fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))}
			globalConfigStore.setCPAddressSource(buildCPAddressList) // as activateControlPlane does
			sup, _ := cpStartSupervised(t, cfg, true, nil)
			if sup == nil {
				t.Fatal("the boot path returned no supervisor")
			}
			cpWaitFor(t, 10*time.Second, "the listener to serve", func() bool { return cpGRPCListenerState().Serving })
			mu.Lock()
			first := lns[0]
			mu.Unlock()
			_ = first.Close() // the serve ends on its own
			select {
			case <-sup.done:
			case <-time.After(15 * time.Second):
				t.Fatal("the supervisor did not end at the injected panic")
			}

			mu.Lock()
			defer mu.Unlock()
			if len(entries) != 1 {
				t.Fatalf("the terminal exit ran the withdrawal %d time(s), want 1", len(entries))
			}
			e := entries[0]
			if e.snap.Serving || !e.snap.SupervisorDown {
				t.Errorf("at the withdrawal: serving=%v supervisorDown=%v — the terminal state was not recorded "+
					"first, so diagnostics reported a dead listener as serving", e.snap.Serving, e.snap.SupervisorDown)
			}
			if !e.withheld {
				t.Error("at the withdrawal: lease renewal was not withheld — a leader with no listener and no " +
					"supervisor kept its fencing lease, delaying failover")
			}
			if final := cpGRPCListenerState(); !final.SupervisorDown || final.LastReason != "bind loop panicked" {
				t.Errorf("after the exit: supervisorDown=%v reason=%q, want the terminal panic state",
					final.SupervisorDown, final.LastReason)
			}
		})
	}
}
