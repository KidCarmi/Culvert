package main

// cp_addr_withdrawal_chaos_test.go — CHAOS-71: a terminal supervisor exit
// keeps CP address-list ownership until the list WITHOUT this node commits
// (Codex P2 4302158678 on #1556).
//
// The defect: after a panic, the withdrawal publish (the fleet's list without
// this node) was fired and its error discarded, and exitTerminal then released
// ownership and reset the pending record. A rejected withdrawal (snapshot
// validation, or every optimistic commit attempt lost) therefore left Data
// Planes holding a dead CP address: the retry loop it had started saw no
// source and exited clean, and nothing ever reconciled the list again — in a
// process that survives the panic.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

const withdrawalTestPeer = "standby-peer.example.internal:50051"

// cpWithdrawalTopology prepares a published store and an HA leader whose
// derived CP address list is [peer, <the CP's own address>] once the CP role
// is claimed. The retry loop is isolated (cpAddrPublishHarness): a spawned
// loop reports on the returned channel and exits, and the test drives
// retryCPAddrPublish synchronously. The caller has isolated globalConfigStore
// (cpIsolateActivation) and sets the address source itself.
func cpWithdrawalTopology(t *testing.T) (spawned chan struct{}, alerts func() []string) {
	t.Helper()
	tempHADir(t)
	h := &HAState{}
	cpUseTopologySource(t, h)
	t.Cleanup(h.Stop)
	spawned, alerts = cpAddrPublishHarness(t)

	seed := ConfigSnapshot{BlockedHosts: make([]string, 50)}
	for i := range seed.BlockedHosts {
		seed.BlockedHosts[i] = fmt.Sprintf("blocked-%04d.example", i)
	}
	if err := globalConfigStore.Update(seed); err != nil {
		t.Fatalf("seed publish: %v", err)
	}
	if _, err := h.EnableAsLeader(withdrawalTestPeer, false); err != nil {
		t.Fatalf("enable HA: %v", err)
	}
	clusterRoleMu.Lock()
	clusterRole.role, clusterRole.grpcAddr = "standalone", ""
	clusterRoleMu.Unlock()
	return spawned, alerts
}

// cpWithdrawalRejectingOnActivated is an onActivated that arms a commit-time
// rejection of the withdrawal (the wire budget one byte below the snapshot
// carrying [peer]) when reject is set, then panics — after the activation
// publish has committed [peer, addr].
func cpWithdrawalRejectingOnActivated(t *testing.T, reject bool) func() {
	return func() {
		if reject {
			cpAddrSetBudgetExcluding(t, []string{withdrawalTestPeer})
		}
		panic("injected: onActivated after the address list was published")
	}
}

// cpWithdrawalOwnership reads the store's ownership state.
func cpWithdrawalOwnership() (owned bool, withdrawing string) {
	globalConfigStore.mu.RLock()
	defer globalConfigStore.mu.RUnlock()
	return globalConfigStore.cpAddrSource != nil, globalConfigStore.cpAddrWithdrawal
}

func cpCountEvent(events []string, want string) int {
	n := 0
	for _, e := range events {
		if e == want {
			n++
		}
	}
	return n
}

// cpWithdrawalEnv isolates the activation globals and the listener health,
// and returns a free loopback address for the supervisor plus its alerts.
func cpWithdrawalEnv(t *testing.T) (addr string, supervisorAlerts func() []string) {
	t.Helper()
	_ = cpIsolateActivation(t)
	supervisorAlerts = cpChaosSetup(t)
	cpInsecure(t)
	addr = fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	return addr, supervisorAlerts
}

// TestChaos71_TerminalExitKeepsAddressOwnershipUntilTheWithdrawalCommits:
// panic after the publish, the withdrawal is rejected, the fault persists for a
// retry, then clears — and only then does the retry commit the withdrawal and
// release ownership.
func TestChaos71_TerminalExitKeepsAddressOwnershipUntilTheWithdrawalCommits(t *testing.T) {
	addr, supervisorAlerts := cpWithdrawalEnv(t)
	spawned, alerts := cpWithdrawalTopology(t)
	globalConfigStore.setCPAddressSource(buildCPAddressList) // as activateControlPlane does

	sup, _ := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, cpWithdrawalRejectingOnActivated(t, true))
	if sup == nil {
		t.Fatal("the boot path returned no supervisor")
	}
	select {
	case <-sup.done:
	case <-time.After(15 * time.Second):
		t.Fatal("the supervisor did not exit terminally after the panic")
	}
	if st := cpGRPCListenerState(); !st.SupervisorDown || st.LastReason != "bind loop panicked" {
		t.Fatalf("precondition: not a terminal exit: %+v", st)
	}
	if len(supervisorAlerts()) == 0 {
		t.Error("the terminal exit raised no cp_grpc_listener_down alert")
	}

	// ---- Phase 1: the withdrawal was rejected. Ownership is KEPT as a
	// withdrawal, the failure is pending, paged once, and a retry owns it.
	owned, withdrawing := cpWithdrawalOwnership()
	if !owned || withdrawing != addr {
		t.Fatalf("after a rejected withdrawal: owned=%v withdrawing=%q, want ownership kept as a withdrawal of %q — "+
			"released, nothing ever reconciles the dead address out of the fleet's list", owned, withdrawing, addr)
	}
	if got := globalConfigStore.Get().CPAddresses; !cpAddrContains(got, addr) {
		t.Fatalf("precondition: the rejected withdrawal committed anyway: %v", got)
	}
	st := globalConfigStore.cpAddrPublishSnapshot()
	if !st.pending || st.trigger != cpAddrWithdrawalTrigger || st.reason != "publish_rejected" {
		t.Fatalf("pending state = %+v, want pending on %q (publish_rejected)", st, cpAddrWithdrawalTrigger)
	}
	if row := checkCPAddressList(); row.Status != diagFail {
		t.Errorf("cp_address_list while the withdrawal is pending = %+v, want FAIL", row)
	}
	if n := cpCountEvent(alerts(), "config_snapshot_rejected"); n != 1 {
		t.Errorf("the rejected withdrawal paged %d time(s), want exactly 1", n)
	}
	cpAddrAwaitSpawn(t, spawned)

	// ---- Phase 2 (negative control): the fault persists. A retry fails, and
	// ownership stays — no release on a failure, no second page.
	rounds := 0
	cpAddrRetrySleep = func(context.Context, time.Duration) bool { rounds++; return rounds <= 1 }
	globalConfigStore.retryCPAddrPublish(context.Background())
	if owned, withdrawing = cpWithdrawalOwnership(); !owned || withdrawing != addr {
		t.Fatalf("a failed retry released ownership: owned=%v withdrawing=%q", owned, withdrawing)
	}
	if st := globalConfigStore.cpAddrPublishSnapshot(); !st.pending || st.attempts < 2 {
		t.Fatalf("after a failed retry the pending state = %+v, want pending with >= 2 attempts", st)
	}
	if n := cpCountEvent(alerts(), "config_snapshot_rejected"); n != 1 {
		t.Errorf("a failed retry in the same episode paged again (%d pages)", n)
	}

	// ---- Phase 3: the fault clears. The retry commits the list without this
	// node and releases ownership.
	snapshotWireBudget = maxSnapshotWireBytes
	rounds = 0
	cpAddrRetrySleep = func(context.Context, time.Duration) bool { rounds++; return rounds <= 3 }
	globalConfigStore.retryCPAddrPublish(context.Background())
	if got := globalConfigStore.Get().CPAddresses; !slicesEqual(got, []string{withdrawalTestPeer}) {
		t.Fatalf("after the fault cleared the committed list = %v, want [%s] — the dead CP address stays", got, withdrawalTestPeer)
	}
	if owned, withdrawing = cpWithdrawalOwnership(); owned || withdrawing != "" {
		t.Errorf("after the withdrawal committed: owned=%v withdrawing=%q, want ownership released", owned, withdrawing)
	}
	if st := globalConfigStore.cpAddrPublishSnapshot(); st.pending || st.retrying {
		t.Errorf("after the withdrawal committed the pending state = %+v, want clear", st)
	}
	if row := checkCPAddressList(); row.Status != diagOK || !strings.Contains(row.Message, "Not an active Control Plane") {
		t.Errorf("cp_address_list after the withdrawal = %+v", row)
	}
	if n := cpCountEvent(alerts(), "config_snapshot_rejected"); n != 1 {
		t.Errorf("recovery paged (%d pages in total, want 1)", n)
	}
}

// TestChaos71_TerminalExitWithACommittedWithdrawalReleasesAtOnce is the
// positive control: with no fault the withdrawal commits inside the terminal
// exit and ownership is released there, with nothing pending and no page.
func TestChaos71_TerminalExitWithACommittedWithdrawalReleasesAtOnce(t *testing.T) {
	addr, _ := cpWithdrawalEnv(t)
	_, alerts := cpWithdrawalTopology(t)
	globalConfigStore.setCPAddressSource(buildCPAddressList)

	sup, _ := cpStartSupervised(t, cpListenerConfig{addr: addr}, true, cpWithdrawalRejectingOnActivated(t, false))
	if sup == nil {
		t.Fatal("the boot path returned no supervisor")
	}
	select {
	case <-sup.done:
	case <-time.After(15 * time.Second):
		t.Fatal("the supervisor did not exit terminally after the panic")
	}
	if got := globalConfigStore.Get().CPAddresses; !slicesEqual(got, []string{withdrawalTestPeer}) {
		t.Fatalf("the committed list after the terminal exit = %v, want [%s]", got, withdrawalTestPeer)
	}
	if owned, withdrawing := cpWithdrawalOwnership(); owned || withdrawing != "" {
		t.Errorf("a committed withdrawal kept ownership: owned=%v withdrawing=%q", owned, withdrawing)
	}
	if st := globalConfigStore.cpAddrPublishSnapshot(); st.pending {
		t.Errorf("pending after a committed withdrawal: %+v", st)
	}
	if n := cpCountEvent(alerts(), "config_snapshot_rejected"); n != 0 {
		t.Errorf("a committed withdrawal paged %d time(s)", n)
	}
}

// TestChaos71_NewOwnerEndsAPendingWithdrawal: an activation that takes the
// list over while a withdrawal is pending owns it from then on — a later
// success is the new owner's, and never releases it.
func TestChaos71_NewOwnerEndsAPendingWithdrawal(t *testing.T) {
	_ = cpIsolateActivation(t)
	spawned, _ := cpAddrPublishHarness(t)
	s := globalConfigStore
	const dead, other = "10.0.0.2:50051", "10.0.0.9:50051"
	s.setCPAddressSource(func() []string { return []string{other, dead} })
	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cpAddrSetBudgetExcluding(t, []string{other})
	if _, err := s.withdrawCPAddress(dead); err == nil {
		t.Fatal("precondition: the withdrawal was not rejected")
	}
	cpAddrAwaitSpawn(t, spawned)
	if !s.releaseCPAddressSourceAfterWithdrawal() {
		t.Fatal("a terminal exit released ownership while the withdrawal was uncommitted")
	}

	s.setCPAddressSource(func() []string { return []string{other, dead} }) // a new Control Plane at the same address
	snapshotWireBudget = maxSnapshotWireBytes
	if _, err := s.publishOwnedCPAddresses("activation", func() []string { return []string{other, dead} }); err != nil {
		t.Fatalf("the new owner's publish: %v", err)
	}
	s.mu.RLock()
	owned, withdrawing := s.cpAddrSource != nil, s.cpAddrWithdrawal
	s.mu.RUnlock()
	if !owned || withdrawing != "" {
		t.Errorf("the new owner's list: owned=%v withdrawing=%q, want owned and no withdrawal", owned, withdrawing)
	}
}

// TestChaos71_InterruptedWithdrawalIsLatchedForRetry: a withdrawal whose
// publish never recorded an outcome (interrupted by a panic) is latched
// pending by the terminal exit, so a retry owns it rather than nothing.
func TestChaos71_InterruptedWithdrawalIsLatchedForRetry(t *testing.T) {
	_ = cpIsolateActivation(t)
	spawned, _ := cpAddrPublishHarness(t)
	s := globalConfigStore
	const dead, other = "10.0.0.2:50051", "10.0.0.9:50051"
	var mu sync.Mutex
	interrupt := true
	s.setCPAddressSource(func() []string { return []string{other, dead} })
	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	s.mu.Lock()
	inner := s.cpAddrSource
	s.cpAddrSource = func() []string {
		mu.Lock()
		defer mu.Unlock()
		if interrupt {
			panic("injected: the withdrawal publish is interrupted")
		}
		return inner()
	}
	s.mu.Unlock()
	func() {
		defer func() { _ = recover() }()
		_, _ = s.withdrawCPAddress(dead)
	}()
	if st := s.cpAddrPublishSnapshot(); st.pending {
		t.Fatalf("precondition: the interrupted withdrawal recorded an outcome: %+v", st)
	}
	if !s.releaseCPAddressSourceAfterWithdrawal() {
		t.Fatal("an interrupted withdrawal released ownership")
	}
	if st := s.cpAddrPublishSnapshot(); !st.pending || st.trigger != cpAddrWithdrawalTrigger {
		t.Fatalf("the interrupted withdrawal was not latched for retry: %+v", st)
	}
	cpAddrAwaitSpawn(t, spawned)

	mu.Lock()
	interrupt = false
	mu.Unlock()
	rounds := 0
	cpAddrRetrySleep = func(context.Context, time.Duration) bool { rounds++; return rounds <= 3 }
	s.retryCPAddrPublish(context.Background())
	if got := s.Get().CPAddresses; !slicesEqual(got, []string{other}) {
		t.Errorf("after the retry the committed list = %v, want [%s]", got, other)
	}
	s.mu.RLock()
	owned, withdrawing := s.cpAddrSource != nil, s.cpAddrWithdrawal
	s.mu.RUnlock()
	if owned || withdrawing != "" {
		t.Errorf("after the retry: owned=%v withdrawing=%q, want released", owned, withdrawing)
	}
}

// TestChaos71_HARepublishDuringAWithdrawalNeverReAddsTheNode: while a
// withdrawal owns the list, an HA transition's republish (whose builder may
// still name the withdrawn node) derives from the withdrawal source, so it
// commits the withdrawal rather than re-advertising the dead address.
func TestChaos71_HARepublishDuringAWithdrawalNeverReAddsTheNode(t *testing.T) {
	_ = cpIsolateActivation(t)
	spawned, _ := cpAddrPublishHarness(t)
	s := globalConfigStore
	const dead, other = "10.0.0.2:50051", "10.0.0.9:50051"
	stale := func() []string { return []string{other, dead} }
	s.setCPAddressSource(stale)
	if err := s.Update(ConfigSnapshot{}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	cpAddrSetBudgetExcluding(t, []string{other})
	if _, err := s.withdrawCPAddress(dead); err == nil {
		t.Fatal("precondition: the withdrawal was not rejected")
	}
	cpAddrAwaitSpawn(t, spawned)
	if !s.releaseCPAddressSourceAfterWithdrawal() {
		t.Fatal("precondition: ownership was not kept for the pending withdrawal")
	}

	snapshotWireBudget = maxSnapshotWireBytes
	if err := s.reconcileCPAddressesFrom(haTransitionSelfFence, stale); err != nil {
		t.Fatalf("HA republish: %v", err)
	}
	if got := s.Get().CPAddresses; !slicesEqual(got, []string{other}) {
		t.Errorf("an HA republish during the withdrawal committed %v, want [%s]", got, other)
	}
	if owned, withdrawing := cpWithdrawalOwnership(); owned || withdrawing != "" {
		t.Errorf("after the withdrawal committed through an HA republish: owned=%v withdrawing=%q, want released", owned, withdrawing)
	}
}
