package main

// cluster_promote_deadlock_chaos_test.go — CHAOS-71 riders ported from open PR
// #1618 onto the CHAOS-71 listener supervisor (#1556): the PROMOTE-DEADLOCK
// rider and the CP ADDRESS-REPUBLISH rider. They are filed under this PR's own
// id (CHAOS-72 belongs to a different finding, #1611); when #1618 is reworked
// onto this branch it drops its own copies of these gates.
//
// Promote deadlock — HA standby→leader promotion must not deadlock on clusterRoleMu.
// main's enableControlPlane held the clusterRoleMu WRITE lock across
// CurrentConfigSnapshot, and that snapshot reads the same mutex through
// buildCPAddressList. sync.RWMutex is not reentrant, so the RLock blocked on
// the goroutine already holding the write lock and never woke. The guard that
// was supposed to make it unreachable (`if !haStatus.Enabled { return nil }`)
// is open on precisely the promotion path: HAStatus.Enabled is `role != ""`, so
// a standby reports Enabled for its whole stint. CHAOS-71's activateControlPlane
// never holds clusterRoleMu across the snapshot (cpActivationMu is the outer
// lock and clusterRoleMu is taken only briefly), so these gates pin that it
// stays that way through the real promotion entry point.
//
// Address republish — once the role is committed (commitActivation) the
// CP address list must be REPUBLISHED, outside the role lock, because the
// pre-bind snapshot names only the HA peer — for a promoting standby, the
// leader that just died — and updateDPAddresses REPLACES a DP's list.
//
// Every suspect call runs on its own goroutine and FAILS on a timeout rather
// than hanging the package: a regression must be reported, not inflicted on
// every later test in the binary.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cpWithGlobalHARole gives globalHA a role (which is what makes
// Status().Enabled true and sends buildCPAddressList down its locking branch)
// and a peer address, restoring both afterwards.
func cpWithGlobalHARole(t *testing.T, role, peer string) {
	t.Helper()
	globalHA.mu.Lock()
	prevRole, prevPeer := globalHA.role, globalHA.peerAddr
	globalHA.role, globalHA.peerAddr = role, peer
	globalHA.mu.Unlock()
	t.Cleanup(func() {
		globalHA.mu.Lock()
		globalHA.role, globalHA.peerAddr = prevRole, prevPeer
		globalHA.mu.Unlock()
	})
}

// cpIsolateActivation gives activateControlPlane a private world and gives it
// back afterwards, returning the cluster-DB path to pass in.
//
// Every global the activation touches is SWAPPED, not merely redirected — the
// lesson #1618's first draft learned: redirecting dataDir but leaving
// initClusterCA to mint into a t.TempDir() that is then deleted leaves every
// later test in the binary holding a global cluster CA pointing at a directory
// that no longer exists. Same for globalConfigStore, which
// armVersionPersistence arms at a temp path and Update then bumps.
//
// Call it BEFORE cpChaosSetup: t.Cleanup is LIFO, so the supervisor that
// cpChaosSetup stops is gone before these globals are restored under it.
func cpIsolateActivation(t *testing.T) string {
	t.Helper()
	prevDir := dataDir
	dataDir = t.TempDir()
	prevCA := globalClusterCA
	globalClusterCA = &clusterCA{}
	prevStore := globalConfigStore
	globalConfigStore = &ConfigStore{}
	t.Cleanup(func() {
		globalConfigStore = prevStore
		globalClusterCA = prevCA
		dataDir = prevDir
	})
	return filepath.Join(t.TempDir(), "cluster.json")
}

// TestChaos71_PromoteDeadlock_BuildCPAddressListNeedsTheClusterRoleLock pins the PREMISE the
// gates below rest on: with HA enabled, buildCPAddressList really does acquire
// clusterRoleMu. If a refactor removes that acquisition this fails loudly
// instead of letting the deadlock gates pass vacuously forever.
//
// The acquisition is proven from ANOTHER goroutine and the lock is then
// released. Reproducing the deadlock itself on one goroutine is deliberately
// not done: that goroutine could never be recovered and would wedge every later
// test that reads the lock.
func TestChaos71_PromoteDeadlock_BuildCPAddressListNeedsTheClusterRoleLock(t *testing.T) {
	cpWithGlobalHARole(t, "standby", "10.0.0.1:50051")
	if !globalHA.Status().Enabled {
		t.Fatal("precondition: a node with an HA role must report Enabled, or this test proves nothing")
	}

	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		clusterRoleMu.Lock()
		close(held)
		<-release
		clusterRoleMu.Unlock()
	}()
	<-held

	blocked := make(chan struct{})
	go func() {
		defer close(blocked)
		_ = buildCPAddressList()
	}()
	select {
	case <-blocked:
		close(release)
		t.Fatal("buildCPAddressList returned while clusterRoleMu was write-held — it no longer reads that lock, " +
			"so the promote-deadlock reentrancy can no longer occur and the gates below are vacuous; re-derive them")
	case <-time.After(500 * time.Millisecond):
		// Expected: it is waiting on the lock.
	}
	close(release)
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("buildCPAddressList did not complete after the write lock was released")
	}
}

// TestChaos71_PromoteDeadlock_EnableControlPlaneDoesNotDeadlockOnPromotion is the regression
// gate: with HA reporting Enabled — the standby condition every promotion path
// runs under — enableControlPlane (the HA onPromote callback) must reach a
// DECISION rather than hang. Driven against an occupied port so the call gets
// all the way through the pre-bind snapshot publish (where the deadlock lived)
// to a refused bind, binding nothing.
func TestChaos71_PromoteDeadlock_EnableControlPlaneDoesNotDeadlockOnPromotion(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	cpWithGlobalHARole(t, "standby", "10.0.0.1:50051")

	port, release := occupyPort(t)
	defer release()
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	got := make(chan error, 1)
	go func() { got <- enableControlPlane(addr, "", "", "", clusterDB) }()

	select {
	case err := <-got:
		if err == nil {
			t.Fatalf("enableControlPlane bound %q although the port is held — this gate is no longer side-effect free", addr)
		}
		// Not vacuous: the refusal must be the BIND, i.e. the call really did
		// pass the snapshot publish that used to deadlock.
		if !strings.Contains(err.Error(), "port_in_use") {
			t.Fatalf("the promotion did not reach the bind: want a port_in_use refusal, got %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("enableControlPlane did not return within 30s while HA reported Enabled — the promotion path is " +
			"deadlocked on clusterRoleMu again, and every cluster-role reader is blocked behind it")
	}
}

// TestChaos71_PromoteDeadlock_ClusterRoleReadersStayLiveAfterPromotion is the blast-radius
// assertion: after a promotion attempt, clusterRoleMu must still be acquirable
// by its readers (diagnostics, /healthz, the PAC mutation gate, the support
// bundle all read it).
func TestChaos71_PromoteDeadlock_ClusterRoleReadersStayLiveAfterPromotion(t *testing.T) {
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	cpWithGlobalHARole(t, "standby", "10.0.0.1:50051")

	port, release := occupyPort(t)
	defer release()

	attempted := make(chan struct{})
	go func() {
		defer close(attempted)
		_ = enableControlPlane(fmt.Sprintf("127.0.0.1:%d", port), "", "", "", clusterDB)
	}()
	select {
	case <-attempted:
	case <-time.After(30 * time.Second):
		t.Fatal("the promotion attempt never returned; clusterRoleMu is held by a wedged goroutine")
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_ = buildCPAddressList()
	}()
	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("clusterRoleMu is still held after the promotion attempt returned — every reader is wedged")
	}
}

// TestChaos71_CPAddrRepublish_PromotingLeaderPublishesAListNamingItself pins the address-republish rider at the level
// the defect lives: the list buildCPAddressList produces BEFORE
// clusterRole.grpcAddr is committed names only the peer, and the list AFTER
// names this node too — so there is something the republish must publish.
func TestChaos71_CPAddrRepublish_PromotingLeaderPublishesAListNamingItself(t *testing.T) {
	const (
		deadLeader = "10.0.0.1:50051"
		promoted   = "10.0.0.2:50051"
	)
	cpWithGlobalHARole(t, "standby", deadLeader)

	clusterRoleMu.Lock()
	prevRole := clusterRole
	clusterRole.grpcAddr = "" // a standby has not published a CP address
	clusterRoleMu.Unlock()
	t.Cleanup(func() {
		clusterRoleMu.Lock()
		clusterRole = prevRole
		clusterRoleMu.Unlock()
	})

	before := buildCPAddressList()
	if len(before) != 1 || before[0] != deadLeader {
		t.Fatalf("pre-commit list = %v, want just the peer %q — this gate's premise about the ordering is stale", before, deadLeader)
	}

	clusterRoleMu.Lock()
	clusterRole.grpcAddr = promoted
	clusterRoleMu.Unlock()

	after := buildCPAddressList()
	if slicesEqual(before, after) {
		t.Fatal("committing the role did not change the address list, so there would be nothing to republish")
	}
	if !cpListNames(after, promoted) {
		t.Errorf("post-commit list = %v, which does not name the promoted node %q — a DP applying it would be "+
			"left with only the dead leader", after, promoted)
	}
}

// TestChaos71_CPAddrRepublish_PromotionRepublishesTheCommittedAddressList is the WIRING gate
// for the address-republish rider on the CHAOS-71 supervisor: a real promotion through enableControlPlane
// must leave the PUBLISHED snapshot naming this node, which only the post-commit
// republish in the supervisor's activation flow can produce (the pre-bind
// publish cannot know grpcAddr). Verified failing with the address publish
// removed from commitActivation.
func TestChaos71_CPAddrRepublish_PromotionRepublishesTheCommittedAddressList(t *testing.T) {
	const deadLeader = "10.0.0.1:50051"
	clusterDB := cpIsolateActivation(t)
	cpChaosSetup(t)
	cpInsecure(t)
	cpWithGlobalHARole(t, "standby", deadLeader)

	addr := fmt.Sprintf("127.0.0.1:%d", cpFreePort(t))
	done := make(chan error, 1)
	go func() { done <- enableControlPlane(addr, "", "", "", clusterDB) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("promotion-path enableControlPlane: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("promotion-path enableControlPlane did not return — deadlock on clusterRoleMu")
	}

	pub := globalConfigStore.Get().CPAddresses
	if !cpListNames(pub, addr) {
		t.Errorf("published CP address list = %v does not name the promoted node %q — DPs would replace their "+
			"list with one naming only the dead leader", pub, addr)
	}
	if !cpListNames(pub, deadLeader) {
		t.Errorf("published CP address list = %v dropped the peer %q", pub, deadLeader)
	}
}

func cpListNames(list []string, want string) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}
