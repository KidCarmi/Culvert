package main

// cluster_promote_deadlock_chaos_test.go — CHAOS-72: HA standby→leader
// promotion must not deadlock on clusterRoleMu.
//
// enableControlPlane held the clusterRoleMu WRITE lock across
// CurrentConfigSnapshot, and that snapshot reads the same mutex through
// buildCPAddressList (it needs clusterRole.grpcAddr for the DP failover address
// list). sync.RWMutex is not reentrant, so the RLock blocked on the goroutine
// already holding the write lock and never woke.
//
// The guard that was supposed to make this unreachable is buildCPAddressList's
// `if !haStatus.Enabled { return nil }`, and it is open on precisely the path
// that matters: HAStatus.Enabled is `role != ""`, so a standby node reports
// Enabled for its entire stint, and every promotion path (manual, legacy
// auto-failover, planned handoff, lease-arbitrated) reaches enableControlPlane
// through HAState.promote's onPromote closure.
//
// The blast radius is why these are errors rather than skips: the hung
// goroutine keeps the WRITE lock, so every clusterRoleMu reader — diagnostics,
// the health surfaces, the PAC mutation gate, the support bundle — blocks
// behind it too. The node becomes neither a control plane nor diagnosable.
//
// Both tests run the suspect call on their own goroutine and FAIL on a timeout
// rather than hanging the package: a regression here must be reported, not
// inflicted on every other test in the binary.

import (
	"testing"
	"time"
)

// withHARoleForTest gives the HA state a role, which is what makes
// Status().Enabled true, and restores it afterwards.
func withHARoleForTest(t *testing.T, role string) {
	t.Helper()
	globalHA.mu.Lock()
	prev := globalHA.role
	globalHA.role = role
	globalHA.mu.Unlock()
	t.Cleanup(func() {
		globalHA.mu.Lock()
		globalHA.role = prev
		globalHA.mu.Unlock()
	})
}

// TestChaos72_BuildCPAddressListNeedsTheClusterRoleLock pins the PREMISE the
// regression guards below rest on: with HA enabled, buildCPAddressList really
// does acquire clusterRoleMu, so calling it under the write lock really would
// be reentrant. If a refactor removes that acquisition this test fails loudly,
// telling the next reader that CHAOS-72's guards have stopped guarding
// anything, instead of letting them pass vacuously forever.
//
// It proves the acquisition from ANOTHER goroutine and then releases the lock.
// Reproducing the deadlock itself — taking the write lock and calling
// buildCPAddressList on one goroutine — is deliberately NOT done here: that
// goroutine can never be recovered, so it would hold a process-global lock for
// the rest of the test binary and wedge every later test that reads it. (The
// first draft of this file did exactly that and poisoned the two tests below.)
func TestChaos72_BuildCPAddressListNeedsTheClusterRoleLock(t *testing.T) {
	withHARoleForTest(t, "standby")
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
		t.Fatal("buildCPAddressList returned while clusterRoleMu was write-held — it no longer reads that lock, so the reentrancy CHAOS-72 fixed can no longer occur and the guards below are vacuous; re-derive them before trusting this file")
	case <-time.After(500 * time.Millisecond):
		// Expected: it is waiting on the lock. Release and let it finish, so
		// nothing is left wedged.
	}
	close(release)
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("buildCPAddressList did not complete after the write lock was released")
	}
}

// chaos72PromotionAddr is a gRPC listen address that is non-empty and
// well-formed — so enableControlPlane's argument check passes and it proceeds
// into the locked section where the deadlock lived — but that can never bind,
// because `.invalid` is reserved by RFC 2606 and never resolves.
//
// That combination is what makes these tests both honest and cheap. The hang
// was at the config-snapshot publish, which happens BEFORE the listen, so the
// call must get far enough to fail at the listen; and because it fails there,
// the test never binds a port and never sets clusterRole.role (which is only
// assigned after a SUCCESSFUL listen). An empty address would not do: it
// returns from the argument check before reaching the snapshot, so it would
// have passed pre-fix too and guarded nothing.
const chaos72PromotionAddr = "culvert-chaos72.invalid:50051"

// chaos72Isolate points the writes enableControlPlane performs before it fails
// (the armed config-version floor and the cluster CA) at a temp dir, and
// restores the cluster-role global afterwards.
func chaos72Isolate(t *testing.T) string {
	t.Helper()
	prevDir := dataDir
	dataDir = t.TempDir()
	clusterRoleMu.Lock()
	prevRole := clusterRole
	clusterRoleMu.Unlock()
	t.Cleanup(func() {
		StopControlPlaneGRPC()
		clusterRoleMu.Lock()
		clusterRole = prevRole
		clusterRoleMu.Unlock()
		dataDir = prevDir
	})
	return t.TempDir()
}

// TestChaos72_EnableControlPlaneDoesNotDeadlockOnPromotion is the regression
// guard: with HA reporting Enabled — the standby condition every promotion path
// runs under — enableControlPlane must reach a DECISION rather than hang.
func TestChaos72_EnableControlPlaneDoesNotDeadlockOnPromotion(t *testing.T) {
	withHARoleForTest(t, "standby")
	clusterDB := chaos72Isolate(t)

	got := make(chan error, 1)
	go func() { got <- enableControlPlane(chaos72PromotionAddr, "", "", "", clusterDB) }()

	select {
	case err := <-got:
		if err == nil {
			t.Fatalf("enableControlPlane bound %q — the address was supposed to be unresolvable, so this test is no longer side-effect free", chaos72PromotionAddr)
		}
		t.Logf("returned a decision rather than hanging: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("enableControlPlane did not return within 30s while HA reported Enabled — the promotion path is deadlocked on clusterRoleMu again, and the wedged goroutine holds the WRITE lock, so diagnostics, health, the PAC mutation gate and the support bundle are all blocked behind it")
	}
}

// TestChaos72_ClusterRoleReadersStayLiveAfterPromotion is the blast-radius
// assertion. A failed promotion is bad; a promotion that also takes every
// health and diagnostic surface with it is why this is critical. After the
// attempt, clusterRoleMu must still be acquirable by readers.
func TestChaos72_ClusterRoleReadersStayLiveAfterPromotion(t *testing.T) {
	withHARoleForTest(t, "standby")
	clusterDB := chaos72Isolate(t)

	attempted := make(chan struct{})
	go func() {
		defer close(attempted)
		_ = enableControlPlane(chaos72PromotionAddr, "", "", "", clusterDB)
	}()
	select {
	case <-attempted:
	case <-time.After(30 * time.Second):
		t.Fatal("the promotion attempt never returned; clusterRoleMu is held by a wedged goroutine")
	}

	// buildCPAddressList is the real reader whose blocking was the symptom.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		_ = buildCPAddressList()
	}()
	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("clusterRoleMu is still held after the promotion attempt returned — every reader (diagnostics, /healthz, the PAC mutation gate, the support bundle) is wedged")
	}
}
