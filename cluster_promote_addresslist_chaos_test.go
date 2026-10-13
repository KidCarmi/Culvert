package main

// cluster_promote_addresslist_chaos_test.go — CHAOS-72b/72c: the CP address
// list a promoted leader publishes, and what a data plane does with a shrinking
// one.
//
// Both came out of the Codex review of PR #1618, and both are consequences of
// CHAOS-72 having made HA promotion complete at all: the ordering below was
// always wrong, but before the deadlock was fixed the promotion path never
// reached the publish.
//
//   72b — buildCPAddressList composes the list from the HA peer address and
//         clusterRole.grpcAddr, and grpcAddr is assigned only AFTER the
//         listener is up. The first snapshot therefore names the PEER — for a
//         promoting standby, the leader that just died — and not the node
//         taking over.
//   72c — updateDPAddresses REPLACED c.addrs without re-resolving activeIdx,
//         which indexes it. A shrinking list left the index past the end, and
//         reconnectActive (the certificate-renewal redial) indexes it directly.

import (
	"testing"
)

// dpAddrState snapshots the client's address list and active index UNDER its
// mutex. The fields are written by updateDPAddresses while holding c.mu, and a
// background loop left over from an earlier test in this binary could still
// reach updateDPAddresses through the activeDPClient global, so an
// unsynchronised read here would be a real -race finding rather than a
// theoretical one.
func dpAddrState(c *DataPlaneClient) ([]string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.addrs...), c.activeIdx
}

// TestChaos72c_ShrinkingAddressListDoesNotStrandTheIndex is the regression test
// for the panic. The pre-fix sequence — two configured CPs, one failover, then a
// one-element list from a promoting leader — left activeIdx=1 against a
// one-element slice, and the next redial died with "index out of range [1] with
// length 1" on an unattended cert-renewal path.
func TestChaos72c_ShrinkingAddressListDoesNotStrandTheIndex(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos72c",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1, // where one failover leaves it
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	// The authoritative list shrinks and drops the address in use.
	updateDPAddresses([]string{"cp1:50051"})

	addrs, idx := dpAddrState(c)
	if idx < 0 || idx >= len(addrs) {
		t.Fatalf("activeIdx=%d is out of range for %d address(es) — reconnectActive indexes this directly and will panic on the cert-renewal redial", idx, len(addrs))
	}

	// The real crash site. connect() will fail to dial, which is fine and
	// expected; what must not happen is a panic before it gets there.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("reconnectActive panicked after the address list shrank: %v", r)
		}
	}()
	_ = c.reconnectActive()
	if c.conn != nil {
		_ = c.conn.Close()
	}
}

// TestChaos72c_ActiveAddressIsTrackedByValueNotIndex pins the stronger property
// the fix provides. Clamping the index into range would also stop the panic,
// but it would silently re-point activeIdx at a DIFFERENT control plane than
// the one c.conn actually holds — so the invariant "activeIdx names the address
// this client is connected to" has to survive a reorder, not just a shrink.
func TestChaos72c_ActiveAddressIsTrackedByValueNotIndex(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos72c",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1, // connected to cp2
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	// Same members, different order — exactly what a promotion produces when
	// the new leader's own address is appended after the peer's.
	updateDPAddresses([]string{"cp2:50051", "cp1:50051"})

	addrs, idx := dpAddrState(c)
	if got := addrs[idx]; got != "cp2:50051" {
		t.Errorf("activeIdx now names %q, want the address the connection actually holds (%q) — a reorder silently re-pointed the client at a different CP", got, "cp2:50051")
	}
}

// TestChaos72c_DroppedActiveAddressFallsBackToAListedOne covers the honest case:
// when the CP says the address in use is no longer a member, the client must
// land on a listed address rather than keep an index it cannot justify.
func TestChaos72c_DroppedActiveAddressFallsBackToAListedOne(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos72c",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1,
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	updateDPAddresses([]string{"cp3:50051", "cp4:50051"})

	addrs, idx := dpAddrState(c)
	if idx != 0 {
		t.Errorf("activeIdx=%d after the active address was dropped, want 0", idx)
	}
	if got := addrs[idx]; got != "cp3:50051" {
		t.Errorf("activeIdx names %q, want the first listed member %q", got, "cp3:50051")
	}
}

// TestChaos72c_EmptyListIsIgnored pins the existing guard that an empty
// CPAddresses (every non-HA snapshot carries one) must not wipe a DP's
// configured addresses.
func TestChaos72c_EmptyListIsIgnored(t *testing.T) {
	c := &DataPlaneClient{
		nodeID:    "dp-chaos72c",
		addrs:     []string{"cp1:50051", "cp2:50051"},
		activeIdx: 1,
	}
	prev := activeDPClient.Load()
	activeDPClient.Store(c)
	t.Cleanup(func() { activeDPClient.Store(prev) })

	updateDPAddresses(nil)

	addrs, idx := dpAddrState(c)
	if len(addrs) != 2 || idx != 1 {
		t.Errorf("an empty list changed the client state: addrs=%v activeIdx=%d", addrs, idx)
	}
}

// TestChaos72b_PromotingLeaderPublishesAListNamingItself is the 72b regression
// test, asserted at the level the defect lives: the list that
// buildCPAddressList produces BEFORE clusterRole.grpcAddr is committed names
// only the peer, and the list it produces AFTER names this node too. The fix in
// enableControlPlane is to publish the second one; this test is what makes that
// difference visible and keeps it from silently regressing.
func TestChaos72b_PromotingLeaderPublishesAListNamingItself(t *testing.T) {
	const (
		deadLeader = "10.0.0.1:50051"
		promoted   = "10.0.0.2:50051"
	)
	withHARoleForTest(t, "standby")
	globalHA.mu.Lock()
	prevPeer := globalHA.peerAddr
	globalHA.peerAddr = deadLeader
	globalHA.mu.Unlock()
	t.Cleanup(func() {
		globalHA.mu.Lock()
		globalHA.peerAddr = prevPeer
		globalHA.mu.Unlock()
	})

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
		t.Fatalf("pre-commit list = %v, want just the peer %q — this test's premise about the ordering is stale", before, deadLeader)
	}

	// Commit the role fields, as enableControlPlane does once the listener is up.
	clusterRoleMu.Lock()
	clusterRole.grpcAddr = promoted
	clusterRoleMu.Unlock()

	after := buildCPAddressList()
	if slicesEqual(before, after) {
		t.Fatal("committing the role did not change the address list, so there would be nothing to republish")
	}
	var names bool
	for _, a := range after {
		if a == promoted {
			names = true
		}
	}
	if !names {
		t.Errorf("post-commit list = %v, which does not name the promoted node %q — a DP applying it would be left with only the dead leader", after, promoted)
	}
}
