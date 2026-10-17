package main

// ha_topology.go — CHAOS-71: the published CP address list is a CONSEQUENCE of
// HA state, not something each caller remembers to refresh.
//
// buildCPAddressList derives the Data Planes' failover list from the HA role
// and peer address plus this node's advertised gRPC address. Codex's review of
// #1556 found a recovered persisted leader publishing a list with no standby
// address: its delayed bind published BEFORE onActivated resumed HA, and
// nothing republished after. Fixing that call order would leave every other
// transition (enable, standby entry, promote, self-fence, resume) to the same
// discipline, so instead the two fields the list derives from — role and peer —
// have ONE writer, setTopologyLocked, and that writer republishes.
// TestChaos71_Wall_HATopologyHasOneWriter pins the single writer;
// TestChaos71_HATransitionsRepublishTheCPAddressList drives every transition.

import "sync/atomic"

// haTopologyOverride, when set (tests only), names the HAState whose topology
// buildCPAddressList reads and whose transitions republish — so a gate can
// drive a private HAState through real transitions without mutating globalHA.
var haTopologyOverride atomic.Pointer[HAState]

// Bounded transition labels for setTopologyLocked.
const (
	haTransitionEnable    = "ha_enable"
	haTransitionResume    = "ha_resume"
	haTransitionStandby   = "ha_standby_entry"
	haTransitionPromote   = "ha_promote"
	haTransitionSelfFence = "ha_self_fence"
)

// haTopologySource is the HAState the CP address list derives from.
func haTopologySource() *HAState {
	if h := haTopologyOverride.Load(); h != nil {
		return h
	}
	return globalHA
}

// cpAddressListFor is the pure derivation buildCPAddressList applies:
// [peer, this node] when HA is enabled (this node only when it advertises an
// address distinct from the peer), nil otherwise.
func cpAddressListFor(haEnabled bool, peer, myAddr string) []string {
	if !haEnabled {
		return nil // no HA = no address list needed
	}
	addrs := []string{peer}
	if myAddr != "" && myAddr != peer {
		addrs = append(addrs, myAddr)
	}
	return addrs
}

// setTopologyLocked is the ONE writer of h.role and h.peerAddr. Caller holds
// h.mu (write). transition is a bounded label (haTransition*) naming the
// caller, carried into the pending state if the republish fails. When the topology source actually changes, the CP address
// list is republished right here, from the NEW values — under h.mu, so no
// other transition can interleave, and without re-reading h (the derivation
// takes the values as arguments; Status() would self-deadlock).
//
// Lock order: h.mu → clusterRoleMu (clusterRoleSnapshot) → ConfigStore.mu.
// Neither of the inner locks is ever held while taking h.mu, and nothing on
// the publish path re-enters h.mu (the derivation takes its inputs as
// arguments). Holding h.mu here is also what orders this against activation:
// a concurrent first publish derives through Status(), so it either runs
// before this write (and the reconcile below corrects it) or after (and sees
// the new topology) — never between.
//
// Cost under h.mu: UpdateCPAddressesFrom returns before validating when the
// derived list is unchanged, so promote and self-fence (same peer) commit
// nothing; the full validate/commit runs only when the list actually changes
// (enable with a new peer, standby entry against a new leader, a resume after
// a delayed bind) — boot- and admin-rate events.
func (h *HAState) setTopologyLocked(role, peer, transition string) {
	if h.role == role && h.peerAddr == peer {
		return
	}
	h.role, h.peerAddr = role, peer
	if h != haTopologySource() {
		return
	}
	enabled := role != ""
	// A no-op unless this node is an active Control Plane (the store has an
	// address source). A failure is NEVER dropped and NEVER rolls the
	// transition back (Codex review of #1556): rejectPublish logs and alerts
	// it, and publishOwnedCPAddresses latches the `cp_address_list` pending
	// state and retries from the live source until it publishes. Why no
	// transition — authority-gaining included — is refused over it is the
	// ADR-0005 reasoning in cp_addr_publish.go's header.
	_ = globalConfigStore.reconcileCPAddressesFrom(transition, func() []string {
		return cpAddressListFor(enabled, peer, clusterRoleSnapshot().grpcAddr)
	})
}
