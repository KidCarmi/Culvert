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
// have ONE writer, setTopologyLocked, which records a republish that its
// caller runs (republishTopology) once HAState.mu is released.
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
// caller, carried into the pending state if the republish fails.
//
// It only RECORDS the change: when the topology source actually changes it
// marks a republish due (topologyRepublish). The republish itself runs in
// republishTopology, which every caller invokes AFTER releasing h.mu — and,
// on an authority-gaining transition, after the keepalive has started. A
// publish marshals and commits a snapshot of up to snapshotWireBudget (and
// records an O(N) blocklist delta); run under h.mu it could outlast a
// short-TTL lease's trusted window before the keepalive could start or a
// renewal could take h.mu, so the first renewal would find the lease expired
// and self-fence (Codex review of #1556). No ConfigStore publish or commit
// runs while h.mu is held, and lease renewal never waits on publication
// (TestChaos71_Wall_NoSnapshotPublishUnderTheHALock).
func (h *HAState) setTopologyLocked(role, peer, transition string) {
	if h.role == role && h.peerAddr == peer {
		return
	}
	h.role, h.peerAddr = role, peer
	h.syncFenceEpochLocked() // the stamp derives from the role: the role-less floor ends here
	if h != haTopologySource() {
		return
	}
	h.topologyRepublish = transition // the latest change wins: the republish derives from live state
}

// republishTopology runs the republish setTopologyLocked marked due, if any.
// The caller must NOT hold h.mu.
//
// It derives the list from the LIVE topology (buildCPAddressList reads
// Status()), on every compare-and-swap attempt, so a transition that lands
// before this runs is published too, and an activation publish built from
// the older topology loses its commit race and rebuilds. A no-op unless this
// node is an active Control Plane (the store has an address source). A
// failure is NEVER dropped and NEVER rolls the transition back (Codex review
// of #1556): rejectPublish logs it, and publishOwnedCPAddresses latches the
// `cp_address_list` pending state, pages once per episode and retries from
// the live source until it publishes. Why no transition — authority-gaining
// included — is refused over it is the ADR-0005 reasoning in
// cp_addr_publish.go's header. It can be a hint and nothing more because the
// fencing epoch never rides in this commit: an authority-gaining transition
// has already committed the snapshot stamped with its new epoch
// (ha_epoch_commit.go) before it reaches here, so a rejected list leaves the
// fleet on the right epoch.
//
// Lock order: the publish takes clusterRoleMu (clusterRoleSnapshot) and
// ConfigStore.mu, and h.mu only through Status(), never while holding the
// others.
func (h *HAState) republishTopology() {
	h.mu.Lock()
	transition := h.topologyRepublish
	h.topologyRepublish = ""
	h.mu.Unlock()
	if transition == "" {
		return
	}
	_ = globalConfigStore.reconcileCPAddressesFrom(transition, buildCPAddressList)
}
