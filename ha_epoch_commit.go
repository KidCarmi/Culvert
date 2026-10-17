package main

// ha_epoch_commit.go — CHAOS-71: a fencing epoch is advertised only once a
// snapshot stamped with it has committed (Codex P1 4299814297 on #1556).
//
// Every authority-gaining HA transition (enable, resume, promote, lease
// recovery) acquires a grant with a new epoch E. Data Planes ratchet to the
// highest epoch they hear — on a heartbeat, an issuance response or a
// snapshot — and reject any snapshot stamped below it. So E must never reach
// them before a committed snapshot carries it: a node that advertised E while
// its committed snapshot kept the old epoch would freeze every existing DP on
// stale policy and leave fresh DPs unable to initialize. That is what
// happened when the restamp to E rode in the SAME commit as the transition's
// new CP address list and that commit was rejected (the added HA addresses
// pushed the snapshot past snapshotWireBudget).
//
// The industry-standard fencing order, which this file implements:
//
//  1. acquireLeaseAttempt only STAGES the grant (grantEpoch). Nothing reads it
//     as the node's epoch, and it confers no write authority.
//  2. installGrantLocked commits the COMMITTED snapshot, content unchanged,
//     restamped with E (ConfigStore.RestampFenceEpoch). Its size is the prior
//     committed size plus the epoch digits, so it fits whenever the prior
//     snapshot did. During this commit the stamp mirror already reads E, so a
//     concurrent publish cannot commit the old epoch after it.
//  3. Only on success does leaseEpoch become E: the heartbeat, issuance,
//     /healthz, keepalive and write authority follow. The caller then takes
//     its role, and the topology writer publishes the new address list as an
//     ordinary owned address publish — latched, retried and paged once per
//     episode on its own. If the list does not fit, that is a stale failover
//     hint; the node still leads with correct fencing.
//  4. On failure (the base itself no longer fits, or the commit race was lost
//     every attempt) E is never advertised, the stamp mirror reverts, and the
//     transition fails closed on LEADERSHIP, not on fencing: enable errors
//     with no role, promote stays standby, lease recovery stays a read-only
//     leader and retries, and a boot resume takes the ADR-0005 S2 read-only
//     leader stance (role kept, no write authority, issuance refused). The
//     refusal pages config_snapshot_rejected once per episode. The staged
//     grant is left to its TTL: ADR-0005 has no Release primitive.
//
// TestChaos71_Wall_FencingEpochIsAdvertisedOnlyAfterItsCommit pins the order.

import (
	"errors"
	"fmt"
)

// haTransitionRecovery labels the CHAOS-55 lease-recovery grant.
const haTransitionRecovery = "ha_lease_recovery"

// errNoStagedGrant: an install with a lease configured but no grant staged.
var errNoStagedGrant = errors.New("no staged fencing-lease grant to install")

// haRestampFenceEpoch commits the committed snapshot restamped with the
// current stamp epoch. Test seam.
var haRestampFenceEpoch = func() error { return globalConfigStore.RestampFenceEpoch() }

// haKeepEpochStampIfCommitted reports whether the committed snapshot carries
// epoch e and, if not, runs revert atomically with every commit. Test seam.
var haKeepEpochStampIfCommitted = func(e int64, revert func()) bool {
	return globalConfigStore.keepEpochStampIfCommitted(e, revert)
}

// installGrantLocked installs the grant acquireLeaseAttempt staged, after a
// snapshot stamped with its epoch has committed — the ONLY place a non-zero
// epoch reaches leaseEpoch. Caller holds h.mu (write). A non-nil error means
// the epoch was NOT installed (and the refusal has been paged); the caller
// must not take write authority on it. transition is a bounded label.
func (h *HAState) installGrantLocked(transition string) error {
	e := h.grantEpoch
	h.grantEpoch = 0
	if h.lease == nil {
		return nil // legacy mode: no fencing epoch
	}
	if e == 0 {
		if h.leaseEpoch != 0 {
			return nil // a concurrent transition already installed this process's grant
		}
		return errNoStagedGrant
	}
	if err := h.commitEpochStampLocked(e); err != nil {
		h.pageEpochRefusedLocked(transition, e, err)
		return err
	}
	h.epochRefused = false // the refusal episode, if any, ended
	h.setLeaseEpochLocked(e)
	return nil
}

// commitEpochStampLocked commits the snapshot restamped with e. The stamp
// mirror reads e for the duration; on failure it reverts, atomically with
// every commit, unless a concurrent publish already committed e (then e IS
// committed and distributable, and the install proceeds). Caller holds h.mu.
func (h *HAState) commitEpochStampLocked(e int64) error {
	if h != haTopologySource() {
		return nil // this HAState's epoch stamps no snapshot
	}
	h.stampEpoch = e
	h.syncFenceEpochLocked()
	err := haRestampFenceEpoch()
	if err == nil {
		h.stampEpoch = 0 // the mirror stays e: setLeaseEpochLocked re-derives it from leaseEpoch
		return nil
	}
	if haKeepEpochStampIfCommitted(e, func() {
		h.stampEpoch = 0
		h.syncFenceEpochLocked()
	}) {
		h.stampEpoch = 0
		return nil
	}
	return err
}

// pageEpochRefusedLocked logs every refusal and pages the episode's first:
// queued before the webhooks load (a boot resume runs in initCluster), valid
// only while the episode is open. Caller holds h.mu.
func (h *HAState) pageEpochRefusedLocked(transition string, e int64, err error) {
	logger.Printf("HA: CRITICAL — %s refused: the config snapshot could not be committed with the new fencing epoch %d, "+
		"so the epoch is NOT advertised and this node takes no write authority on it: %v", transition, e, err)
	if h.epochRefused {
		return
	}
	h.epochRefused = true
	h.epochRefusedEpisode++
	episode := h.epochRefusedEpisode
	payload := AlertPayload{
		Event:  "config_snapshot_rejected",
		Actor:  "culvert",
		Source: "ha",
		Detail: fmt.Sprintf("HA %s refused: the config snapshot could not be committed with fencing epoch %d (%v) — "+
			"the epoch is not advertised and this node has no write authority; reduce the oversized collection", transition, e, err),
	}
	if !startupAlertsFlushed() {
		deferStartupAlertWhile("config_snapshot_rejected", payload, func() bool { return h.epochRefusedEpisodeOpen(episode) })
		return
	}
	fireAlert("config_snapshot_rejected", payload)
}

// epochRefusedEpisodeOpen reports whether refusal episode ep is still the
// current, unresolved one — the validity test for a queued page.
func (h *HAState) epochRefusedEpisodeOpen(ep uint64) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.epochRefused && h.epochRefusedEpisode == ep
}
