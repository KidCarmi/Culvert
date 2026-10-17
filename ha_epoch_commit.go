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
//  2. commitGrant commits the COMMITTED snapshot, content unchanged,
//     restamped with E (ConfigStore.RestampFenceEpoch). Its size is the prior
//     committed size plus the epoch digits, so it fits whenever the prior
//     snapshot did. During this commit the stamp mirror already reads E, so a
//     concurrent publish cannot commit the old epoch after it. "Nothing
//     published yet" is not success (Codex P1 4302217586 on #1645): a Control
//     Plane whose initial publish was rejected has no snapshot to carry E, so
//     the transition is refused (step 4). The one exception is a promote,
//     whose Control Plane activation (onPromote) makes the first publish,
//     stamped E by the mirror: it is preflighted before the listener starts.
//  3. exposeGrantLocked re-verifies, atomically with every commit, that the
//     committed snapshot carries E — the rule itself, whatever the path to
//     it — and only then does leaseEpoch become E: the heartbeat, issuance,
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

// errNoSnapshotToRestamp: the store has published nothing, so no commit can
// carry a new fencing epoch (RestampFenceEpoch).
var errNoSnapshotToRestamp = errors.New("no committed config snapshot to carry the new fencing epoch (the initial publish was rejected or has not run)")

// errEpochNotCommitted: at exposure, the committed snapshot does not carry
// the grant's epoch.
var errEpochNotCommitted = errors.New("no committed config snapshot carries the new fencing epoch")

// haPreflightFirstPublish runs the commit-time gates over the first publish a
// promote's Control Plane activation will make (CurrentConfigSnapshot,
// stamped with the in-flight epoch), committing nothing. Test seam.
var haPreflightFirstPublish = func() error { return preflightFirstPublish(CurrentConfigSnapshot()) }

// commitGrant is the first half of every install: it commits the snapshot
// stamped with the staged grant's epoch and leaves that epoch UNADVERTISED,
// with the stamp mirror on it, until exposeGrantLocked installs it or
// abandonGrantLocked drops it. Returns the epoch to expose (0: nothing to
// expose). A refusal is paged, and the staged grant is abandoned. A store
// that has published nothing is a refusal, except for a promote whose
// activation's first publish passes the preflight; that publish, like every
// path here, is verified to have committed by exposeGrantLocked.
//
// The caller must NOT hold h.mu, and should have started the keepalive on the
// staged grant: the commit marshals a snapshot of up to snapshotWireBudget,
// and nothing that long may run under h.mu, where it would block lease
// renewal (Codex review of #1556; TestChaos71_Wall_NoSnapshotPublishUnderTheHALock).
// h.mu is taken only to read the grant and set the stamp, and afterwards for
// the compare-only keep-or-revert decision.
func (h *HAState) commitGrant(transition string) (int64, error) {
	h.mu.Lock()
	e := h.grantEpoch
	switch {
	case h.lease == nil:
		h.mu.Unlock()
		return 0, nil // legacy mode: no fencing epoch
	case e == 0:
		installed := h.leaseEpoch != 0
		h.mu.Unlock()
		if installed {
			return 0, nil // a concurrent transition already installed this process's grant
		}
		return 0, errNoStagedGrant
	}
	stamping := h == haTopologySource() // otherwise this HAState's epoch stamps no snapshot
	if stamping {
		h.stampEpoch = e
		h.syncFenceEpochLocked()
	}
	h.mu.Unlock()
	if !stamping {
		return e, nil
	}
	err := haRestampFenceEpoch() // the marshal and commit: outside h.mu
	if errors.Is(err, errNoSnapshotToRestamp) && transition == haTransitionPromote {
		// A promote's first publish is its Control Plane activation's, inside
		// onPromote, and the mirror stamps it e. Refuse NOW if it would not
		// pass the commit-time gates, before the listener exists; whether it
		// committed is verified at exposure (exposeGrantLocked).
		err = haPreflightFirstPublish()
	}
	if err == nil {
		return e, nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// Keep or revert, atomically with every commit (a compare under the store
	// lock, no marshal): a concurrent publish that committed e already made it
	// distributable, and the install proceeds.
	if h.stampEpoch == e && haKeepEpochStampIfCommitted(e, func() {
		h.stampEpoch = 0
		h.syncFenceEpochLocked()
	}) {
		return e, nil
	}
	if h.grantEpoch == e {
		h.pageEpochRefusedLocked(transition, e, err)
	}
	h.abandonGrantLocked()
	return 0, err
}

// errGrantLost: the staged grant was lost (superseded, expired, or no longer
// confirmed) between its commit and its exposure.
var errGrantLost = errors.New("the fencing-lease grant was lost before its epoch could be installed")

// exposeGrantLocked installs a committed grant's epoch — the ONLY place a
// non-zero epoch reaches leaseEpoch, and so the heartbeat, issuance,
// /healthz and write authority. It re-checks that the grant is still held:
// still staged, since the keepalive drops a grant it loses (superseded, or
// unconfirmed past its validity window). And it re-checks the rule itself:
// a committed snapshot carries e, compared atomically with every commit under
// the store lock (a compare, no marshal). commitGrant's success says a commit
// was made or is to come (a promote's activation publish); only this says it
// landed (Codex P1 4302217586 on #1645). Refused, the stamp mirror reverts in
// the same step, the refusal pages once per episode and the grant is
// abandoned. Write authority itself stays gated on the confirmed window
// (WriteAllowed). Caller holds h.mu (write) and has run commitGrant for e.
func (h *HAState) exposeGrantLocked(transition string, e int64) error {
	if h.lease == nil || e == 0 {
		return nil
	}
	if h.grantEpoch != e {
		h.abandonGrantLocked()
		return errGrantLost
	}
	if h == haTopologySource() && !haKeepEpochStampIfCommitted(e, func() {
		h.stampEpoch = 0
		h.syncFenceEpochLocked()
	}) {
		h.pageEpochRefusedLocked(transition, e, errEpochNotCommitted)
		h.abandonGrantLocked()
		return errEpochNotCommitted
	}
	h.grantEpoch = 0
	h.epochRefused = false // the refusal episode, if any, ended
	h.stampEpoch = 0       // the mirror stays e: setLeaseEpochLocked re-derives it from leaseEpoch
	h.setLeaseEpochLocked(e)
	return nil
}

// abandonGrantLocked drops a staged, unexposed grant (its transition failed
// or was aborted): the stamp mirror returns to the installed grant, and a
// keepalive that renewed only the staged grant stops, so the grant lapses at
// its TTL (ADR-0005 has no Release primitive). Caller holds h.mu (write).
func (h *HAState) abandonGrantLocked() {
	h.grantEpoch = 0
	h.stampEpoch = 0
	h.syncFenceEpochLocked()
	if h.leaseEpoch == 0 && h.leaseStopCh != nil {
		close(h.leaseStopCh)
		h.leaseStopCh = nil
	}
}

// dropStagedGrant is abandonGrantLocked for a caller not holding h.mu.
func (h *HAState) dropStagedGrant() {
	h.mu.Lock()
	h.abandonGrantLocked()
	h.mu.Unlock()
}

// heldEpochLocked is the grant this process holds and the keepalive renews:
// the installed one, else a staged one (renewing it exposes nothing). Caller
// holds h.mu.
func (h *HAState) heldEpochLocked() int64 {
	if h.leaseEpoch != 0 {
		return h.leaseEpoch
	}
	return h.grantEpoch
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
