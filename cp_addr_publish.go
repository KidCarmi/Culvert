package main

// cp_addr_publish.go — CHAOS-71: a failed CP address-list republish is never
// silent and never final (Codex review of #1556, P1 4295648192).
//
// Every OWNED republish (an HA transition through setTopologyLocked, the
// reconcile after a full publish, and the retry loop below) goes through
// publishOwnedCPAddresses, which records its outcome. A failure (the list
// would push a near-budget snapshot past snapshotWireBudget, or the commit
// race was lost cpAddrMergeAttempts times) is already logged and alerted by
// rejectPublish; here it additionally:
//
//   - latches the store's "address list pending" state, which the
//     `cp_address_list` operator-contract row reports until it clears; and
//   - starts ONE retry loop that republishes from the live source
//     (buildCPAddressList) with capped backoff until a publish succeeds, the
//     store stops owning the list, or the process shuts down.
//
// The HA transition that triggered it is NEVER rolled back, whichever kind it
// is. Safety transitions (self-fence, standby entry) must not be: fencing is
// the safety property. Authority-gaining transitions (enable, resume, promote)
// are not either, which is the ADR-0005 reading: write authority comes from the
// fence (Acquire-gated promotion, epoch-checked sinks), and the address list is
// only the Data Planes' failover HINT. Refusing leadership over a hint would
// turn a sync-size condition — which already holds every ordinary config
// publish back, and does not clear on its own — into a leaderless cluster that
// retries promotion forever. So the role stands, the publish is pending and
// loud, and the retry clears it the moment the condition does.

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// errCPAddrCommitRace is UpdateCPAddressesFrom's "lost the commit race every
// attempt" outcome — transient (something is publishing in a tight loop), as
// opposed to a commit-time gate rejection.
var errCPAddrCommitRace = errors.New("CP address list publish lost the commit race")

// cpAddrPublishState is a store's pending-republish record. The zero value is
// "current". Guarded by mu (its own lock: never held while taking s.mu).
type cpAddrPublishState struct {
	pending  bool
	since    time.Time
	trigger  string // bounded: the transition/caller whose publish failed first
	reason   string // bounded class: publish_rejected | commit_race
	attempts int    // failed attempts in the current episode
	retrying bool   // a retry loop owns the episode
	// gen is bumped by EVERY failure latch. A publish captures it before it
	// starts and may clear the pending state only if it is unchanged when it
	// finishes: a success computed before a newer failure (topology A
	// committed while topology B's publish failed) must not erase B's latch
	// (Codex review of #1556). Never reset.
	gen uint64

	// The rest of the address-rejection latch lives HERE, under the same
	// generation guard, and is written only by noteCPAddrPublish and
	// resetCPAddrPublish (TestChaos71_Wall_AddressRejectionLatchHasOneWriter).
	// It used to sit on ConfigStore under s.mu, where an up-to-date check or a
	// commit decided before a newer failure cleared it unconditionally (Codex
	// review of #1556) — so B paged again, and B's queued startup page was
	// invalidated.
	//
	// rejectPaged: config_snapshot_rejected has been paged (fired or queued)
	// for this episode; rejectEpisode numbers episodes, so a page queued before
	// the webhooks load can test at the flush that its episode is still open.
	// rejectErr/rejectErrTS: the address half of LastPublishError.
	rejectPaged   bool
	rejectEpisode uint64
	rejectErr     string
	rejectErrTS   string
}

// cpAddrNote is noteCPAddrPublish's verdict for its caller.
type cpAddrNote struct {
	startRetry bool   // a failure with no retry loop running: start one
	page       bool   // this failure opened an episode: page it
	episode    uint64 // the episode the page belongs to
}

// cpAddrRetryBackoffMin and cpAddrRetryBackoffMax bound the retry cadence. A
// commit-time rejection clears only when the operator shrinks the config, so
// the ceiling keeps a long episode to one attempt (and one log line) per 30 s.
const (
	cpAddrRetryBackoffMin = time.Second
	cpAddrRetryBackoffMax = 30 * time.Second
)

// cpAddrRetrySleep waits d or until ctx ends (false). Test seam.
var cpAddrRetrySleep = func(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// cpAddrRetryCtx is the lifetime of a retry loop: the process lifecycle
// context, so shutdown ends it. Test seam.
var cpAddrRetryCtx = resolveLifecycleCtx

// cpAddrPublishNow is the clock the pending state is stamped with. Test seam.
var cpAddrPublishNow = time.Now

// publishOwnedCPAddresses is the ONE path an owned republish takes: publish
// build() and record the outcome (pending latch + retry on failure, clear on
// success). trigger is a bounded label naming the caller.
func (s *ConfigStore) publishOwnedCPAddresses(trigger string, build func() []string) (bool, error) {
	gen := s.cpAddrPublishGen()
	changed, err := s.UpdateCPAddressesFrom(build)
	note := s.noteCPAddrPublish(trigger, err, gen)
	if note.page {
		s.pageCPAddrRejection(note.episode, err)
	}
	if note.startRetry {
		go s.retryCPAddrPublish(cpAddrRetryCtx())
	}
	return changed, err
}

// cpAddrPublishGen is the current pending-state generation, captured by a
// publish before it starts.
func (s *ConfigStore) cpAddrPublishGen() uint64 {
	s.addrPubMu.Lock()
	defer s.addrPubMu.Unlock()
	return s.addrPub.gen
}

// noteCPAddrPublish is the SINGLE WRITER of the address-rejection record: it
// records one owned-publish outcome and tells the caller whether to page and
// whether to start the retry loop. startGen is the generation the publish
// captured before it began. A success (or an up-to-date list) ends the episode
// — pending state, page latch and error together — only if no failure has
// latched since (gen unchanged); a stale success leaves a newer episode
// entirely alone. A failure bumps gen, records the error, and opens the
// episode's page latch if it is not open yet (page once per episode).
func (s *ConfigStore) noteCPAddrPublish(trigger string, err error, startGen uint64) cpAddrNote {
	s.addrPubMu.Lock()
	defer s.addrPubMu.Unlock()
	st := &s.addrPub
	if err == nil {
		if st.gen != startGen {
			return cpAddrNote{} // a newer failure latched while this publish ran: not ours to clear
		}
		if st.pending {
			logger.Printf("ControlPlane: CP address list republished after %d failed attempts (pending since %s, first failed on %q)",
				st.attempts, st.since.UTC().Format(time.RFC3339), st.trigger)
		}
		st.pending, st.attempts, st.trigger, st.reason = false, 0, "", ""
		st.rejectPaged, st.rejectErr, st.rejectErrTS = false, "", ""
		return cpAddrNote{}
	}
	st.gen++
	st.rejectErr, st.rejectErrTS = err.Error(), time.Now().UTC().Format(time.RFC3339)
	if !st.pending {
		st.pending, st.since, st.trigger = true, cpAddrPublishNow(), trigger
		logWarnf("ControlPlane: CP address list publish FAILED on %q — Data Planes keep the last committed list until a retry succeeds: %v", trigger, err)
	}
	st.attempts++
	st.reason = "publish_rejected"
	if errors.Is(err, errCPAddrCommitRace) {
		st.reason = "commit_race"
	}
	var note cpAddrNote
	if !st.rejectPaged {
		st.rejectPaged = true
		st.rejectEpisode++
		note.page, note.episode = true, st.rejectEpisode
	}
	if !st.retrying {
		st.retrying = true
		note.startRetry = true
	}
	return note
}

// resetCPAddrPublish ends every episode: ownership was released or replaced.
// The other writer of the record. A running retry loop keeps running (it
// exits on its own once nothing is owned); gen is bumped so an in-flight
// outcome from the old owner cannot touch the new state.
func (s *ConfigStore) resetCPAddrPublish() {
	s.addrPubMu.Lock()
	defer s.addrPubMu.Unlock()
	s.addrPub = cpAddrPublishState{retrying: s.addrPub.retrying, gen: s.addrPub.gen + 1, rejectEpisode: s.addrPub.rejectEpisode}
}

// cpAddrRejectEpisodeOpen reports whether rejection episode ep is still the
// current, paged one — the validity test for a queued page.
func (s *ConfigStore) cpAddrRejectEpisodeOpen(ep uint64) bool {
	s.addrPubMu.Lock()
	defer s.addrPubMu.Unlock()
	return s.addrPub.rejectPaged && s.addrPub.rejectEpisode == ep
}

// pageCPAddrRejection delivers an episode's config_snapshot_rejected page.
// Before the startup flush (a persisted leader's boot republish runs in
// initCluster, before the webhooks load) it queues, valid only while its
// episode is still open; after the flush it fires at once.
func (s *ConfigStore) pageCPAddrRejection(episode uint64, err error) {
	payload := AlertPayload{
		Event:  "config_snapshot_rejected",
		Actor:  "culvert",
		Source: "cluster",
		Detail: "config publish rejected at commit: " + err.Error() + " — the cluster stays on the last valid config; reduce the oversized collection to resume sync",
	}
	if !startupAlertsFlushed() {
		deferStartupAlertWhile("config_snapshot_rejected", payload, func() bool { return s.cpAddrRejectEpisodeOpen(episode) })
		return
	}
	fireAlert("config_snapshot_rejected", payload)
}

// retryCPAddrPublish republishes from the store's live source until the
// pending state clears. The exit decision is taken under addrPubMu, the lock
// a new failure latches under, so a failure that lands while the loop is
// leaving starts a fresh loop rather than being stranded.
func (s *ConfigStore) retryCPAddrPublish(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			logger.Printf("ControlPlane: CP address list retry loop panicked (contained): %v", r)
			s.addrPubMu.Lock()
			s.addrPub.retrying = false
			s.addrPubMu.Unlock()
		}
	}()
	backoff := cpAddrRetryBackoffMin
	for {
		if !cpAddrRetrySleep(ctx, backoff) {
			s.addrPubMu.Lock()
			s.addrPub.retrying = false // shutdown: the pending state stays reported
			s.addrPubMu.Unlock()
			return
		}
		s.mu.RLock()
		src := s.cpAddrSource
		s.mu.RUnlock()
		gen := s.cpAddrPublishGen()
		var err error
		if src != nil {
			_, err = s.UpdateCPAddressesFrom(src)
		} else {
			gen = s.cpAddrPublishGen() // no source: nothing is owned any more, so nothing is pending
		}
		if note := s.noteCPAddrPublish("retry", err, gen); note.page {
			s.pageCPAddrRejection(note.episode, err)
		}

		s.addrPubMu.Lock()
		if !s.addrPub.pending {
			s.addrPub.retrying = false
			s.addrPubMu.Unlock()
			return
		}
		stale := err == nil // this attempt published, but a newer failure latched meanwhile
		s.addrPubMu.Unlock()
		if stale {
			backoff = cpAddrRetryBackoffMin // re-derive from the live source promptly
			continue
		}
		backoff = min(backoff*2, cpAddrRetryBackoffMax)
	}
}

// cpAddrPublishSnapshot returns a copy of the pending-republish record.
func (s *ConfigStore) cpAddrPublishSnapshot() cpAddrPublishState {
	s.addrPubMu.Lock()
	defer s.addrPubMu.Unlock()
	return s.addrPub
}

// checkCPAddressList is the `cp_address_list` operator-contract row: FAIL
// while an owned republish is pending, so a Data Plane failover list that is
// behind the HA topology is never silent.
func checkCPAddressList() OperatorContractCheck {
	s := globalConfigStore
	st := s.cpAddrPublishSnapshot()
	if !st.pending {
		s.mu.RLock()
		owned := s.cpAddrSource != nil
		s.mu.RUnlock()
		msg := "Not an active Control Plane (no CP address list to publish)"
		if owned {
			msg = "Control Plane address list is current"
		}
		return OperatorContractCheck{Code: "cp_address_list", Status: diagOK, Message: msg}
	}
	msg := fmt.Sprintf("Control Plane address list publish pending since %s (%d failed attempts, first failed on %s, reason: %s); Data Planes still hold the last committed list and may not fail over to a changed peer",
		st.since.UTC().Format(time.RFC3339), st.attempts, st.trigger, st.reason)
	action := "The publish is rejected at commit — see LastPublishError and the config_snapshot_rejected alert (usually a config at its cluster-sync size cap). Reduce the oversized collection; the list republishes automatically within 30 s, no restart and no HA change needed."
	status := diagFail
	if st.reason == "commit_race" {
		status = diagWarn
		action = "Config publishes are arriving faster than the address list can commit. It retries automatically; if this persists, look for a client publishing configuration in a tight loop."
	}
	return OperatorContractCheck{Code: "cp_address_list", Status: status, Message: msg, OperatorAction: action}
}
