package main

// cp_addr_publish.go — CHAOS-71: a failed CP address-list republish is never
// silent and never final (Codex review of #1556, P1 4295648192).
//
// Every OWNED republish (an HA transition through republishTopology, the
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
	"slices"
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

// ─── Ownership: one generation for every change of owner ────────────────────
//
// The address list's owner (cpAddrSource, and cpAddrWithdrawal when that
// source is a withdrawal) changes on activation (setCPAddressSource), when a
// terminal exit installs a withdrawal, and when ownership is released or
// superseded. Each such change goes through setCPAddrOwnerLocked, which bumps
// cpAddrOwnerGen. A publish reads the owner ONCE, as a cpAddrOwner carrying
// that generation, and commits only while the generation is unchanged
// (updateCPAddressesBound): a source captured before an ownership change can
// never commit after it. Three Codex findings on #1556 were instances of one
// class — a captured source or ownership bit outliving its owner — and the
// generation closes the class rather than each window
// (TestChaos71_Wall_AddressSourceReadsCarryTheOwnerGeneration).

// errCPAddrOwnerChanged: the ownership generation a publish was bound to
// changed before it committed. Nothing was committed; the caller rebuilds
// from the current owner or stops (updateOwnedCPAddresses).
var errCPAddrOwnerChanged = errors.New("CP address list ownership changed before the publish committed")

// errCPAddrOwnerReleased: a bound publish found nothing owning the list any
// more. Not a failure: nothing is owned, so nothing is pending.
var errCPAddrOwnerReleased = errors.New("CP address list ownership released before the publish committed")

// cpAddrOwner is ONE read of the address-list ownership: the source, the
// withdrawal it serves (if any) and the generation they belong to. The source
// is reachable only through its methods, so whatever builds from it carries
// the generation.
type cpAddrOwner struct {
	src        func() []string
	withdrawal string
	gen        uint64
}

func (o cpAddrOwner) owned() bool { return o.src != nil }

// builder is what a publish bound to o builds from: the caller's build, or
// o's own source when the caller gave none — and always o's source while a
// withdrawal owns the list, so no builder that may still name the Control
// Plane being withdrawn is ever committed over it.
func (o cpAddrOwner) builder(build func() []string) func() []string {
	if build == nil || o.withdrawal != "" {
		return o.src
	}
	return build
}

// without derives o's list without addr (a withdrawal source).
func (o cpAddrOwner) without(addr string) func() []string {
	return cpAddrSourceWithout(o.src, addr)
}

// cpAddrOwnerLocked reads the owner. The ONLY read of cpAddrSource. Caller
// holds s.mu (read or write).
func (s *ConfigStore) cpAddrOwnerLocked() cpAddrOwner {
	return cpAddrOwner{src: s.cpAddrSource, withdrawal: s.cpAddrWithdrawal, gen: s.cpAddrOwnerGen}
}

// currentCPAddrOwner reads the owner under s.mu.
func (s *ConfigStore) currentCPAddrOwner() cpAddrOwner {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cpAddrOwnerLocked()
}

// setCPAddrOwnerLocked is the ONE writer of the owner: it installs (src,
// withdrawal) and bumps the generation, so every publish bound to the
// previous owner stops at its commit. Caller holds s.mu (write).
func (s *ConfigStore) setCPAddrOwnerLocked(src func() []string, withdrawal string) {
	s.cpAddrSource, s.cpAddrWithdrawal = src, withdrawal
	s.cpAddrOwnerGen++
}

// updateOwnedCPAddresses commits own.builder(build) bound to own. When the
// owner changes first, the caller's build (chosen for the previous owner) is
// dropped and the publish rebuilds from the NEW owner's source; when nothing
// owns the list any more it stops with errCPAddrOwnerReleased.
func (s *ConfigStore) updateOwnedCPAddresses(own cpAddrOwner, build func() []string) (bool, error) {
	for attempt := 0; attempt < cpAddrMergeAttempts; attempt++ {
		b := own.builder(build)
		if b == nil {
			return false, errCPAddrOwnerReleased
		}
		changed, err := s.updateCPAddressesBound(own, b)
		if !errors.Is(err, errCPAddrOwnerChanged) {
			return changed, err
		}
		own, build = s.currentCPAddrOwner(), nil
	}
	return false, fmt.Errorf("%w %d times in a row", errCPAddrCommitRace, cpAddrMergeAttempts)
}

// publishOwnedCPAddresses is publishOwnedCPAddressesAs bound to the owner
// current at the call. For callers whose build does not come from the store
// (the activation and HA builders); a caller that read the owner itself
// passes that read to publishOwnedCPAddressesAs.
func (s *ConfigStore) publishOwnedCPAddresses(trigger string, build func() []string) (bool, error) {
	return s.publishOwnedCPAddressesAs(trigger, s.currentCPAddrOwner(), build)
}

// publishOwnedCPAddressesAs is the ONE path an owned republish takes: publish
// own.builder(build), bound to own, and record the outcome (pending latch +
// retry on failure, clear on success). trigger is a bounded label naming the
// caller. A publish whose owner was released before it committed records
// nothing: the release ended the episode.
func (s *ConfigStore) publishOwnedCPAddressesAs(trigger string, own cpAddrOwner, build func() []string) (bool, error) {
	gen := s.cpAddrPublishGen()
	changed, err := s.updateOwnedCPAddresses(own, build)
	if errors.Is(err, errCPAddrOwnerReleased) {
		return false, nil
	}
	note := s.noteCPAddrPublish(trigger, err, gen)
	if note.page {
		s.pageCPAddrRejection(note.episode, err)
	}
	if note.startRetry {
		go s.retryCPAddrPublish(cpAddrRetryCtx())
	}
	if err == nil {
		s.completeCPAddressWithdrawal()
	}
	return changed, err
}

// ─── Withdrawal: a terminal exit keeps ownership until the list drops it ─────
//
// A Control Plane listener supervisor that exits TERMINALLY (a panic, a role
// conflict) after the fleet was told this node is a Control Plane must take
// its address out of the list Data Planes fail over to. That withdrawal is an
// ordinary owned publish, so it can be rejected at commit or lose every
// optimistic commit attempt like any other. The first draft then released
// ownership regardless — and with no source the retry loop exits clean, so the
// fleet kept a dead CP address that nothing ever reconciled, in a process that
// survived the panic (Codex review of #1556).
//
// So the terminal exit decides from the COMMITTED list whether the node is
// advertised (a supervisor flag set by its own activation publish missed an
// HA transition's republish of the node: Codex review of #1556), and if it
// is, turns the source into a WITHDRAWAL source (the live list without this
// node) instead of dropping it: a rejected withdrawal is
// pending, paged once per episode and retried by the same loop as every other
// owned republish, and ownership is released only once the committed list no
// longer names the node. A new owner (setCPAddressSource) ends the withdrawal.

// cpAddrWithdrawalTrigger is the bounded trigger label of a withdrawal publish.
const cpAddrWithdrawalTrigger = "cp_withdrawal"

// errCPAddrWithdrawalInterrupted latches a withdrawal that is due but whose
// publish never recorded an outcome (interrupted, e.g. by a contained panic,
// or never started), so the retry loop owns it rather than nothing.
var errCPAddrWithdrawalInterrupted = errors.New("CP address list withdrawal has not committed and no publish recorded its outcome")

// withdrawCPAddress withdraws addr from the owned CP address list when the
// committed list names it, publishing the list without it. A failure is
// recorded and retried (publishOwnedCPAddresses); ownership stays until a
// publish commits. A no-op when nothing is owned or the committed list does
// not name addr.
func (s *ConfigStore) withdrawCPAddress(addr string) (changed bool, err error) {
	own, ok := s.beginCPAddressWithdrawal(addr)
	if !ok {
		return false, nil
	}
	return s.publishOwnedCPAddressesAs(cpAddrWithdrawalTrigger, own, nil)
}

// beginCPAddressWithdrawal decides from the COMMITTED list — the one Data
// Planes hold, whichever owned path (activation, HA republish, reconcile)
// committed it — whether addr needs withdrawing, and if so replaces the owned
// source with one that derives the same live list without addr. The pending
// episode (if any) is kept: the withdrawal is the same list, one node shorter,
// so an open episode stays paged once. Returns the withdrawal owner (read
// under the same lock that installed it), or ok=false when there is nothing
// to withdraw.
func (s *ConfigStore) beginCPAddressWithdrawal(addr string) (own cpAddrOwner, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.cpAddrOwnerLocked().owned() || !s.cpAddrNamesLocked(addr) {
		return cpAddrOwner{}, false
	}
	s.beginCPAddressWithdrawalLocked(addr)
	return s.cpAddrOwnerLocked(), true
}

// beginCPAddressWithdrawalLocked installs the withdrawal of addr (idempotent).
// Caller holds s.mu and has checked the list is owned.
func (s *ConfigStore) beginCPAddressWithdrawalLocked(addr string) {
	own := s.cpAddrOwnerLocked()
	if own.withdrawal == addr {
		return
	}
	s.setCPAddrOwnerLocked(own.without(addr), addr)
}

// cpAddrSourceWithout derives from's list without addr. It copies: a source
// may hand back a slice it shares.
func cpAddrSourceWithout(from func() []string, addr string) func() []string {
	return func() []string {
		var out []string
		for _, a := range from() {
			if a != addr {
				out = append(out, a)
			}
		}
		return out
	}
}

// cpAddrNamesLocked reports whether the list THIS store committed names addr.
// published is set by commitLocked, the one commit path every kind takes; a
// snapshot seeded from an HA peer (seedReplicatedSnapshot) is not this store's
// commit and is never carried into one (an unpublished store's full publish
// carries its caller's list), so it does not count. Caller holds s.mu.
func (s *ConfigStore) cpAddrNamesLocked(addr string) bool {
	return addr != "" && s.published && slices.Contains(s.snap.CPAddresses, addr)
}

// cpAddrWithdrawnLocked reports whether the committed list no longer names the
// address being withdrawn. Caller holds s.mu.
func (s *ConfigStore) cpAddrWithdrawnLocked() bool {
	return !s.cpAddrNamesLocked(s.cpAddrWithdrawal)
}

// completeCPAddressWithdrawal releases ownership once a withdrawal has
// committed. A no-op when no withdrawal owns the list or it has not committed
// yet. Called after every successful owned publish.
func (s *ConfigStore) completeCPAddressWithdrawal() {
	s.mu.Lock()
	addr := s.cpAddrWithdrawal
	if addr == "" || !s.cpAddrWithdrawnLocked() {
		s.mu.Unlock()
		return
	}
	s.setCPAddrOwnerLocked(nil, "")
	s.mu.Unlock()
	s.resetCPAddrPublish()
	logger.Printf("ControlPlane: withdrew %q from the fleet's CP address list; address-list ownership released", sanitizeLog(addr))
}

// releaseCPAddressSourceAfterWithdrawal is a terminal exit's ownership step
// for the Control Plane at addr. It decides from the COMMITTED list, not from
// whether a withdrawal was started: if the list names addr (or a withdrawal
// in progress has not committed), ownership is KEPT as a withdrawal of addr —
// installed here if no publish path installed it — and the retry loop
// releases it when the withdrawal commits; a withdrawal no publish recorded is
// latched pending here, so a retry owns it. Otherwise ownership is released at
// once. Reports whether ownership was kept.
func (s *ConfigStore) releaseCPAddressSourceAfterWithdrawal(addr string) (kept bool) {
	s.mu.Lock()
	named := s.cpAddrOwnerLocked().owned() && s.cpAddrNamesLocked(addr)
	inFlight := s.cpAddrWithdrawal != "" && !s.cpAddrWithdrawnLocked()
	if !named && !inFlight {
		s.setCPAddrOwnerLocked(nil, "")
		s.mu.Unlock()
		s.resetCPAddrPublish()
		return false
	}
	if named {
		s.beginCPAddressWithdrawalLocked(addr)
	}
	withdrawing := s.cpAddrWithdrawal
	s.mu.Unlock()
	if !s.cpAddrPublishSnapshot().pending {
		note := s.noteCPAddrPublish(cpAddrWithdrawalTrigger, errCPAddrWithdrawalInterrupted, s.cpAddrPublishGen())
		if note.page {
			s.pageCPAddrRejection(note.episode, errCPAddrWithdrawalInterrupted)
		}
		if note.startRetry {
			go s.retryCPAddrPublish(cpAddrRetryCtx())
		}
	}
	logWarnf("ControlPlane: the fleet's CP address list still names %q — keeping address-list ownership until the withdrawal commits (retrying)", sanitizeLog(withdrawing))
	return true
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
		gen, published, err := s.retryCPAddrPublishOnce()
		if note := s.noteCPAddrPublish("retry", err, gen); note.page {
			s.pageCPAddrRejection(note.episode, err)
		}
		if published {
			s.completeCPAddressWithdrawal() // a committed withdrawal ends ownership, and with it the episode
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

// retryCPAddrPublishOnce is one retry attempt: republish from the CURRENT
// owner's source, bound to it. It returns the pending-state generation to note
// the outcome against, whether a bound publish completed, and its error. With
// nothing owned — before the attempt or released during it — nothing is
// pending: a clean outcome at the current generation.
func (s *ConfigStore) retryCPAddrPublishOnce() (gen uint64, published bool, err error) {
	own := s.currentCPAddrOwner()
	gen = s.cpAddrPublishGen()
	if !own.owned() {
		return s.cpAddrPublishGen(), false, nil
	}
	_, err = s.updateOwnedCPAddresses(own, nil)
	if errors.Is(err, errCPAddrOwnerReleased) {
		return s.cpAddrPublishGen(), false, nil
	}
	return gen, err == nil, err
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
		msg := "Not an active Control Plane (no CP address list to publish)"
		if s.currentCPAddrOwner().owned() {
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
