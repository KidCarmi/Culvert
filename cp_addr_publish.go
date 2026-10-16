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
	changed, err := s.UpdateCPAddressesFrom(build)
	if s.noteCPAddrPublish(trigger, err) {
		go s.retryCPAddrPublish(cpAddrRetryCtx())
	}
	return changed, err
}

// noteCPAddrPublish records one owned-publish outcome and reports whether the
// caller must start the retry loop (a failure with no loop running).
func (s *ConfigStore) noteCPAddrPublish(trigger string, err error) (startRetry bool) {
	s.addrPubMu.Lock()
	defer s.addrPubMu.Unlock()
	st := &s.addrPub
	if err == nil {
		if st.pending {
			logger.Printf("ControlPlane: CP address list republished after %d failed attempts (pending since %s, first failed on %q)",
				st.attempts, st.since.UTC().Format(time.RFC3339), st.trigger)
		}
		st.pending, st.attempts, st.trigger, st.reason = false, 0, "", ""
		return false
	}
	if !st.pending {
		st.pending, st.since, st.trigger = true, cpAddrPublishNow(), trigger
		logWarnf("ControlPlane: CP address list publish FAILED on %q — Data Planes keep the last committed list until a retry succeeds: %v", trigger, err)
	}
	st.attempts++
	st.reason = "publish_rejected"
	if errors.Is(err, errCPAddrCommitRace) {
		st.reason = "commit_race"
	}
	if st.retrying {
		return false
	}
	st.retrying = true
	return true
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
		var err error
		if src != nil {
			_, err = s.UpdateCPAddressesFrom(src)
		} // no source: nothing is owned any more, so nothing is pending
		s.noteCPAddrPublish("retry", err)

		s.addrPubMu.Lock()
		if !s.addrPub.pending {
			s.addrPub.retrying = false
			s.addrPubMu.Unlock()
			return
		}
		s.addrPubMu.Unlock()
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
