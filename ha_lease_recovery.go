package main

// ha_lease_recovery.go — CHAOS-55: the way BACK from an unfenced leader.
//
// ADR-0005 gave the fencing lease three exits from write authority — denied on
// promotion, denied on resume, and self-fenced by the keepalive — and a way
// back from exactly one of them (a demoted leader with recorded resync material
// re-enters standby, where the standby loop can eventually re-promote). The
// other two dead-ended:
//
//	acquireLeaseForResume returned FALSE on the first transport error. Its 45 s
//	budget (haResumeGhostWait) was spent only on waiting out our OWN previous
//	process's ghost lease — the one denial shape that is not a fault. The fault
//	that actually happens, an unreachable backend, got zero patience. That is
//	the boot-order case: on a host reboot the container runtime starts culvert
//	and etcd concurrently, and a few seconds of "connection refused" was enough.
//
//	ResumeAsLeader then asserted role="leader" with leaseEpoch=0. WriteAllowed()
//	is false in that state, and startLeaseKeepalive() no-ops on a zero epoch, so
//	NOTHING in the process ever called Acquire again. The node served reads
//	forever, reported culvert_ha_role=1 exactly like a healthy leader, and could
//	not issue a certificate, accept a revocation, or publish a config snapshot
//	until an operator noticed and restarted it (register row HA-7).
//
// Two changes close it, and the split between them is deliberate:
//
//  1. acquireLeaseForResume now spends its EXISTING budget on transport errors
//     too (resumeAcquireRound below classifies the round). No new state, and it
//     alone covers the common case — etcd a few seconds behind us at boot.
//
//  2. When the budget is exhausted the node still takes the read-only leader
//     role, but now arms a background recovery loop. Recovery is bounded in
//     RATE, never in ATTEMPTS: giving up would reinstate exactly the dead end
//     this file exists to remove, and the retry is never silent (rate-limited
//     log, alert on entry and on recovery, four metrics).
//
// The safety rule the loop must not break: **it may complete an interrupted
// resume, but it must never override the fence.** Acquire is denied while
// anyone else holds the lease, so it cannot take leadership from a live peer.
// But a denial is not enough on its own — if a peer took the lease while we
// were blind, our config may now be arbitrarily stale, and quietly waiting for
// that peer to die so we can take over would make a stale node authoritative.
// So the loop READS before it acquires, and an observed foreign holder is
// terminal: this node demotes and routes any future promotion through the
// standby machinery, where the freshness and hysteresis gates already live
// (ha_failover.go). Recovery deliberately owns the "nothing changed while we
// were blind" case and nothing more.

import (
	"context"
	"fmt"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/halease"
)

const (
	// haLeaseRecoveryMinBackoff / haLeaseRecoveryMaxBackoff bound the
	// re-acquire cadence. The floor keeps a fast recovery fast (the common
	// case is a backend that is seconds away from ready); the ceiling keeps a
	// long outage cheap — one RPC per node per 30 s against an etcd that is
	// already struggling.
	haLeaseRecoveryMinBackoff = 1 * time.Second
	haLeaseRecoveryMaxBackoff = 30 * time.Second
	// haLeaseRecoveryJitter is the fraction of the backoff randomised each
	// round. Every CP in a fleet restarts together after a site-wide power
	// event, so a fixed cadence would have them all hit the recovering
	// backend on the same tick (the WK-13 thundering-herd shape).
	haLeaseRecoveryJitter = 0.2
	// haLeaseRecoveryLogInterval rate-limits the "still trying" line. The
	// first failure of an episode logs immediately; the magnitude lives in
	// culvert_ha_lease_reacquire_attempts_total (CHAOS-54's rule).
	haLeaseRecoveryLogInterval = 60 * time.Second
	// haLeaseResumeRetryBackoff is the transport-error retry cadence inside
	// acquireLeaseForResume.
	haLeaseResumeRetryBackoff = 2 * time.Second
	// haResumeUnreachableWait bounds how long a resume BLOCKS waiting for an
	// unreachable fencing backend, and it is deliberately much shorter than
	// haResumeGhostWait (45 s).
	//
	// ResumeAsLeader runs inside initCluster, which is ordered BEFORE the root
	// CA, the policy engine, the proxy listener and the admin UI. Time spent
	// here is time the SECURE WEB GATEWAY DATA PLANE is not serving — and an
	// etcd outage must never cost the data path availability, because the fence
	// governs control-plane writes and nothing else. So the resume absorbs the
	// short race it exists for (etcd a few seconds behind us at boot) and hands
	// anything longer to the background loop, which costs the boot nothing.
	//
	// The ghost budget stays 45 s: that wait is for a condition with a KNOWN,
	// self-clearing expiry (one lease TTL), and it is pre-existing behaviour.
	haResumeUnreachableWait = 5 * time.Second
)

// haLeaseComponent labels contained recovery-loop panics in the crash plane.
const haLeaseComponent = "ha-lease-recovery"

// statHALeaseReacquireAttempts counts recovery Acquire/Read rounds that did not
// restore write authority. It is the magnitude behind the rate-limited log.
var statHALeaseReacquireAttempts atomic.Int64

// statHALeaseReacquired counts completed recoveries (unfenced → write authority
// restored without an operator).
var statHALeaseReacquired atomic.Int64

// ── The resume acquire, with its budget spent on the right fault ────────────

// resumeOutcome classifies one resume-acquire round. acquireLeaseForLeadership
// collapses grant/denial/error into a bool, which is right for its callers but
// loses exactly the distinction the resume path needs: a DENIAL by a live
// foreign holder is a decision (stop), an unreachable backend is an absence of
// one (retry).
type resumeOutcome int

const (
	resumeGranted       resumeOutcome = iota // the lease is ours
	resumeForeign                            // another node holds it — a real fence decision
	resumeOwnGhost                           // our own previous process still holds it
	resumeUnknown                            // backend unreachable — we learned nothing
	resumeRaceRetryable                      // free on read but denied on acquire (or vice versa)
)

// resumeAcquireRound performs one Acquire and, on failure, one Read to classify
// why. The Read is what separates "denied" from "unreachable" — Provider.Acquire
// reports a denial as (false, status, nil) and a transport fault as an error,
// but acquireLeaseForLeadership has already discarded that by the time we see
// its bool, and re-deriving it here keeps the single logging site intact.
func (h *HAState) resumeAcquireRound() (resumeOutcome, halease.Status) {
	if h.acquireLeaseForLeadership("leader resume") {
		return resumeGranted, halease.Status{}
	}
	h.mu.RLock()
	p, id := h.lease, h.leaseCandidateID
	h.mu.RUnlock()
	if p == nil {
		return resumeGranted, halease.Status{} // legacy mode never reaches here, but never block it
	}
	ctx, cancel := context.WithTimeout(context.Background(), haLeaseOpTimeout)
	st, err := p.Read(ctx)
	cancel()
	switch {
	case err != nil:
		return resumeUnknown, halease.Status{}
	case st.Holder == id:
		return resumeOwnGhost, st
	case st.Holder != "":
		return resumeForeign, st
	default:
		// The backend says free but Acquire did not grant: another candidate
		// won the race between the two calls, or the holder vanished mid-txn
		// (the etcd provider's len(kvs)==0 branch). Retryable.
		return resumeRaceRetryable, st
	}
}

// ── The background recovery loop ────────────────────────────────────────────

// leaseRecoveryActive reports whether the re-acquire loop is armed. Surfaced on
// /healthz and /api/cluster/ha so "read-only and working on it" is
// distinguishable from "read-only and stuck".
func (h *HAState) leaseRecoveryActive() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.leaseRecoveryCh != nil
}

// startLeaseRecovery arms the re-acquire loop for a leader that holds the role
// but not the fence. No-op in legacy mode, when the fence IS held, when a loop
// is already running, or while Stop() is joining (the startLeaseKeepalive
// contract — a goroutine spawned now would hold a channel the in-flight
// stopLoops already missed, deadlocking the join).
func (h *HAState) startLeaseRecovery() {
	h.mu.Lock()
	if h.lease == nil || h.leaseEpoch != 0 || h.role != "leader" || h.leaseRecoveryCh != nil || h.stopping {
		h.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	h.leaseRecoveryCh = stop
	// wg.Add INSIDE the lock: atomic with the stopping check above (an Add
	// racing Stop()'s Wait at counter 0 is WaitGroup misuse — see Stop).
	h.wg.Add(1)
	h.mu.Unlock()

	logger.Printf("HA: lease recovery ARMED — retrying the fencing acquire in the background " +
		"(this node serves READ-ONLY until the fence is held; no operator action required)")
	go func() {
		defer h.wg.Done()
		h.leaseRecoveryLoop(stop)
	}()
}

// stopLeaseRecovery halts the re-acquire loop (idempotent).
func (h *HAState) stopLeaseRecovery() {
	h.mu.Lock()
	if h.leaseRecoveryCh != nil {
		close(h.leaseRecoveryCh)
		h.leaseRecoveryCh = nil
	}
	h.mu.Unlock()
}

// clearLeaseRecoveryHandle drops the loop's own channel handle on exit without
// closing it (the loop is the one returning). Closing here would double-close
// when stopLeaseRecovery races the loop's own exit.
func (h *HAState) clearLeaseRecoveryHandle(stop chan struct{}) {
	h.mu.Lock()
	if h.leaseRecoveryCh == stop {
		h.leaseRecoveryCh = nil
	}
	h.mu.Unlock()
}

func (h *HAState) leaseRecoveryLoop(stop chan struct{}) {
	defer h.clearLeaseRecoveryHandle(stop)

	backoff := haLeaseRecoveryMinBackoff
	started := time.Now()
	var lastLog time.Time
	var suppressed int

	for {
		done := h.leaseRecoveryRound(started, &lastLog, &suppressed)
		if done {
			return
		}
		statHALeaseReacquireAttempts.Add(1)
		if !haSleepInterruptible(stop, jitterDuration(backoff, haLeaseRecoveryJitter)) {
			return // Stop() — the node is going away, still read-only. Correct.
		}
		backoff *= 2
		if backoff > haLeaseRecoveryMaxBackoff {
			backoff = haLeaseRecoveryMaxBackoff
		}
	}
}

// leaseRecoveryRound runs ONE recovery attempt under a panic guard, returning
// true when the loop must exit.
//
// CHAOS-24 note, and it lands the OPPOSITE way from leaseRenewRound: a panic in
// the keepalive is dangerous to contain, because containment there would let a
// node keep write authority it is no longer confirming. Here the node has NO
// write authority to extend — a panicking round is simply a round that did not
// recover, so containing it and backing off is strictly fail-closed. The cost
// of NOT containing it is a process crash on a node that is already degraded,
// which helps nobody. The contained round is reported (crash record +
// culvert_crash_records_total{component="ha-lease-recovery"}) and charged to
// the attempt counter like any other failed round.
func (h *HAState) leaseRecoveryRound(started time.Time, lastLog *time.Time, suppressed *int) (done bool) {
	if panicked := runGuarded(haLeaseComponent, func() {
		done = h.leaseRecoveryAttempt(started, lastLog, suppressed)
	}); panicked {
		return false
	}
	return done
}

func (h *HAState) leaseRecoveryAttempt(started time.Time, lastLog *time.Time, suppressed *int) (done bool) {
	h.mu.RLock()
	p, id, role, epoch := h.lease, h.leaseCandidateID, h.role, h.leaseEpoch
	h.mu.RUnlock()
	// The state that armed us is gone (an operator promoted/demoted this node,
	// HA was disabled, or a concurrent path already took the fence). Nothing
	// left to recover.
	if p == nil || role != "leader" || epoch != 0 {
		return true
	}

	// READ BEFORE ACQUIRE. See the file header: a denial alone cannot tell us
	// whether the fence was taken while we were blind, and that distinction
	// decides whether recovering is safe or makes a stale node authoritative.
	ctx, cancel := context.WithTimeout(context.Background(), haLeaseOpTimeout)
	st, err := p.Read(ctx)
	cancel()
	if err != nil {
		h.logRecoveryProgress(started, lastLog, suppressed, fmt.Sprintf("fencing backend unreachable: %v", err))
		return false
	}
	if st.Holder != "" && st.Holder != id {
		h.handleForeignFenceHolder(st.Holder, st.Epoch)
		return true
	}

	// Free, or still pinned by our own previous process's lease. Either way the
	// fence has not moved to anyone else, so completing the resume is safe.
	if !h.acquireLeaseForLeadership("lease recovery") {
		h.logRecoveryProgress(started, lastLog, suppressed, "acquire not granted (retrying)")
		return false
	}
	h.completeLeaseRecovery(started, *suppressed)
	return true
}

// completeLeaseRecovery installs the recovered grant: the term collapses into
// the new epoch (ADR-0005 Finding 6 — the same rule every other grant path
// follows), the config is re-persisted so a further restart resumes on the
// current epoch, and the keepalive starts. Recovery is announced on EVIDENCE —
// a landed grant — never on elapsed time (the ca_health.go / storage_health.go
// rule).
//
// Note the ordering: the grant is already installed by the time this runs (that
// is what makes WriteAllowed true), and the recovering flag drops a beat later
// when the loop returns. A scrape landing in between sees write_authority=1
// with lease_recovering=1. That is deliberate — authority first, bookkeeping
// second is the safe direction — and it is harmless, because the alertable
// condition is `unfenced=1 AND recovering=0` and unfenced is already 0 here.
func (h *HAState) completeLeaseRecovery(started time.Time, suppressed int) {
	h.mu.Lock()
	h.term = termFromEpoch(h.leaseEpoch)
	epoch := h.leaseEpoch
	cfg := h.snapshotConfigLocked()
	h.mu.Unlock()
	_ = saveHAConfig(cfg)
	h.startLeaseKeepalive()

	statHALeaseReacquired.Add(1)
	elapsed := time.Since(started).Round(time.Second)
	if suppressed > 0 {
		logger.Printf("HA: RECOVERED — fencing lease re-acquired after %s (epoch=%d, term=%d); "+
			"write authority is back, %d further failure log lines were suppressed during the episode",
			elapsed, epoch, epoch, suppressed)
	} else {
		logger.Printf("HA: RECOVERED — fencing lease re-acquired after %s (epoch=%d, term=%d); write authority is back",
			elapsed, epoch, epoch)
	}
	go alerts.Fire("ha_lease_reacquired", alerts.Payload{
		Event:  "ha_lease_reacquired",
		Detail: "unfenced leader re-acquired the fencing lease and regained write authority",
		Source: "ha",
	})
}

// handleForeignFenceHolder handles the one outcome recovery must never paper
// over: while this node was unfenced, another node took the lease. It is the
// leader now, this node's persisted role is stale, and so — potentially — is
// every byte of its config.
//
// The decision is LATCHED: the loop exits and never acquires again, even if
// that holder later disappears. Quietly waiting for a live leader to die and
// then taking over with state of unknown age is exactly what the freshness gate
// (ha_failover.go) exists to prevent, and recovery must not route around it.
// Any future promotion belongs to the standby machinery, which owns both that
// gate and the hysteresis one.
//
// The disposition mirrors the SHIPPED ADR-0005 S4/S2 decision for a resume
// denied by a live holder, deliberately rather than inventing a third stance:
// resync from the recorded ex-standby when the material exists, and otherwise
// keep the read-only leader role with a CRITICAL alert — the "operator, come
// look" state for a topology with a foreign leader and nowhere to resync from.
func (h *HAState) handleForeignFenceHolder(holder string, epoch int64) {
	h.mu.Lock()
	if h.role != "leader" {
		h.mu.Unlock()
		return
	}
	// The hysteresis clock starts here as well as on a self-fence: this node
	// just discovered it lost leadership, and an immediate auto-repromotion
	// against a freshly-elected peer is precisely the churn haRepromoteCooldown
	// exists to prevent.
	h.lastSelfFence = time.Now()
	h.mu.Unlock()

	logger.Printf("HA: the fencing lease is held by %q (epoch=%d) while this node was unfenced — "+
		"another node is the leader; this node stops trying to re-acquire (its state may be stale)",
		sanitizeLog(holder), epoch)

	// StartAsStandby (inside enterStandbyResync) already flips the role, clears
	// the promote guard and persists — nothing to duplicate here beyond the
	// transition record and the alert.
	if h.enterStandbyResync("foreign fence holder observed") {
		globalHAFailoverRing.Load().record("leader", "standby",
			"fence taken by another node while unfenced", epoch, time.Now())
		go alerts.Fire("ha_self_fenced", alerts.Payload{
			Event:  "ha_self_fenced",
			Detail: "unfenced leader observed another node holding the fencing lease and re-entered standby",
			Source: "ha",
		})
		return
	}

	logger.Printf("HA: CRITICAL — another node holds the fencing lease and no resync target/material is " +
		"recorded; this node keeps the leader role READ-ONLY and will NOT re-acquire. Operator action " +
		"required (ADR-0005 S2 stance).")
	go alerts.Fire("ha_resume_unfenced", alerts.Payload{
		Event: "ha_resume_unfenced",
		Detail: "another node holds the fencing lease and no resync target is recorded; " +
			"this node is read-only and has stopped attempting recovery",
		Source: "ha",
	})
}

// logRecoveryProgress emits the first failure of an episode immediately, then at
// most one line per haLeaseRecoveryLogInterval, counting what it suppressed so
// the recovery line can name the magnitude. A recovery loop that logged every
// round would, at the 1 s floor, be the CHAOS-54 log flood in a slower costume.
func (h *HAState) logRecoveryProgress(started time.Time, lastLog *time.Time, suppressed *int, detail string) {
	now := time.Now()
	if !lastLog.IsZero() && now.Sub(*lastLog) < haLeaseRecoveryLogInterval {
		*suppressed++
		return
	}
	*lastLog = now
	logger.Printf("HA: still UNFENCED after %s — %s (serving read-only; retrying in the background)",
		now.Sub(started).Round(time.Second), sanitizeLog(detail))
}

// ── Shared helpers ──────────────────────────────────────────────────────────

// haSleepInterruptible sleeps for d unless stop closes first. Returns false when
// it was interrupted — the CHAOS-54 rule: a shutdown must never have to wait out
// a backoff.
func haSleepInterruptible(stop <-chan struct{}, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-stop:
		return false
	case <-t.C:
		return true
	}
}

// jitterDuration spreads d by ±frac so a fleet restarting together does not
// converge on one cadence against a recovering backend.
func jitterDuration(d time.Duration, frac float64) time.Duration {
	if d <= 0 || frac <= 0 {
		return d
	}
	span := float64(d) * frac
	//nolint:gosec // G404: jitter is a load-spreading device, not a security primitive
	out := time.Duration(float64(d) + (rand.Float64()*2-1)*span)
	if out < time.Millisecond {
		out = time.Millisecond
	}
	return out
}

// haLeaseConfigured reports whether a fencing backend is armed on the global HA
// state — the gate for every lease metric below. A `culvert_ha_write_authority 0`
// on a node that never had a fence is indistinguishable from a broken one, and
// the documented paging rule is `== 0` (the CHAOS-54 rule).
func haLeaseConfigured() bool { return globalHA.leaseConfigured() }

// resetHALeaseRecoveryStatsForTest zeroes the process-global recovery counters
// so a test can assert on absolute values. The suite runs under
// `-count=2 -shuffle=on`, where a cumulative counter is a guaranteed flake.
func resetHALeaseRecoveryStatsForTest() {
	statHALeaseReacquireAttempts.Store(0)
	statHALeaseReacquired.Store(0)
}
