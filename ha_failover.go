package main

// ha_failover.go — ADR-0005 S4: lease-arbitrated automatic failover.
//
// In lease mode the standby's leader-unreachable path attempts a FENCE-GATED
// promotion (leaseAutoPromote) instead of the legacy flag-gated 15s trigger:
// Acquire is denied while the leader lives, so the split-brain that made
// auto-failover opt-in (ADR-0004) is structurally impossible and the
// --ha-auto-failover flag governs legacy mode only. Two additional gates
// protect the AUTOMATIC path (manual promotion bypasses both):
//
//   - freshness (Finding 8): refuse to auto-promote on state older than
//     haPromoteFreshnessWindow — prefer an availability gap over serving
//     long-stale config as the new source of truth;
//   - hysteresis (Finding 8): refuse to auto-repromote within
//     haRepromoteCooldown of a self-fence, so flapping links don't churn
//     leadership.
//
// A demoted leader (self-fence, or an unfenced resume) re-enters standby
// AND resyncs from its S0-recorded ex-standby (enterStandbyResync) when the
// cluster loader provided the material — its CP gRPC server keeps running
// (S3's role-gated issuance fences writes), so onPromote is a no-op.

import (
	"context"
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

const (
	// haPromoteFreshnessWindow bounds how stale a standby's last successful
	// HASync may be for AUTOMATIC promotion. Manual promotion bypasses it.
	haPromoteFreshnessWindow = 10 * time.Minute
	// haRepromoteCooldown suppresses automatic re-promotion after a
	// self-fence so flapping connectivity cannot churn leadership.
	haRepromoteCooldown = 30 * time.Second
	// haResumeGhostWait bounds how long a restarting leader waits for its
	// OWN previous process's lease to expire before treating the denial as
	// real (ghost-lease window ≈ one TTL).
	haResumeGhostWait = 45 * time.Second
)

// haResyncContext is the material a demoted leader needs to re-enter
// standby mode (captured by the cluster loader at CP boot).
type haResyncContext struct {
	ctx                       context.Context
	grpcAddr                  string
	certFile, keyFile, caFile string
	set                       bool
}

// SetResyncMaterial records the connection material a later demotion needs
// to resync from the ex-standby (ADR-0005 S4). Called by the cluster loader
// at CP boot, before any leadership assertion.
func (h *HAState) SetResyncMaterial(ctx context.Context, grpcAddr, certFile, keyFile, caFile string) {
	h.mu.Lock()
	h.resync = haResyncContext{ctx: ctx, grpcAddr: grpcAddr, certFile: certFile, keyFile: keyFile, caFile: caFile, set: true}
	h.mu.Unlock()
}

// leaseConfigured reports whether a fencing-lease backend is installed.
func (h *HAState) leaseConfigured() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.lease != nil
}

// markSyncOK records a successful HASync apply (freshness-gate input).
func (h *HAState) markSyncOK() {
	h.mu.Lock()
	h.lastSyncOK = time.Now()
	h.mu.Unlock()
}

// leaseAutoPromote is the lease-mode leader-unreachable path (replaces the
// legacy 15s flag-gated trigger). Returns true when this node promoted (the
// standby loop exits). Every refusal keeps the standby looping read-only.
func (h *HAState) leaseAutoPromote() bool {
	h.mu.RLock()
	lastFence := h.lastSelfFence
	h.mu.RUnlock()

	// Hysteresis: a recent self-fence means our connectivity (or etcd's view
	// of us) is suspect — do not churn leadership.
	if !lastFence.IsZero() && time.Since(lastFence) < haRepromoteCooldown {
		logger.Printf("HA: auto-promotion suppressed — self-fenced %s ago (cooldown %s)",
			time.Since(lastFence).Round(time.Second), haRepromoteCooldown)
		return false
	}
	// CHAOS-71 (CodeRabbit review of #1556): never AUTO-promote a node whose
	// own Control Plane listener is dark. A self-fenced ex-leader still runs
	// its supervisor; promoting it while the listener is unavailable would
	// re-acquire the lease only for leaseRenewOnce to withhold it again — a
	// promote/fence flap that keeps the lease away from a healthy peer.
	// PromoteManually (break-glass) is unaffected.
	if reason, dark := haLeaseRenewWithheld(); dark {
		logger.Printf("HA: auto-promotion refused — %q (manual promotion available)", sanitizeLog(reason))
		return false
	}
	// Freshness (Finding 8): never auto-promote on long-stale (or never
	// synced) state. An operator can still PromoteManually — that is the
	// break-glass, and it logs the staleness instead. The predicate is SHARED
	// with the legacy path (legacyAutoPromote): see haSyncIneligibility.
	if h.refuseAutoPromoteUnsynced() {
		return false
	}

	// promote() is Acquire-gated (S2): while the leader still holds the
	// lease this is denied and we keep standing by — the fence, not a
	// timeout, arbitrates.
	h.promote("leader unreachable (lease-arbitrated auto-failover)")
	return h.IsLeader()
}

// haSyncIneligibility is the ONE synchronization-eligibility predicate for
// AUTOMATIC promotion. Lease-arbitrated failover (leaseAutoPromote) and legacy
// flag-gated failover (legacyAutoPromote) both decide through it, so the two
// paths give the same guarantee by construction rather than by two checks that
// happen to agree:
//
//	a standby is promoted automatically only if it has successfully APPLIED a
//	leader state bundle (lastSync non-zero) no longer than
//	haPromoteFreshnessWindow ago.
//
// lastSync is HAState.lastSyncOK, written ONLY by markSyncOK, which
// syncFromLeader calls after applyHABundle returned true — the bundle passed
// the puller-side epoch fence and its CA, cluster state and config snapshot
// were all applied. A bundle that was refused (an unenforceable ruleset under
// POL-005, a rejected IdP sync, an over-cap or stale-epoch snapshot, a CA that
// would not decrypt), failed in transport, or panicked in the apply path never
// reaches it. The value is in-memory only: a restarted standby is ineligible
// until its first post-restart sync.
//
// A standby that fails the predicate holds empty or old configuration; promoted,
// it would publish that as the authoritative config to every data plane — an
// empty blocklist, missing policy rules, an old default action. Refusing costs
// availability of the control plane (the data planes keep enforcing their last
// applied config), and manual promotion remains the break-glass.
//
// Pure: the caller supplies both instants.
func haSyncIneligibility(lastSync, now time.Time) (reason string, ineligible bool) {
	if lastSync.IsZero() {
		return "no successful state sync yet (manual promotion available)", true
	}
	if stale := now.Sub(lastSync); stale > haPromoteFreshnessWindow {
		return fmt.Sprintf("last state sync %s ago exceeds the %s freshness window "+
			"(promoting would serve stale config; use manual promotion to override)",
			stale.Round(time.Second), haPromoteFreshnessWindow), true
	}
	return "", false
}

// autoPromoteSyncRefusal evaluates haSyncIneligibility against this node's
// recorded last successful sync.
func (h *HAState) autoPromoteSyncRefusal() (reason string, refused bool) {
	h.mu.RLock()
	lastSync := h.lastSyncOK
	h.mu.RUnlock()
	return haSyncIneligibility(lastSync, time.Now())
}

// refuseAutoPromoteUnsynced reports whether an AUTOMATIC promotion must be
// refused on synchronization grounds, and logs the refusal. It is the single
// call both automatic paths make. The reason is built from this node's own
// clock and constants only — no peer- or operator-supplied value.
func (h *HAState) refuseAutoPromoteUnsynced() bool {
	reason, refused := h.autoPromoteSyncRefusal()
	if refused {
		logger.Printf("HA: auto-promotion refused — %s", reason)
	}
	return refused
}

// legacyAutoPromote is the legacy (no fencing lease) leader-unreachable path
// when --ha-auto-failover is on. It used to promote unconditionally: a standby
// that had never completed a sync — or whose every attempt had been refused —
// became leader on three failed rounds and published its empty state fleet-wide.
// It now applies the same synchronization eligibility as lease mode
// (haSyncIneligibility); an ineligible standby stays a read-only standby, keeps
// retrying the sync, and raises ha_manual_failover_required once per outage,
// because promoting it is now an operator decision.
//
// Returns whether promotion ACTUALLY happened, mirroring the lease path.
// promote() is not infallible: onPromote can return an error, or (CHAOS-25)
// panic and be contained — both reset the once-guard and leave this node a
// standby. Returning an unconditional true there told standbyLoop to exit,
// permanently ending BOTH replication and leader monitoring on a node that
// never became a leader — the silent-stall outcome the per-round guard exists
// to prevent, reached one level up. Returning IsLeader() keeps the loop ticking
// so the next round retries the promotion, exactly as lease mode already does.
func (s *standbyLoopState) legacyAutoPromote() bool {
	if s.h.refuseAutoPromoteUnsynced() {
		if !s.manualWarned {
			s.h.warnAutoFailoverRefused(s.leaderAddr)
			s.manualWarned = true
		}
		return false
	}
	s.h.promote("leader unreachable")
	return s.h.IsLeader()
}

// warnAutoFailoverRefused pages that the leader is unreachable and this standby
// will NOT take over on its own although automatic failover is enabled, because
// it holds no sufficiently fresh copy of the leader's state. It reuses the
// ha_manual_failover_required event: the operator action is the same one — decide
// whether to promote this node manually.
func (h *HAState) warnAutoFailoverRefused(leaderAddr string) {
	logger.Printf("HA: leader %q did not answer the last sync rounds and automatic failover was REFUSED — this standby has no fresh "+
		"copy of the leader's state, so promoting it would publish empty or stale configuration to every "+
		"data plane. Staying standby (read-only) and retrying the sync. Restore the leader, or promote this "+
		"node manually if the leader is permanently gone and you accept serving its state.",
		sanitizeLog(leaderAddr))
	go alerts.Fire("ha_manual_failover_required", alerts.Payload{
		Event: "ha_manual_failover_required",
		Host:  leaderAddr,
		Detail: "leader did not answer the last sync rounds; automatic failover refused because this standby has not synced the " +
			"leader's state recently enough; standby staying read-only pending manual action",
		Source: "ha",
	})
}

// autoPromoteBlockedLocked is the standby-side status line for the eligibility
// predicate: the reason an automatic promotion would be refused RIGHT NOW, or
// "" when it would not be (or when this node has no automatic path at all —
// legacy mode with auto-failover off). Evaluated live, so a standby that is not
// failover-ready says so before the leader is lost. Caller holds h.mu.
func (h *HAState) autoPromoteBlockedLocked() string {
	if h.lease == nil && !h.autoFailover {
		return ""
	}
	reason, _ := haSyncIneligibility(h.lastSyncOK, time.Now())
	return reason
}

// manualPromoteSyncWarning describes, for the operator performing a MANUAL
// promotion, the state this standby would be promoted on when it fails the
// automatic path's eligibility predicate; "" when it passes. Manual promotion is
// the break-glass and is never refused on these grounds (a cluster whose leader
// is permanently gone must stay recoverable) — the risk is stated, not blocked.
func (h *HAState) manualPromoteSyncWarning() string {
	h.mu.RLock()
	lastSync := h.lastSyncOK
	h.mu.RUnlock()
	now := time.Now()
	if _, ineligible := haSyncIneligibility(lastSync, now); !ineligible {
		return ""
	}
	if lastSync.IsZero() {
		return "this standby never completed a state sync from the leader: it was promoted on its own local " +
			"configuration, which may be empty, and now publishes that to every data plane"
	}
	return fmt.Sprintf("this standby's last successful state sync was %s (%s ago, beyond the %s freshness window): "+
		"it was promoted on that state and now publishes it to every data plane",
		lastSync.UTC().Format(time.RFC3339), now.Sub(lastSync).Round(time.Second), haPromoteFreshnessWindow)
}

// logManualPromoteSyncOverride records that a manual promotion is overriding
// the automatic path's synchronization eligibility. No-op for an eligible node.
func (h *HAState) logManualPromoteSyncOverride() {
	if w := h.manualPromoteSyncWarning(); w != "" {
		logger.Printf("HA: MANUAL promotion overrides the synchronization eligibility that gates automatic failover — %s", w)
	}
}

// manualPromoteOutcome builds the manual-promotion API response and audit
// detail, carrying the synchronization warning into both when there is one.
func manualPromoteOutcome(status HAStatus, syncWarning string) (resp map[string]any, auditDetail string) {
	resp = map[string]any{"ok": true, "role": status.Role, "term": status.Term}
	auditDetail = fmt.Sprintf("manual standby→leader promotion (term=%d)", status.Term)
	if syncWarning != "" {
		resp["warning"] = syncWarning
		auditDetail += "; WARNING: " + syncWarning
	}
	return resp, auditDetail
}

// enterStandbyResync re-enters standby mode against the S0-recorded
// ex-standby after a demotion (self-fence or unfenced resume). Returns
// false when the failback target or the resync material is missing — the
// caller stays in the S2 passive stance. onPromote is a NO-OP: a demoted
// leader's CP gRPC server never stopped, and S3's role-gated issuance
// keeps writes fenced while it stands by.
func (h *HAState) enterStandbyResync(reason string) bool {
	h.mu.RLock()
	target := h.standbyAddr
	token := h.token
	rc := h.resync
	autoFailover := h.autoFailover
	h.mu.RUnlock()

	if target == "" {
		logger.Printf("HA: no recorded standby address — cannot resync after %s (staying passive; ADR-0005 S0)", sanitizeLog(reason))
		return false
	}
	if !rc.set {
		logger.Printf("HA: no resync material recorded — cannot resync after %s (staying passive)", sanitizeLog(reason))
		return false
	}
	ctx := rc.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// ADR-0064: preserve before overwrite. What this node committed as leader
	// is about to be replaced by the new leader's bundle; the new leader may
	// lack it and need to adopt it (ha_publish_reconcile.go).
	h.preserveLedSnapshot(reason)
	logger.Printf("HA: re-entering standby against recorded ex-standby %s (%s)", sanitizeLog(target), sanitizeLog(reason))
	h.StartAsStandby(ctx, target, token,
		rc.grpcAddr, rc.certFile, rc.keyFile, rc.caFile, autoFailover,
		func() error { return nil }, // CP gRPC server already running
	)
	return true
}

// acquireLeaseForResume is acquireLeaseForLeadership plus RETRY handling for
// restarts (ADR-0005 S5). Two denials are not decisions and are retried, each
// under its own budget:
//
//   - our own GHOST lease: a leader that restarts WITHIN the lease TTL finds
//     the key still held by its previous process's lease — holder == our own
//     candidate ID with no keepaliver. Treating that as a real denial would
//     demote a healthy leader on every fast restart. Budget: haResumeGhostWait
//     (45 s) — the condition has a known, self-clearing expiry.
//   - an UNREACHABLE backend: we learned nothing, so there is nothing to obey.
//     Budget: haResumeUnreachableWait (5 s), much shorter because this call
//     sits on the BOOT path ahead of the proxy listener — see that constant.
//     CHAOS-55 — this branch used to return false on the FIRST transport error,
//     so the 45 s budget was spent only on the denial shape that is not a
//     fault, and the fault that actually happens got zero patience. A host
//     reboot starts culvert and etcd concurrently; a few seconds of
//     "connection refused" was enough to leave the node a read-only leader
//     with nothing left in the process that would ever retry (register HA-7).
//     Anything longer than the short budget is the background recovery loop's
//     job (ha_lease_recovery.go), which costs the boot nothing.
//
// A denial by ANY OTHER holder returns false immediately — that fence is real,
// and retrying it would be waiting for a live leader to die.
//
// sawForeignHolder is the second half of the CHAOS-55 finding and the reason
// this returns two values rather than one. It reports whether the fence
// AFFIRMATIVELY told us another node holds the lease, as opposed to us simply
// failing to take it. ResumeAsLeader used to demote to standby on any failed
// resume, so an unreachable backend — an absence of information — was acted on
// as if it were a fence decision. On a whole-site restart that is how a
// two-node cluster deadlocks: the ex-leader stands by against the ex-standby
// while the ex-standby stands by against it, neither ever syncs (a
// lease-configured puller rejects a bundle carrying no live holder), so the
// freshness gate refuses every auto-promotion and the cluster is permanently
// leaderless. Giving leadership up on an unknown is the same mistake as taking
// it on one, in the other direction.
func (h *HAState) acquireLeaseForResume() (granted bool, sawForeignHolder bool) {
	h.mu.RLock()
	p := h.lease
	h.mu.RUnlock()
	if p == nil {
		return true, false
	}
	unreachableWait, retryBackoff := h.resumeUnreachableTiming()
	ghostDeadline := time.Now().Add(haResumeGhostWait)
	unreachableDeadline := time.Now().Add(unreachableWait)
	unreachable := 0
	for {
		if h.shuttingDown() {
			logger.Printf("HA: process shutdown began — abandoning the leadership-resume lease acquire")
			return false, false
		}
		outcome, st := h.resumeAcquireRound()
		switch outcome {
		case resumeGranted:
			return true, false
		case resumeForeign:
			return false, true // a live foreign holder — the fence has decided
		case resumeOwnGhost:
			if time.Now().After(ghostDeadline) {
				logger.Printf("HA: own ghost lease did not expire within %s — giving up the resume acquire", haResumeGhostWait)
				return false, false
			}
			logger.Printf("HA: waiting out our own ghost lease from the previous process (valid_for=%s)", st.ValidFor)
			if !h.sleepUnlessShutdown(ghostRetryWait(st.ValidFor)) {
				return false, false // shutdown: the loop head logs and the resume aborts
			}
		default: // resumeUnknown, resumeRaceRetryable
			if time.Now().After(unreachableDeadline) {
				logger.Printf("HA: fencing backend still unreachable after %s — taking the leader role "+
					"READ-ONLY and continuing to retry in the background so the data plane is not "+
					"held up by a control-plane fence (CHAOS-55)", unreachableWait)
				return false, false
			}
			unreachable++
			if unreachable == 1 {
				logger.Printf("HA: fencing backend unreachable during leader resume — retrying for up to %s "+
					"before falling back to a read-only leader role", unreachableWait)
			}
			if !h.sleepUnlessShutdown(retryBackoff) {
				return false, false
			}
		}
	}
}

// resumeUnreachableTiming is acquireLeaseForResume's unreachable-backend budget
// and retry cadence: the production constants unless a test shortened them on
// this instance (HAState.testResumeUnreachableWait).
func (h *HAState) resumeUnreachableTiming() (budget, retry time.Duration) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.testResumeUnreachableWait > 0 {
		return h.testResumeUnreachableWait, h.testResumeRetryBackoff
	}
	return haResumeUnreachableWait, haLeaseResumeRetryBackoff
}

// ghostRetryWait is how long to wait before re-testing our own ghost lease:
// its reported remaining validity plus a second, clamped into (1s, 5s].
func ghostRetryWait(validFor time.Duration) time.Duration {
	wait := validFor + time.Second
	if wait > 5*time.Second || wait <= time.Second {
		wait = 5 * time.Second
	}
	return wait
}
