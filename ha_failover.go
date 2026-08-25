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
	"time"
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
	lastSync := h.lastSyncOK
	h.mu.RUnlock()

	// Hysteresis: a recent self-fence means our connectivity (or etcd's view
	// of us) is suspect — do not churn leadership.
	if !lastFence.IsZero() && time.Since(lastFence) < haRepromoteCooldown {
		logger.Printf("HA: auto-promotion suppressed — self-fenced %s ago (cooldown %s)",
			time.Since(lastFence).Round(time.Second), haRepromoteCooldown)
		return false
	}
	// Freshness (Finding 8): never auto-promote on long-stale (or never
	// synced) state. An operator can still PromoteManually — that is the
	// break-glass, and it logs the staleness instead.
	if lastSync.IsZero() {
		logger.Printf("HA: auto-promotion refused — no successful state sync yet (manual promotion available)")
		return false
	}
	if stale := time.Since(lastSync); stale > haPromoteFreshnessWindow {
		logger.Printf("HA: auto-promotion refused — last state sync %s ago exceeds the %s freshness window "+
			"(promoting would serve stale config; use manual promotion to override)",
			stale.Round(time.Second), haPromoteFreshnessWindow)
		return false
	}

	// promote() is Acquire-gated (S2): while the leader still holds the
	// lease this is denied and we keep standing by — the fence, not a
	// timeout, arbitrates.
	h.promote("leader unreachable (lease-arbitrated auto-failover)")
	return h.IsLeader()
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
	ghostDeadline := time.Now().Add(haResumeGhostWait)
	unreachableDeadline := time.Now().Add(haResumeUnreachableWait)
	unreachable := 0
	for {
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
			time.Sleep(ghostRetryWait(st.ValidFor))
		default: // resumeUnknown, resumeRaceRetryable
			if time.Now().After(unreachableDeadline) {
				logger.Printf("HA: fencing backend still unreachable after %s — taking the leader role "+
					"READ-ONLY and continuing to retry in the background so the data plane is not "+
					"held up by a control-plane fence (CHAOS-55)", haResumeUnreachableWait)
				return false, false
			}
			unreachable++
			if unreachable == 1 {
				logger.Printf("HA: fencing backend unreachable during leader resume — retrying for up to %s "+
					"before falling back to a read-only leader role", haResumeUnreachableWait)
			}
			time.Sleep(haLeaseResumeRetryBackoff)
		}
	}
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
