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

// acquireLeaseForResume is acquireLeaseForLeadership plus ghost-lease
// handling for restarts (ADR-0005 S5): a leader that restarts WITHIN the
// lease TTL finds the key still held by its previous process's lease —
// holder == our own candidate ID with no keepaliver. Treating that as a
// real denial would demote a healthy leader on every fast restart, so we
// wait out our own ghost (bounded by the denial's reported validity plus
// margin, capped at haResumeGhostWait) and retry. A denial by ANY OTHER
// holder returns false immediately — that fence is real.
func (h *HAState) acquireLeaseForResume() bool {
	h.mu.RLock()
	p, id := h.lease, h.leaseCandidateID
	h.mu.RUnlock()
	if p == nil {
		return true
	}
	deadline := time.Now().Add(haResumeGhostWait)
	for {
		if h.acquireLeaseForLeadership("leader resume") {
			return true
		}
		ctx, cancel := context.WithTimeout(context.Background(), haLeaseOpTimeout)
		st, err := p.Read(ctx)
		cancel()
		if err != nil || st.Holder != id {
			return false // real denial (other holder) or unknown backend state
		}
		if time.Now().After(deadline) {
			logger.Printf("HA: own ghost lease did not expire within %s — giving up the resume acquire", haResumeGhostWait)
			return false
		}
		logger.Printf("HA: waiting out our own ghost lease from the previous process (valid_for=%s)", st.ValidFor)
		wait := st.ValidFor + time.Second
		if wait > 5*time.Second || wait <= time.Second {
			wait = 5 * time.Second
		}
		time.Sleep(wait)
	}
}
