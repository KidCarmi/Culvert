package main

// ha_lease.go — ADR-0005 S2: the fencing lease wired into HA leadership.
//
// A nil provider (production reality until S5 wires flags/compose/GUI) leaves
// every ADR-0004 behavior byte-identical: manual failover, term++ promotion,
// role-based write authority. With a provider set (tests use halease.Fake):
//
//   - promotion (auto / manual / planned) is Acquire-gated — denied OR
//     transport error means NO promotion (leadership cannot be taken while
//     the fence's state is unknown);
//   - the term collapses into the etcd epoch on every grant (create_revision
//     is already strictly monotonic — Finding 6);
//   - the leader runs a keepalive loop: a LOST lease self-fences immediately;
//     a transport error self-fences once the last etcd-CONFIRMED validity
//     window (minus the write margin) is exhausted — etcd is the clock,
//     local time only measures elapsed-since-confirmation (Finding 3);
//   - WriteAllowed() is the write-authority primitive surfaced on /healthz
//     in S2; stamping every write sink is S3.
//
// Self-fence demotes in-process to a read-only standby and (S4) re-enters
// standby-resync against the S0-recorded ex-standby — see ha_failover.go
// for the S4 layer (fence-gated auto-promotion, freshness, hysteresis).

import (
	"context"
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/alerts"
	"github.com/KidCarmi/Culvert/internal/halease"
)

const (
	// haLeaseOpTimeout bounds each Acquire/Renew RPC.
	haLeaseOpTimeout = 5 * time.Second
	// haLeaseWriteMargin is subtracted from the confirmed validity window
	// before trusting write authority — headroom for in-flight writes
	// (Finding 3's maxWriteLatency).
	haLeaseWriteMargin = 1 * time.Second
	// haLeaseMinTick floors the keepalive interval (validFor/3) so tests
	// with very short TTLs cannot spin.
	haLeaseMinTick = 20 * time.Millisecond
	// haLeaseMaxTick caps the keepalive interval so an operator-configured
	// long TTL cannot make loss discovery (and self-fence) arbitrarily slow.
	haLeaseMaxTick = 2 * time.Second
)

// termFromEpoch converts a fencing epoch (an etcd revision — always > 0 on
// a grant) into the HA term. The clamp is defensive: epochs are never
// negative, and a zero term is visibly wrong on /healthz rather than a
// wrapped huge value.
func termFromEpoch(epoch int64) uint64 {
	if epoch < 0 {
		return 0
	}
	return uint64(epoch)
}

// SetLeaseProvider installs the fencing-lease backend and this node's
// candidate ID. Call before leadership operations (cluster wiring / tests);
// nil provider = legacy manual-failover mode.
func (h *HAState) SetLeaseProvider(p halease.Provider, candidateID string) {
	h.mu.Lock()
	h.lease = p
	h.leaseCandidateID = candidateID
	h.mu.Unlock()
}

// acquireLeaseForLeadership gates every path to leadership. Returns true in
// legacy mode (nil provider) or on a successful grant (recording the epoch +
// confirmed validity, and collapsing term=epoch happens at the caller under
// its own lock). Denied or transport-error returns false — the caller must
// not take leadership.
func (h *HAState) acquireLeaseForLeadership(reason string) bool {
	h.mu.RLock()
	p, id := h.lease, h.leaseCandidateID
	h.mu.RUnlock()
	if p == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), haLeaseOpTimeout)
	defer cancel()
	granted, st, err := p.Acquire(ctx, id)
	if err != nil {
		logger.Printf("HA: fencing lease acquire failed (%s) — refusing leadership (fence state unknown): %v",
			sanitizeLog(reason), err)
		return false
	}
	if !granted {
		logger.Printf("HA: fencing lease held by %q (epoch=%d) — refusing leadership (%s)",
			sanitizeLog(st.Holder), st.Epoch, sanitizeLog(reason))
		return false
	}
	h.mu.Lock()
	h.leaseEpoch = st.Epoch
	h.leaseConfirmedAt = time.Now()
	h.leaseValidFor = st.ValidFor
	h.mu.Unlock()
	logger.Printf("HA: fencing lease acquired (epoch=%d, valid_for=%s) — %s", st.Epoch, st.ValidFor, sanitizeLog(reason))
	return true
}

// startLeaseKeepalive launches the renew loop (no-op in legacy mode or when
// already running). Call after taking leadership with a granted lease.
func (h *HAState) startLeaseKeepalive() {
	h.mu.Lock()
	// h.stopping: Stop() is joining — a fresh keepalive spawned now (e.g. a
	// tracked standby loop promoting mid-shutdown) would hold a channel the
	// in-flight stopLoops already missed, deadlocking the join.
	if h.lease == nil || h.leaseEpoch == 0 || h.leaseStopCh != nil || h.stopping {
		h.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	h.leaseStopCh = stop
	validFor := h.leaseValidFor
	// wg.Add INSIDE the lock: atomic with the stopping check above (an Add
	// racing Stop()'s Wait at counter 0 is WaitGroup misuse — see Stop).
	h.wg.Add(1)
	h.mu.Unlock()

	tick := validFor / 3
	if tick < haLeaseMinTick {
		tick = haLeaseMinTick
	}
	if tick > haLeaseMaxTick {
		tick = haLeaseMaxTick
	}
	go func() {
		defer h.wg.Done() // Add is in the locked section above
		h.leaseKeepaliveLoop(stop, tick)
	}()
}

// stopLeaseKeepalive halts the renew loop (idempotent).
func (h *HAState) stopLeaseKeepalive() {
	h.mu.Lock()
	if h.leaseStopCh != nil {
		close(h.leaseStopCh)
		h.leaseStopCh = nil
	}
	h.mu.Unlock()
}

func (h *HAState) leaseKeepaliveLoop(stop chan struct{}, tick time.Duration) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			if fenced := h.leaseRenewRound(); fenced {
				return
			}
		}
	}
}

// leaseRenewRound runs one keepalive round under a panic guard, returning true
// when this node self-fenced (the loop must exit).
//
// CHAOS-24 — this is the one place where panic containment is a SAFETY decision
// rather than an availability one, and getting it wrong manufactures the exact
// failure ADR-0005 exists to prevent:
//
//   - Do nothing (the pre-CHAOS-24 state): a panic here kills the process.
//     Ugly, but accidentally fail-closed — a dead node cannot dual-write.
//   - Recover and let the goroutine EXIT: catastrophic. This node keeps
//     role=leader and leaseEpoch!=0, so WriteAllowed() stays true, but nothing
//     renews the etcd lease. The lease expires, a standby legitimately acquires
//     it, and now TWO nodes believe they hold write authority — a split brain
//     invented by the very guard that was supposed to make things safer.
//   - Recover and retry blindly: also unsafe. If the panic is deterministic,
//     every round dies before reaching the validity-window check in
//     leaseRenewOnce, so the node holds write authority forever on the strength
//     of a confirmation that keeps getting older.
//
// So a panicking round is treated as exactly what it is: a round that did NOT
// confirm the lease — the same epistemic state as a transport failure, where
// "the truth is unknown". It is charged against the last CONFIRMED validity
// window and self-fences the moment that window closes. Containment therefore
// never extends this node's write authority by even one tick.
func (h *HAState) leaseRenewRound() (fenced bool) {
	if panicked := runGuarded("ha_lease_keepalive", func() {
		fenced = h.leaseRenewOnce()
	}); panicked {
		return h.fenceIfLeaseWindowElapsed(
			"fencing lease unconfirmed: keepalive round aborted by a recovered panic")
	}
	return fenced
}

// fenceIfLeaseWindowElapsed self-fences when the last etcd-CONFIRMED validity
// window has run out, mirroring the transport-failure branch of leaseRenewOnce
// (including the haLeaseWriteMargin safety margin). Returns true when the loop
// must exit — either because this node fenced, or because it no longer holds a
// lease to renew.
//
// time.Since over the monotonic clock keeps this immune to wall-clock jumps,
// same as the branch it mirrors: a clock rollback must not silently extend
// write authority.
func (h *HAState) fenceIfLeaseWindowElapsed(reason string) bool {
	h.mu.RLock()
	p, epoch := h.lease, h.leaseEpoch
	confirmedAt, validFor := h.leaseConfirmedAt, h.leaseValidFor
	h.mu.RUnlock()
	if p == nil || epoch == 0 {
		return true // no write authority left to protect; stop looping
	}
	if time.Since(confirmedAt) >= validFor-haLeaseWriteMargin {
		h.selfFence(reason)
		return true
	}
	return false
}

// leaseRenewOnce performs one keepalive round. Returns true when this node
// self-fenced (the loop must exit).
func (h *HAState) leaseRenewOnce() (fenced bool) {
	h.mu.RLock()
	p, id, epoch := h.lease, h.leaseCandidateID, h.leaseEpoch
	confirmedAt, validFor := h.leaseConfirmedAt, h.leaseValidFor
	h.mu.RUnlock()
	if p == nil || epoch == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), haLeaseOpTimeout)
	ok, validNow, err := p.Renew(ctx, id, epoch)
	cancel()
	switch {
	case err == nil && ok:
		h.mu.Lock()
		h.leaseConfirmedAt = time.Now()
		h.leaseValidFor = validNow
		h.mu.Unlock()
		return false
	case err == nil:
		// Confirmed loss: superseded or expired. Fence NOW.
		h.selfFence("fencing lease lost (superseded or expired)")
		return true
	default:
		// Transport failure: the truth is unknown. Keep retrying while the
		// last CONFIRMED window still covers us; fence the moment it ends.
		if time.Since(confirmedAt) >= validFor-haLeaseWriteMargin {
			h.selfFence(fmt.Sprintf("fencing lease unconfirmed beyond validity window (%v)", err))
			return true
		}
		logger.Printf("HA: lease keepalive transport error (retrying inside confirmed window): %v", err)
		return false
	}
}

// selfFence demotes this leader in-process to a read-only standby (ADR-0005
// S2): role persisted, write authority gone (leaseEpoch=0), promote guard
// re-armed. S4 then re-enters standby-resync against the S0-recorded
// ex-standby (enterStandbyResync below); when target/material is missing
// the node stays passive pending operator action.
func (h *HAState) selfFence(reason string) {
	h.mu.Lock()
	if h.role != "leader" {
		h.mu.Unlock()
		return
	}
	h.role = "standby"
	h.since = time.Now()
	fencedEpoch := h.leaseEpoch // capture the epoch being fenced before it is zeroed
	h.leaseEpoch = 0
	// CLOSE the keepalive stop channel rather than just nil it: when the
	// loop's own renew round fenced, it exits by returning anyway — but a
	// fence driven from OUTSIDE the loop (tests exercising leaseRenewOnce,
	// any future caller) would otherwise leave the loop ticking forever with
	// no channel left for stopLeaseKeepalive to close (Stop() then joins a
	// goroutine that never exits).
	if h.leaseStopCh != nil {
		close(h.leaseStopCh)
		h.leaseStopCh = nil
	}
	h.lastSelfFence = time.Now() // re-promotion hysteresis input (ADR-0005 S4)
	// Persist INSIDE the lock: anyone observing the demotion (IsLeader/
	// Status take h.mu) is then guaranteed the config write has completed —
	// the small file write is worth the determinism (matches EnableAsLeader).
	_ = saveHAConfig(h.snapshotConfigLocked())
	h.mu.Unlock()
	h.promoted.Store(false) // a future (fence-gated) promotion is legitimate

	logger.Printf("HA: SELF-FENCED — demoted to read-only standby: %s", sanitizeLog(reason))
	// M5: record the demotion in the failover ring (the epoch is the one being
	// fenced out, captured before the zero above).
	globalHAFailoverRing.Load().record("leader", "standby", "self-fence: "+reason, fencedEpoch, time.Now())
	go alerts.Fire("ha_self_fenced", alerts.Payload{
		Event:  "ha_self_fenced",
		Detail: "leader lost the fencing lease and demoted to read-only standby: " + reason,
		Source: "ha",
	})

	// ADR-0005 S4: resync from the S0-recorded ex-standby (the presumptive
	// new leader) so this node converges instead of serving frozen state.
	// Falls back to the passive S2 stance when target/material is missing.
	h.enterStandbyResync("self-fence")
}

// WriteAllowed is the lease-layer write-authority primitive (ADR-0005 S2).
// Legacy mode (nil provider) always allows — role-based authority stays at
// the call sites. Lease mode allows only while a grant is held AND the last
// etcd-CONFIRMED validity window (minus the write margin) still covers now.
// S3 stamps this onto every write sink; S2 surfaces it on /healthz only.
func (h *HAState) WriteAllowed() bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.lease == nil {
		return true
	}
	if h.leaseEpoch == 0 {
		return false
	}
	return time.Since(h.leaseConfirmedAt) < h.leaseValidFor-haLeaseWriteMargin
}

// probeLeaseBackend performs a read-only reachability check of the fencing-lease
// backend (M5 diagnose etcd). configured is false when no lease provider is armed
// (legacy manual-failover or standalone HA) — the caller reports that as a clean
// not-configured result, never an error. The Read is bounded by ctx and MUST NOT
// mutate lease state (Provider.Read contract). It deliberately does NOT touch the
// leaseEpoch/validity bookkeeping — this is an out-of-band diagnostic, not a
// keepalive.
func (h *HAState) probeLeaseBackend(ctx context.Context) (configured bool, st halease.Status, err error) {
	h.mu.RLock()
	p := h.lease
	h.mu.RUnlock()
	if p == nil {
		return false, halease.Status{}, nil
	}
	st, err = p.Read(ctx)
	return true, st, err
}

// leaseHealth reports the lease posture for /healthz: mode ("none" legacy /
// "lease"), current validity, and the fencing epoch (0 = not held).
func (h *HAState) leaseHealth() (mode string, valid bool, epoch int64) {
	h.mu.RLock()
	p := h.lease
	epoch = h.leaseEpoch
	h.mu.RUnlock()
	if p == nil {
		return "none", false, 0
	}
	return "lease", h.WriteAllowed(), epoch
}

// addLeaseHealth annotates an HA /healthz response with the fencing-lease
// posture (ADR-0005 S2: epoch + lease_valid). Legacy mode adds lease_mode
// "none" only, so monitors can tell the difference between "no fence
// configured" and "fence configured but not held".
func addLeaseHealth(resp map[string]any, h *HAState) {
	mode, valid, epoch := h.leaseHealth()
	resp["lease_mode"] = mode
	if mode != "none" {
		resp["lease_valid"] = valid
		resp["epoch"] = epoch
		// CHAOS-55: "read-only and working on it" is a different operator
		// decision from "read-only and stuck", and before this they looked
		// identical on every surface.
		resp["lease_recovering"] = h.leaseRecoveryActive()
	}
}
