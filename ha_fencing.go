package main

// ha_fencing.go — ADR-0005 S3: the fencing epoch enforced at every write
// sink, and propagated to Data Planes.
//
// Write-sink audit (Finding 2 / Finding 7 closure):
//
//   FENCED (this file):
//     - Enroll / RenewCert — CA issuance with the shared cluster CA: the
//       zombie-leader capability that motivated F6. Gated on
//       haIssuanceAllowed.
//     - SyncRevocations — merges revocation state across the cluster; a
//       zombie accepting revocations silently diverges the cluster view.
//     - HASync (serving side) — the bundle is STAMPED with the leader's
//       epoch; the puller (standby) verifies it against its own backend
//       read before ImportFullState (Finding 7: the fence must sit on the
//       PULLER side of a pull protocol).
//     - ConfigSnapshot — stamped; DPs reject snapshots below their
//       last-seen epoch and ratchet forward otherwise.
//
//   DELIBERATELY NOT FENCED (telemetry aggregation, not authority):
//     - PushMetrics / SyncRateLimits / PushAuditEvents — DP→CP telemetry;
//       accepting these on a zombie wastes memory but grants nothing. The
//       PushMetrics REPLY carries the epoch so DPs learn it on every
//       heartbeat.
//     - GetConfig — reads are epoch-checked on the DP side (the snapshot
//       carries the stamp), which is stronger than gating the serve.
//
// Epoch semantics: 0 = no fencing information (legacy mode / standalone) —
// checks pass. A positive epoch only ever ratchets forward.

import (
	"context"
	"sync/atomic"
)

// CurrentEpoch reports this node's fencing epoch for stamping outbound
// bundles/snapshots/issuance (0 = legacy mode or lease not held).
func (h *HAState) CurrentEpoch() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.lease == nil {
		return 0
	}
	return h.leaseEpoch
}

// haIssuanceAllowed gates the CA-issuance / cluster-state write sinks
// (ADR-0005 S3, Finding 2). Standalone (HA off): allowed — there is no
// standby to race. HA on: the node must be the leader, and in lease mode
// its write authority must be live (WriteAllowed re-checks the confirmed
// validity window at call time — the commit-time re-check of Finding 3).
func haIssuanceAllowed() (ok bool, reason string) {
	st := globalHA.Status()
	if !st.Enabled {
		return true, ""
	}
	if st.Role != "leader" {
		return false, "this node is not the HA leader"
	}
	if !globalHA.WriteAllowed() {
		return false, "fencing lease not held or unconfirmed (write authority off)"
	}
	return true, ""
}

// verifyBundleEpoch is the PULLER-side fence (Finding 7): before importing
// an HASync bundle, the standby reads the CURRENT epoch from its own lease
// backend and rejects any bundle stamped below it — a zombie leader serving
// stale state cannot be imported. Legacy mode (nil provider) skips the
// check. A backend read failure rejects the import (fail-closed: skipping
// one sync round is recoverable; importing a zombie's state is not).
func (h *HAState) verifyBundleEpoch(bundleEpoch int64) bool {
	h.mu.RLock()
	p := h.lease
	h.mu.RUnlock()
	if p == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), haLeaseOpTimeout)
	defer cancel()
	st, err := p.Read(ctx)
	if err != nil {
		logger.Printf("HA: bundle epoch verification unavailable (backend read failed) — rejecting this sync round: %v", err)
		return false
	}
	if bundleEpoch < st.Epoch {
		logger.Printf("HA: REJECTED state bundle from a stale leader (bundle epoch %d < current epoch %d)", bundleEpoch, st.Epoch)
		return false
	}
	return true
}

// ── Data Plane side: last-seen epoch ratchet ─────────────────────────────────

// dpLastSeenEpoch is the highest fencing epoch this DP has observed from any
// CP (config snapshot, heartbeat reply, issuance response). Issuance or
// config stamped BELOW it comes from a fenced-out zombie and is rejected.
var dpLastSeenEpoch atomic.Int64

// dpObserveEpoch ratchets the last-seen epoch and reports whether the
// observed value is acceptable. 0 = no fencing information (legacy CP) —
// accepted without moving the ratchet.
func dpObserveEpoch(source string, epoch int64) bool {
	if epoch <= 0 {
		return true
	}
	for {
		last := dpLastSeenEpoch.Load()
		if epoch < last {
			logger.Printf("DataPlane: REJECTED %s from a stale control plane (epoch %d < last seen %d)", sanitizeLog(source), epoch, last)
			return false
		}
		if epoch == last || dpLastSeenEpoch.CompareAndSwap(last, epoch) {
			return true
		}
	}
}

// dpHeartbeatReply is the PushMetrics response shape: the CP piggybacks its
// current epoch on every heartbeat so DPs track leadership changes even
// between config polls (ADR-0005 S3 — "the fencing token is only real once
// the recipient knows it").
type dpHeartbeatReply struct {
	OK    bool  `json:"ok"`
	Epoch int64 `json:"epoch,omitempty"`
}

// resetDPLastSeenEpochForTest clears the ratchet (test isolation).
func resetDPLastSeenEpochForTest() (restore func()) {
	old := dpLastSeenEpoch.Load()
	dpLastSeenEpoch.Store(0)
	return func() { dpLastSeenEpoch.Store(old) }
}
