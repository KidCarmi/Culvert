package main

import "sync/atomic"

// configSnapshotApplyFailing tracks whether the LAST real ConfigSnapshot
// apply attempt (fetchAndApply's full-snapshot path or applyDeltaReply's
// delta path, both in controlplane_client.go) was rejected — as opposed to
// configSnapshotValidatorOK (healthcheck.go), which only self-tests that the
// pure validator accepts an EMPTY baseline and has no memory of any real
// snapshot the appliance has actually received.
//
// A received config payload passes through this outcome model:
//
//	received → parsed → validated → fenced → synchronized → applied
//
// markConfigSnapshotApplyRejected is called at every PAYLOAD-CONTENT
// rejection point in that chain:
//   - parsed:       malformed full-snapshot JSON, malformed delta-remainder
//     JSON (fetchAndApply / applyDeltaReply's json.Unmarshal failures)
//   - validated:    validateConfigSnapshot rejects the full snapshot or the
//     delta remainder (over-cap or otherwise structurally invalid)
//   - synchronized: syncSnapshotIdPProfiles fails to apply the IdP profiles
//   - applied:      applyConfigSnapshot rejects the full snapshot, or
//     applyBlocklistDeltaSnapshot rejects the delta (drift/fingerprint
//     mismatch)
//
// The "fenced" step (dpObserveEpoch rejecting a stale-leader epoch stamp) is
// DELIBERATELY excluded: a fencing rejection is a leadership/epoch-topology
// condition — already observable via the HA lease/fencing surface — not a
// judgment about whether the config CONTENT itself is valid, and folding it
// in here would conflate two different failure domains behind one signal.
//
// Default false (healthy): a node that has never received/applied a
// snapshot (CP-only, standalone, or a DP that hasn't polled yet) has
// observed no failure, so it reads healthy — the same optimistic-default
// posture as dpControlPlanePollFailing (readyz_dp_health.go).
var configSnapshotApplyFailing atomic.Bool

// markConfigSnapshotApplyRejected records that the last real snapshot/delta
// apply attempt was rejected (parse, validation, IdP sync, or apply
// failure) — called from the exact call sites in controlplane_client.go
// that already detect this and log it.
func markConfigSnapshotApplyRejected() { configSnapshotApplyFailing.Store(true) }

// markConfigSnapshotApplyOK records a successful real snapshot/delta apply,
// clearing any previously recorded failure.
func markConfigSnapshotApplyOK() { configSnapshotApplyFailing.Store(false) }

// lastConfigSnapshotApplyOK reports whether the last real apply attempt (if
// any) succeeded. True when no attempt has been recorded yet — there is
// nothing to invalidate.
func lastConfigSnapshotApplyOK() bool { return !configSnapshotApplyFailing.Load() }

// ── Did a round die INSIDE the mutating apply? (CHAOS-71, Codex P2) ──────────
//
// configSnapshotApplyInterrupted separates the two ways a config round can
// fail, which the outcome model above deliberately does not distinguish because
// until CHAOS-71 only one of them was survivable.
//
// A PRE-mutation failure (transport, parse, validate, fence, or a panic in any
// of them) leaves the node enforcing its last-known-good config, whole and
// coherent. A POST-mutation interruption does not: applyConfigSnapshot replaces
// blocklist, admission, policy, IdP, category and MCP state sequentially with
// no rollback, so a round that dies partway leaves a blend of two generations
// live.
//
// Why this exists. guardedConfigRound first marked the apply rejected on ANY
// panicking round, and that is wrong in both directions:
//
//   - it OVER-reports: a panic in the RPC itself claims the configuration
//     CONTENT was rejected when no apply was attempted, and because the
//     "unchanged" sentinel and the delta no-op both return without reaching
//     markConfigSnapshotApplyOK (controlplane_client.go), the false latch would
//     then persist on the operator contract until the CP published a new
//     version — indefinitely on a steady-state cluster;
//   - it UNDER-reports what matters: "rejected" is the same word used for a
//     snapshot refused before any mutation, so the one outcome an operator most
//     needs to tell apart — the node is serving a half-applied config — is
//     indistinguishable from the benign case.
//
// How the marker survives the panic. begin…() is called once, immediately
// before the mutating region, and end…() once immediately after it returns —
// deliberately NOT via defer, because a deferred clear runs during panic
// unwinding and would erase the very fact being recorded before runGuarded's
// recover could read it. The region is a single function call
// (applySnapshotMutations), so there is exactly one begin and one end and a
// future early return inside the region cannot bypass the clear; only a panic
// crossing the region can, which is precisely the condition. Keeping the single
// recover in runGuarded also preserves the original fault's stack in the crash
// record, which a recover-and-re-panic inside the apply would have replaced.
//
// This is also the signal a future readiness row would consume: it is the one
// that means "this node cannot vouch for its policy coherence", as opposed to
// the pre-mutation rejections that must never gate readiness (gating on those
// would eject healthy nodes serving last-known-good config — see
// readyz_dp_health.go on why its DP rows are report-only). That row is NOT
// added here; see the CHAOS-71 review's residual risk.
var configSnapshotApplyInterrupted atomic.Bool

// beginConfigSnapshotApplyMutation marks the start of the mutating region.
func beginConfigSnapshotApplyMutation() { configSnapshotApplyInterrupted.Store(true) }

// endConfigSnapshotApplyMutation marks its normal completion (success or a
// reported failure). Never call this through defer — see above.
func endConfigSnapshotApplyMutation() { configSnapshotApplyInterrupted.Store(false) }

// consumeConfigSnapshotApplyInterrupted reports whether the last mutating
// region failed to complete, and clears the marker so one interrupted apply is
// accounted once and a later pre-mutation panic cannot read a stale true.
func consumeConfigSnapshotApplyInterrupted() bool {
	return configSnapshotApplyInterrupted.Swap(false)
}
