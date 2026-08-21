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
