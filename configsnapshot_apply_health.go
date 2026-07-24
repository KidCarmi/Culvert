package main

import "sync/atomic"

// configSnapshotApplyFailing tracks whether the LAST real ConfigSnapshot
// apply attempt (fetchAndApply's full-snapshot path or applyDeltaReply's
// delta path, both in controlplane_client.go) was rejected — as opposed to
// configSnapshotValidatorOK (healthcheck.go), which only self-tests that the
// pure validator accepts an EMPTY baseline and has no memory of any real
// snapshot the appliance has actually received.
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
