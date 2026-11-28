// The decision for a runtime.recover record (ADR-0062 slice 6, PR 2; owner
// decisions 3, 5 and 2026-11-28).
//
// A runtime recovery puts back the image R that an upgrade this agent ran
// replaced, when that upgrade's image X keeps failing its health check. Its
// record is written before anything moves, with R as the prior, X as the
// target, phase restarted and RollbackArmed set: exactly the record an
// interrupted inline rollback of that upgrade would hold. So it is decided by
// the same branch, decideDangerPhaseV2, and executed by the same plan
// (finish_rollback_retag: tag R, `up`, gate, verify by id, audit-first
// retire), at runtime and, after a crash, by the startup reconcile. One
// executor, no second recovery path.
//
// Two things are added for this kind and nothing is taken away:
//
//   - a record that is not armed, or not at phase restarted, is not one this
//     agent writes: reported, never acted on;
//   - every verdict that tags R or starts it requires the data-compatibility
//     check (slice 6a) to have proven that R reads the data X may have
//     migrated. Unknown or incompatible is reported, never acted on.
package server

import "culvert-maint/internal/journal"

func decideRuntimeRecoverV2(in *reconcileInputsV2, ids v2ids) reconcileVerdictV2 {
	switch {
	case !in.RollbackArmed:
		return rr("runtime_recover_not_armed")
	case in.Phase != journal.PhaseRestarted:
		return rr("runtime_recover_unexpected_phase")
	}
	v := decideDangerPhaseV2(in, ids)
	if v.Action.mutatesDocker() && in.Compat != compatOK {
		if in.Compat == compatIncompatible {
			return rr("restore_incompatible")
		}
		return rr("restore_compatibility_unknown")
	}
	return v
}
