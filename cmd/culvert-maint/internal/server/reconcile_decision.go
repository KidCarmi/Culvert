// Pure decision core for RISK-022 PR-E ReconcileOnStartup (slice E1).
//
// THIS FILE HAS NO SIDE EFFECTS. It runs no docker, touches no disk, and is not
// wired into startup — it is the executable spec of the reconcile decision
// table (design §0, v2). The boot hook that ACTS on these verdicts is slice E3,
// which is gated on explicit owner sign-off. Keeping the decision pure lets the
// class-correctness and fail-safe invariants the red-team demanded be pinned by
// unit tests before anything destructive is built.
//
// Corrections baked in from the v2 red-team (design §0):
//   - P0-A digest class: comparisons prefer the CLASS-INVARIANT image config
//     digest (RunningImageID/.Id, stable across tag-vs-digest pulls); the
//     manifest/repo-digest axis is prefix-normalized before intersection so a
//     stripped record field can never silently miss a prefixed capture set.
//   - P0-D bound: exhausted reconcile attempts fail loud, never loop.
//   - P0-E trust: an unvalidated record ref fails loud, never acts.
//   - (Kind,Mode) router: mode=data never enters the image table.
//   - crash-F4 / multiarch-F4: "safe boundary" phases still consult Docker truth
//     (an elided fsync that left the tag advanced is caught), and the tag fact
//     drives a converge-via-`up` branch instead of being dead input.
package server

import (
	"strings"

	"culvert-maint/internal/journal"
	"culvert-maint/internal/ops"
)

// reconcileAction is the structural decision for one interrupted record. The
// health-gated adopt-vs-rollback choice is deferred to the caller (which runs
// the probe under the conservative reconcile budget + no-offline floor); the
// pure core only decides WHICH structural branch applies.
type reconcileAction int

const (
	// actNoop: nothing to undo (confirmed safe boundary, or already on prior).
	// Caller marks the op interrupted and removes the record.
	actNoop reconcileAction = iota
	// actVerifyAdoptElseRollback: the target image is live. Caller probes health
	// (conservative budget): healthy — or a mere timeout while running==target —
	// ADOPTS (mark succeeded(reconciled)); a definitive-unhealthy signal ROLLS
	// BACK to prior (subject to the no-offline floor).
	actVerifyAdoptElseRollback
	// actRollbackToPrior: indeterminate running image + a valid, known prior.
	// Caller restores prior ONLY if the target is confirmed local (no-offline
	// floor); otherwise it degrades to actLoudStop.
	actRollbackToPrior
	// actReup: the pinned tag advanced to target but the container is not running
	// it (crash between tag and `up`). Caller converges with `compose up` — never
	// a rollback.
	actReup
	// actLoudStop: cannot safely act (invalid ref, exhausted attempts, no
	// recovery target). Caller marks failed(reason), keeps serving, leaves the
	// running stack untouched.
	actLoudStop
	// actDataManual: a mode=data rollback — never touch Docker; caller emits the
	// loud-detection surface (recovery command + /v1/status + audit).
	actDataManual
)

func (a reconcileAction) String() string {
	switch a {
	case actNoop:
		return "noop"
	case actVerifyAdoptElseRollback:
		return "verify_adopt_else_rollback"
	case actRollbackToPrior:
		return "rollback_to_prior"
	case actReup:
		return "reup"
	case actLoudStop:
		return "loud_stop"
	case actDataManual:
		return "data_manual"
	default:
		return "unknown"
	}
}

// reconcileInputs is the fully-resolved fact set the decision needs. The caller
// (E3) populates it from the journal record, a `docker image inspect
// culvert/proxy:pinned`, and `CaptureRunningProxyImage`, AFTER re-validating the
// record's refs. Digest slices are repo/manifest digests as Docker reports them
// (the `sha256:` prefix is tolerated on either side — the core normalizes).
type reconcileInputs struct {
	Kind  string        // ops.KindUpgradeApply | ops.KindRollbackCreate
	Mode  string        // "" | "image" | "data"
	Phase journal.Phase // last durable phase reached

	// Attempt bound (P0-D). Attempts is how many times THIS op_id has already
	// been reconciled; MaxAttempts is the cap (0 disables the bound).
	Attempts    int
	MaxAttempts int

	// RefValid is the caller's re-validation result (P0-E): the record's refs
	// passed validatePinnedDigestRef + image_allowlist + ref⇔digest consistency.
	// false ⇒ the record is untrustworthy and must never drive a docker action.
	RefValid bool

	// Class-invariant image CONFIG digests (primary key — stable across
	// tag-vs-digest pulls). "" when unknown.
	RunningImageID string
	TargetImageID  string
	PriorImageID   string

	// Manifest/repo digest sets (secondary axis; prefix-normalized here).
	RunningDigests []string
	TargetDigests  []string
	PriorDigests   []string
	TagDigests     []string // digests the pinned tag currently resolves to
}

// reconcileVerdict is the decision plus the audit reason.
type reconcileVerdict struct {
	Action reconcileAction
	Reason string
}

// reconcileDecision is the total, pure decision function. Ordered first-match:
// routing/guards, then the phase+Docker-truth ladder.
func reconcileDecision(in reconcileInputs) reconcileVerdict {
	// (Kind,Mode) router — a data rollback never enters the image table.
	if in.Kind == ops.KindRollbackCreate && in.Mode == "data" {
		return reconcileVerdict{actDataManual, "data_window_manual"}
	}
	// Trust gate (P0-E): an unvalidated ref must never drive a docker action.
	if !in.RefValid {
		return reconcileVerdict{actLoudStop, "invalid_record_ref"}
	}
	// Attempt bound (P0-D): never loop.
	if in.MaxAttempts > 0 && in.Attempts >= in.MaxAttempts {
		return reconcileVerdict{actLoudStop, "reconcile_exhausted"}
	}

	liveIsTarget := sameImage(in.RunningImageID, in.TargetImageID, in.RunningDigests, in.TargetDigests)
	liveIsPrior := sameImage(in.RunningImageID, in.PriorImageID, in.RunningDigests, in.PriorDigests)
	priorEqTarget := sameImage(in.PriorImageID, in.TargetImageID, in.PriorDigests, in.TargetDigests)
	tagIsTarget := digestSetsIntersect(normDigests(in.TagDigests), normDigests(in.TargetDigests))
	priorKnown := in.PriorImageID != "" || len(in.PriorDigests) > 0

	// If the new image is LIVE, verify-and-adopt regardless of phase (this also
	// catches an elided-fsync "safe boundary" record whose tag actually
	// advanced — crash-F4). When prior==target there is nothing to roll back to,
	// so adopt-or-noop, never rollback.
	if liveIsTarget {
		if priorEqTarget {
			return reconcileVerdict{actVerifyAdoptElseRollback, "live_target_prior_equals_target"}
		}
		return reconcileVerdict{actVerifyAdoptElseRollback, "live_target"}
	}
	// Already back on prior (tag never advanced, or a partial rollback landed).
	if liveIsPrior {
		return reconcileVerdict{actNoop, "already_on_prior"}
	}
	// Tag advanced to target but the container is NOT running it — crash between
	// the tag move and `up`. Converge with `up`; do not roll back a healthy
	// pending upgrade.
	if tagIsTarget {
		return reconcileVerdict{actReup, "tag_advanced_container_stale"}
	}

	// Neither target nor prior is live and the tag isn't on target.
	if safeBoundary(in.Phase) {
		// Journal says the tag never advanced AND Docker agrees (target not live,
		// tag not on target) — genuinely nothing happened.
		return reconcileVerdict{actNoop, "safe_boundary_confirmed"}
	}
	// Danger window, indeterminate running image. Restore the last known-good
	// prior if we have one; otherwise stop loud (never guess an image).
	if priorKnown {
		return reconcileVerdict{actRollbackToPrior, "indeterminate_restore_prior"}
	}
	return reconcileVerdict{actLoudStop, "no_recovery_target"}
}

// sameImage reports whether two images are the same, preferring the
// class-invariant config digest (identical across tag-vs-digest pulls) and
// falling back to a prefix-normalized manifest/repo-digest set intersection.
func sameImage(idA, idB string, digestsA, digestsB []string) bool {
	if idA != "" && idB != "" && idA == idB {
		return true
	}
	return digestSetsIntersect(normDigests(digestsA), normDigests(digestsB))
}

// safeBoundary reports whether a phase is at or before the last safe boundary
// (image pulled, fixed tag NOT advanced).
func safeBoundary(p journal.Phase) bool {
	switch p {
	case journal.PhaseAdmitted, journal.PhaseCaptured, journal.PhaseResolved, journal.PhasePulled:
		return true
	default:
		return false
	}
}

// normDigests strips the `sha256:` prefix from every element so a stripped
// record field and a prefixed capture set compare equal (P0-A prefix fix). It
// copies — the inputs are not mutated.
func normDigests(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	for i, d := range in {
		out[i] = strings.TrimPrefix(d, "sha256:")
	}
	return out
}
