package main

// saas_feed_recover.go — F3b-3: startup / crash recovery (record-driven precedence).
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §B.7 (recovery precedence), §B.8
// (crash matrix), §B.9 (idempotent resume), §B.11 (stale-LKG posture), §B.12
// (invariants). Recovery is OFFLINE — it performs NO network request. It reads only the
// FIXED durable records (never a filename / directory order / mtime), classifies the
// state deterministically, re-verifies the exact referenced immutable generation from its
// signed bytes before serving it, and installs the effective live view atomically.
//
// The five concerns are selected SEPARATELY (§B.1): the max rollback floor (never
// lowered, even under equivocation), the resumable floor-ahead candidate, the currently
// active generation, the previous LKG, and the embedded baseline. A floor NUMBER never
// selects content — content is always record-driven + digest-re-verified.

import (
	"context"
	"errors"
)

// recoveryClass distinguishes every startup outcome so F3b-4 can surface the exact
// condition (this slice returns the structured state; no metrics/alerts here).
type recoveryClass int

const (
	recoveryFreshInstall     recoveryClass = iota // no records — clean fresh install on the embedded baseline (benign)
	recoveryActiveServed                          // the committed active generation re-verified + served (LKG)
	recoveryResumed                               // a floor-ahead candidate re-verified + activation completed + served
	recoveryStaleServed                           // a committed generation past expiry, served stale (never fail-closed on age)
	recoveryEmbeddedDegraded                      // fell back to the embedded baseline (critical)
	recoveryEquivocation                          // same-version identity equivocation — floor retained, content refused (critical)
)

func (c recoveryClass) String() string {
	switch c {
	case recoveryFreshInstall:
		return "fresh_install"
	case recoveryActiveServed:
		return "active_served"
	case recoveryResumed:
		return "resumed"
	case recoveryStaleServed:
		return "stale_served"
	case recoveryEmbeddedDegraded:
		return "embedded_degraded"
	case recoveryEquivocation:
		return "equivocation"
	default:
		return "unknown"
	}
}

// recoveryResult is the structured, distinguishable recovery state (§B.11 requires every
// condition be separable). It always carries the installed live view + the max floor.
type recoveryResult struct {
	Class            recoveryClass
	Floor            floorWatermark
	FloorFromCheckpt bool
	ActiveVersion    int64 // 0 when none / embedded
	Source           effectiveSource
	Stale            bool
	Critical         bool // a degraded/equivocation state an operator must see
	GCEnabled        bool // GC may run only from a consistent, non-equivocating, committed state
	FloorHealth      floorHealth
	ActivationStatus activationReadStatus
	View             *effectiveCategoryView
	Detail           string
}

var errRecoverInternal = errors.New("saas feed recover: internal invariant violated")

// Recover runs the boot / post-crash recovery under the coordinator's serialization lock
// and installs the resulting live view. It never returns without either installing a
// re-verified generation view or the embedded baseline.
func (c *activationCoordinator) Recover(ctx context.Context) (recoveryResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return recoveryResult{}, err
	}

	arec, ast, _ := c.activation.Read()
	activeVer := int64(0)
	if ast == activationValid {
		activeVer = arec.ActiveVersion
	}
	frec := c.floor.Recover(activeVer)

	// Equivocation or corrupt-all durable state: the floor is RETAINED (never lowered),
	// content resume is refused, GC is disabled. Keep a valid LKG if the activation record
	// re-verifies; otherwise fall to the embedded baseline (critical).
	if frec.FailClosed {
		return c.recoverFailClosed(ctx, arec, ast, frec)
	}

	// Floor-ahead resumable candidate (crash after floor advance, before/at activation).
	if frec.Candidate != nil && frec.Candidate.FeedVersion > activeVer {
		if res, ok, err := c.tryResume(ctx, frec, *frec.Candidate); err != nil {
			return recoveryResult{}, err
		} else if ok {
			return res, nil
		}
		// Candidate missing/corrupt/expired/identity-mismatch: do NOT activate it; fall
		// through to the active LKG or the embedded baseline. Floor stays preserved.
	}

	// Currently active generation (the LKG) — re-verify + serve.
	if ast == activationValid {
		if res, ok, err := c.tryServeActive(ctx, arec, frec); err != nil {
			return recoveryResult{}, err
		} else if ok {
			return res, nil
		}
		return c.installEmbedded(frec, recoveryEmbeddedDegraded, true, false,
			"active generation failed offline re-verification"), nil
	}

	// No valid activation record.
	if ast == activationAbsent && frec.Health == floorHealthFresh {
		// Truly fresh install: benign embedded baseline. GC has nothing to collect but is
		// not in a degraded state, so it is not disabled.
		return c.installEmbedded(frec, recoveryFreshInstall, false, true, "fresh install"), nil
	}
	return c.installEmbedded(frec, recoveryEmbeddedDegraded, true, false,
		"no valid activation record with durable floor state"), nil
}

// recoverFailClosed handles equivocation / corrupt-all: never lower the floor, disable GC,
// keep a re-verifying LKG else embedded — all critical.
func (c *activationCoordinator) recoverFailClosed(ctx context.Context, arec activationRecord, ast activationReadStatus, frec floorRecovery) (recoveryResult, error) {
	class := recoveryEquivocation
	detail := "same-version floor equivocation: content resume refused, floor retained"
	if frec.Health == floorHealthCorruptAll {
		class = recoveryEmbeddedDegraded
		detail = "all durable floor records corrupt: floor at compiled checkpoint"
	}
	if ast == activationValid {
		if res, ok, err := c.tryServeActive(ctx, arec, frec); err != nil {
			return recoveryResult{}, err
		} else if ok {
			// A valid LKG survives, but the durable state is degraded ⇒ critical + GC off.
			res.Class = class
			res.Critical = true
			res.GCEnabled = false
			res.Detail = detail + "; serving re-verified active generation"
			return res, nil
		}
	}
	r := c.installEmbedded(frec, class, true, false, detail)
	return r, nil
}

// tryResume completes a floor-ahead candidate idempotently (§B.9): re-verify the exact
// digest-bound generation offline and, on success, write the still-missing durable records
// + cut over. Returns ok=false (no error) when the candidate cannot be safely resumed, so
// the caller falls through to the LKG / embedded baseline.
func (c *activationCoordinator) tryResume(ctx context.Context, frec floorRecovery, cand floorRecord) (recoveryResult, bool, error) {
	res, err := c.activateLocked(ctx, activateInput{
		GenerationID: cand.GenerationID,
		Provenance:   activationProvenanceResumed,
		AllowStale:   true, // a floor-ahead candidate whose manifest expired is resumed + marked stale (§B.11)
		Bind:         &generationBinding{GenerationID: cand.GenerationID, ManifestSHA256: cand.ManifestSHA256, ArtifactSHA256: cand.ArtifactSHA256},
	})
	if err != nil {
		// Missing/corrupt/expired-future/identity-mismatch/durability failure ⇒ not
		// resumable. This is a recovery fall-through, not a fatal error.
		return recoveryResult{}, false, nil
	}
	if res.Outcome != activationCommitted {
		return recoveryResult{}, false, nil
	}
	class := recoveryResumed
	if res.Stale {
		class = recoveryStaleServed
	}
	return recoveryResult{
		Class: class, Floor: frec.Floor, FloorFromCheckpt: frec.FloorFromCheckpoint,
		ActiveVersion: res.Version, Source: sourceResumed, Stale: res.Stale,
		Critical: res.Stale, GCEnabled: true, FloorHealth: frec.Health,
		ActivationStatus: activationValid, View: c.live.Current(),
		Detail: "floor-ahead candidate re-verified; activation completed idempotently",
	}, true, nil
}

// tryServeActive re-verifies the committed active generation offline and installs its
// effective view WITHOUT any durable write (the floor + activation record are already
// valid). It serves a past-expiry active generation as STALE (§B.11). Returns ok=false
// (no error) when the active generation fails offline re-verification.
func (c *activationCoordinator) tryServeActive(ctx context.Context, arec activationRecord, frec floorRecovery) (recoveryResult, bool, error) {
	if err := ctx.Err(); err != nil {
		return recoveryResult{}, false, ctx.Err()
	}
	rg, err := reverifyGeneration(c.read, c.verifier, c.genRoot, arec.GenerationID, bindingFromActivation(arec))
	if err != nil {
		return recoveryResult{}, false, nil
	}
	stale, ferr := c.classifyFreshness(rg, true) // committed active gen may be stale; never fail-closed on age
	if ferr != nil {
		// A future-dated active generation is anomalous; do not serve it.
		return recoveryResult{}, false, nil
	}
	ov, rev, oerr := c.overrides.Current()
	if oerr != nil {
		return recoveryResult{}, false, nil
	}
	view, verr := c.buildEffectiveView(rg, ov, rev, activationProvenanceCached, stale)
	if verr != nil {
		return recoveryResult{}, false, nil
	}
	c.live.Swap(view)
	setSignedFeedOwnsLiveStore(true)
	class := recoveryActiveServed
	if stale {
		class = recoveryStaleServed
	}
	return recoveryResult{
		Class: class, Floor: frec.Floor, FloorFromCheckpt: frec.FloorFromCheckpoint,
		ActiveVersion: rg.Version, Source: sourceCached, Stale: stale,
		Critical: stale, GCEnabled: true, FloorHealth: frec.Health,
		ActivationStatus: activationValid, View: view,
		Detail: "committed active generation re-verified and served",
	}, true, nil
}

// installEmbedded swaps in the compiled baseline view and returns the classified result.
// It NEVER touches the floor or activation records (the baseline is not a generation).
func (c *activationCoordinator) installEmbedded(frec floorRecovery, class recoveryClass, critical, gcEnabled bool, detail string) recoveryResult {
	view := embeddedBaselineView()
	c.live.Swap(view)
	return recoveryResult{
		Class: class, Floor: frec.Floor, FloorFromCheckpt: frec.FloorFromCheckpoint,
		ActiveVersion: 0, Source: sourceEmbedded, Stale: false,
		Critical: critical, GCEnabled: gcEnabled, FloorHealth: frec.Health,
		ActivationStatus: activationAbsent, View: view, Detail: detail,
	}
}

// currentFloorVersion is a small read-only helper for GC + tests (the max recovered floor
// version without an active-gen context).
func (c *activationCoordinator) currentFloorVersion() int64 {
	return c.floor.Recover(0).Floor.Version
}

var _ = errRecoverInternal // reserved for future strict-invariant checks
