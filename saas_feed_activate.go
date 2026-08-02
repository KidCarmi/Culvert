package main

// saas_feed_activate.go — F3b-3: the serialized activation coordinator.
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md §B.5 (commit ordering S0–S5),
// §B.6.1 (write quorum), §B.7 (record-driven selection), §B.9 (idempotent resume),
// §B.12 (invariants). ONE mutex serializes every activation AND every override-driven
// rebuild, so no two effective-store builds interleave and no policy-update race can
// expose a half-old/half-new store.
//
// Commit ordering (never a live mutation before the activation record commits):
//
//	S0  generation already durable (F3b-2)                         [precondition]
//	S1  re-verify the generation OFFLINE from its signed bytes     (§B.9)
//	S2  build the effective store off-path (feed snapshot + overrides), validate it
//	S3  floor.Advance: both floor records durable + read-back      (concern 1)
//	S4  re-check the authoritative config/override revision; then activation.Commit
//	    (activation record durable + read-back)                    (concern 2)
//	S5  ONE atomic live-store cutover (pointer swap)               (concern 4)
//	    — only AFTER S3+S4 committed; GC eligibility only after S5.
//
// A required durability failure at S3/S4 ABORTS with no live cutover (the old LKG keeps
// serving); the immutable generation stays on disk for a later resume. If the config
// revision changes before cutover, the coordinator rebuilds under the lock (bounded
// retries) rather than exposing a store built from mixed policy, and aborts to the LKG
// if churn does not settle. DORMANT: nothing in this slice calls Activate from startup
// or a scheduler.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/catoverride"
	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// maxConfigRebuildRetries bounds the rebuild loop when the authoritative config/override
// revision keeps changing before cutover (managed-DP CP epoch churn). Exhausting it
// aborts to the LKG rather than spinning.
const maxConfigRebuildRetries = 3

var (
	errActivateReverify    = errors.New("saas feed activate: candidate re-verification failed")
	errActivateFuture      = errors.New("saas feed activate: candidate generated_at beyond the accepted future skew")
	errActivateExpired     = errors.New("saas feed activate: candidate already expired (fresh activation)")
	errActivateFloorGate   = errors.New("saas feed activate: candidate not strictly greater than the recovered floor")
	errActivateStore       = errors.New("saas feed activate: effective store validation failed")
	errActivateFloorWrite  = errors.New("saas feed activate: floor quorum write failed")
	errActivateRecord      = errors.New("saas feed activate: activation record commit failed")
	errActivateConfigChurn = errors.New("saas feed activate: config/override revision churn did not settle; aborted to LKG")
	errActivateOverrides   = errors.New("saas feed activate: authoritative overrides unavailable/invalid")
	errActivateProvenance  = errors.New("saas feed activate: invalid provenance")
)

// overrideProvider yields the CURRENT authoritative override set + an opaque revision
// identity. The revision changes whenever the fleet override policy changes (a managed-DP
// CP epoch, or a local override-set fingerprint) so the coordinator can detect churn
// between build and cutover. Managed DP MUST return the CP-authoritative overrides, never
// a locally-conflicting set.
type overrideProvider interface {
	Current() (catoverride.Overrides, string, error)
}

// activationOutcome is the coordinator's typed result.
type activationOutcome int

const (
	activationCommitted  activationOutcome = iota // a new active generation was committed + cut over
	activationIdempotent                          // the generation was already the committed active one (no-op cutover)
	activationAbortedLKG                          // aborted to the existing LKG (durability failure / config churn)
)

func (o activationOutcome) String() string {
	switch o {
	case activationCommitted:
		return "committed"
	case activationIdempotent:
		return "idempotent"
	case activationAbortedLKG:
		return "aborted_lkg"
	default:
		return "unknown"
	}
}

// activationResult is the structured result handed back (and, later, to F3b-4).
type activationResult struct {
	Outcome      activationOutcome
	Version      int64
	GenerationID string
	Floor        floorWatermark
	Stale        bool // the committed generation is past expires_at (served, not fail-closed) — §B.11
	Provenance   string
	ConfigRev    string
}

// activationCoordinator owns the durable stores, the trust kernel, the live holder, and
// the override source. All state transitions run under mu.
type activationCoordinator struct {
	mu sync.Mutex

	genRoot    string
	floor      *floorStore
	activation *activationStore
	verifier   feedVerifier
	live       liveCategorySwapper
	overrides  overrideProvider
	read       reverifyReader
	checkpoint int64
	now        func() time.Time
	futureSkew time.Duration
}

// newActivationCoordinator wires the coordinator (test-friendly core; all deps explicit).
func newActivationCoordinator(genRoot string, floor *floorStore, activation *activationStore, verifier feedVerifier, live liveCategorySwapper, overrides overrideProvider, read reverifyReader, checkpoint int64, now func() time.Time, futureSkew time.Duration) *activationCoordinator {
	if now == nil {
		now = time.Now
	}
	if futureSkew <= 0 {
		futureSkew = saasFeedDefaultFutureSkew
	}
	return &activationCoordinator{
		genRoot: genRoot, floor: floor, activation: activation, verifier: verifier,
		live: live, overrides: overrides, read: read, checkpoint: checkpoint,
		now: now, futureSkew: futureSkew,
	}
}

// activateInput parameterizes one activation.
type activateInput struct {
	GenerationID string
	Provenance   string // activationProvenance* — how this generation is being activated
	ETag         string // manifest ETag when known (from the F3b-2 fetch), else ""
	// AllowStale: a fresh network activation rejects an expired candidate (F0 §10); a
	// recovery resume/cached activation of an already-committed generation serves it as
	// STALE past expiry (§B.11). Set true only on the recovery paths.
	AllowStale bool
	// Bind, when set, requires the exact digest-bound identity (floor-ahead resume).
	Bind *generationBinding
}

// Activate runs the serialized commit sequence for one generation. It returns a typed
// result and an error only on a genuine failure; an abort-to-LKG is a non-error
// activationAbortedLKG outcome. No live mutation occurs unless S3+S4 both committed.
func (c *activationCoordinator) Activate(ctx context.Context, in activateInput) (activationResult, error) {
	if !validActivationProvenance(in.Provenance) {
		return activationResult{}, fmt.Errorf("%w: %q", errActivateProvenance, in.Provenance)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.activateLocked(ctx, in)
}

func (c *activationCoordinator) activateLocked(ctx context.Context, in activateInput) (activationResult, error) {
	if err := ctx.Err(); err != nil {
		return activationResult{}, err
	}
	// S1: re-verify the exact generation OFFLINE.
	rg, err := reverifyGeneration(c.read, c.verifier, c.genRoot, in.GenerationID, in.Bind)
	if err != nil {
		return activationResult{}, fmt.Errorf("%w: %v", errActivateReverify, err)
	}
	// Freshness (current-time). Future-dated is always rejected; expiry is a reject for a
	// fresh activation and a stale-serve for a recovery activation.
	stale, err := c.classifyFreshness(rg, in.AllowStale)
	if err != nil {
		return activationResult{}, err
	}
	// Floor accept gate: strictly greater than the recovered floor for a fresh network
	// activation. A resume/cached activation of the already-active generation is exempt
	// (it re-activates the exact digest-bound generation, §B.9), handled by the store's
	// own idempotency below.
	rec := c.floor.Recover(0)
	if !in.AllowStale && rg.Version <= rec.Floor.Version {
		return activationResult{}, fmt.Errorf("%w: v%d <= floor v%d", errActivateFloorGate, rg.Version, rec.Floor.Version)
	}

	// S2 + S3 + S4 with a bounded config-rebuild loop.
	return c.commitWithConfigStability(ctx, rg, in, stale)
}

// commitWithConfigStability builds the effective store, advances the floor, and commits
// the activation record — rebuilding under the lock if the authoritative config/override
// revision changes before the cutover so a mixed-policy store is never exposed. It aborts
// to the LKG (no cutover) if churn does not settle within maxConfigRebuildRetries.
func (c *activationCoordinator) commitWithConfigStability(ctx context.Context, rg *reverifiedGeneration, in activateInput, stale bool) (activationResult, error) {
	var floorAdvanced bool
	var floorAfter floorWatermark
	for attempt := 0; attempt < maxConfigRebuildRetries; attempt++ {
		if err := ctx.Err(); err != nil {
			return activationResult{}, err
		}
		ov, rev, err := c.overrides.Current()
		if err != nil {
			return activationResult{}, fmt.Errorf("%w: %v", errActivateOverrides, err)
		}
		view, err := c.buildEffectiveView(rg, ov, rev, in.Provenance, stale)
		if err != nil {
			return activationResult{}, err
		}
		// S3: advance the floor (idempotent for the exact record) — only once.
		if !floorAdvanced {
			q, ferr := c.floor.Advance(ctx, floorRecordFor(rg))
			if ferr != nil {
				return activationResult{}, fmt.Errorf("%w: %v", errActivateFloorWrite, ferr)
			}
			floorAdvanced, floorAfter = true, q.Floor
		}
		// S4a: re-check the authoritative revision immediately before the record commit.
		// A recheck ERROR (managed-DP outage / invalid snapshot transition) means we can no
		// longer confirm the revision is unchanged, so we must NOT commit + swap the view we
		// built under the old revision — abort, leaving the live store untouched (the
		// "invalid override snapshot leaves live untouched / abort to LKG" contract). Only a
		// confirmed-unchanged revision proceeds to commit; a confirmed CHANGE rebuilds (loop).
		_, rev2, cerr := c.overrides.Current()
		if cerr != nil {
			return activationResult{}, fmt.Errorf("%w: config recheck: %v", errActivateOverrides, cerr)
		}
		if rev2 != rev {
			continue
		}
		// S4b: commit the activation record durably (read-back verified).
		arec := activationRecordFor(rg, floorAfter, rev, in.Provenance, in.ETag)
		if err := c.activation.Commit(arec); err != nil {
			return activationResult{}, fmt.Errorf("%w: %v", errActivateRecord, err)
		}
		// S5: ONE atomic live cutover, then publish single-writer ownership.
		c.live.Swap(view)
		setSignedFeedOwnsLiveStore(true)
		return activationResult{
			Outcome: activationCommitted, Version: rg.Version, GenerationID: rg.GenerationID,
			Floor: floorAfter, Stale: stale, Provenance: in.Provenance, ConfigRev: rev,
		}, nil
	}
	// Churn did not settle: the floor already ratcheted (safe — it only rejects more), but
	// we DID NOT commit a mixed-policy activation and DID NOT cut over. Abort to the LKG.
	return activationResult{Outcome: activationAbortedLKG, Version: rg.Version, GenerationID: rg.GenerationID, Floor: floorAfter, Stale: stale, Provenance: in.Provenance},
		fmt.Errorf("%w", errActivateConfigChurn)
}

// overridesEmpty reports whether an override set is a no-op (no add / recategorize /
// tombstone), so the embedded baseline can keep its "compiled" provenance unchanged.
func overridesEmpty(ov catoverride.Overrides) bool {
	return len(ov.Added) == 0 && len(ov.Recategorized) == 0 && len(ov.Tombstones) == 0
}

// rawEmbeddedView is the embedded baseline with the unchanged "compiled" provenance (no
// overrides applied).
func rawEmbeddedView() *effectiveCategoryView {
	return newEffectiveView(embeddedBaselineEntries(), effectiveCategoryView{Source: sourceEmbedded, ConfigRevision: "compiled"})
}

// composeEmbeddedForOverrides builds the embedded-baseline effective view with the CURRENT
// authoritative overrides layered on (F3b-4: override-only changes apply on the policy path
// even before the first signed activation). It PROPAGATES an override-provider error and a
// composition-validation error so a caller that must not corrupt the live view can abort
// without swapping. With no overrides it returns the raw baseline ("compiled" provenance).
// The caller holds c.mu.
func (c *activationCoordinator) composeEmbeddedForOverrides() (*effectiveCategoryView, error) {
	ov, rev, err := c.overrides.Current()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errActivateOverrides, err)
	}
	if overridesEmpty(ov) {
		return rawEmbeddedView(), nil
	}
	composed := catoverride.ComposeView(embeddedBaselineEntries(), ov)
	if verr := validateEffectiveComposition(composed); verr != nil {
		return nil, fmt.Errorf("%w: %v", errActivateStore, verr)
	}
	return newEffectiveView(composed, effectiveCategoryView{Source: sourceEmbedded, ConfigRevision: rev}), nil
}

// buildEmbeddedComposedView is the FAIL-SAFE embedded view builder for recovery's
// installEmbedded: it degrades to the raw baseline on any override error (never fail-closed
// on the taxonomy) rather than propagating. The caller holds c.mu.
func (c *activationCoordinator) buildEmbeddedComposedView() *effectiveCategoryView {
	view, err := c.composeEmbeddedForOverrides()
	if err != nil {
		return rawEmbeddedView()
	}
	return view
}

// buildEffectiveView composes the feed-owned snapshot with the current overrides OFF-PATH
// and validates the result before it can be swapped in.
func (c *activationCoordinator) buildEffectiveView(rg *reverifiedGeneration, ov catoverride.Overrides, rev, provenance string, stale bool) (*effectiveCategoryView, error) {
	composed := catoverride.ComposeView(rg.SnapshotEntries, ov)
	if err := validateEffectiveComposition(composed); err != nil {
		return nil, fmt.Errorf("%w: %v", errActivateStore, err)
	}
	return newEffectiveView(composed, effectiveCategoryView{
		Source:         provenanceToSource(provenance),
		FeedVersion:    rg.Version,
		GenerationID:   rg.GenerationID,
		ManifestSHA256: rg.ManifestSHA256,
		SnapshotSHA256: rg.SnapshotSHA256,
		GeneratedAt:    rg.GeneratedAt,
		ExpiresAt:      rg.ExpiresAt,
		ConfigRevision: rev,
		Stale:          stale,
	}), nil
}

// classifyFreshness applies current-time freshness. Future-dated (generated_at beyond
// now+skew) is always rejected. An expired candidate is rejected for a fresh activation
// (F0 §10) and served as STALE for a recovery activation (§B.11 — never fail-closed on age).
func (c *activationCoordinator) classifyFreshness(rg *reverifiedGeneration, allowStale bool) (bool, error) {
	gen, ok := canonicalUTCSecond(rg.GeneratedAt)
	if !ok {
		return false, fmt.Errorf("%w: non-canonical generated_at", errActivateReverify)
	}
	exp, ok := canonicalUTCSecond(rg.ExpiresAt)
	if !ok {
		return false, fmt.Errorf("%w: non-canonical expires_at", errActivateReverify)
	}
	now := c.now().UTC()
	if gen.After(now.Add(c.futureSkew)) {
		return false, fmt.Errorf("%w: generated_at %s", errActivateFuture, rg.GeneratedAt)
	}
	if !now.Before(exp) { // expired
		if !allowStale {
			return false, fmt.Errorf("%w: expires_at %s", errActivateExpired, rg.ExpiresAt)
		}
		return true, nil // recovery: serve stale
	}
	return false, nil
}

// floorRecordFor builds the floor/commit-intent record for a re-verified generation.
func floorRecordFor(rg *reverifiedGeneration) floorRecord {
	return floorRecord{
		SchemaVersion:  floorSchemaVersion,
		Protocol:       urlcatfeed.Protocol,
		Feed:           urlcatfeed.FeedID,
		FeedVersion:    rg.Version,
		GeneratedAt:    rg.GeneratedAt,
		GenerationID:   rg.GenerationID,
		ManifestSHA256: rg.ManifestSHA256,
		ArtifactSHA256: rg.ArtifactSHA256,
	}
}

// activationRecordFor builds the activation-state record for a committed generation.
func activationRecordFor(rg *reverifiedGeneration, floor floorWatermark, rev, provenance, etag string) activationRecord {
	floorGenAt := ""
	if !floor.GeneratedAt.IsZero() {
		floorGenAt = floor.GeneratedAt.UTC().Format(time.RFC3339)
	}
	return activationRecord{
		SchemaVersion:    activationSchemaVersion,
		Protocol:         urlcatfeed.Protocol,
		Feed:             urlcatfeed.FeedID,
		ActiveVersion:    rg.Version,
		GenerationID:     rg.GenerationID,
		ManifestSHA256:   rg.ManifestSHA256,
		ArtifactSHA256:   rg.ArtifactSHA256,
		SnapshotSHA256:   rg.SnapshotSHA256,
		GeneratedAt:      rg.GeneratedAt,
		ExpiresAt:        rg.ExpiresAt,
		ETag:             etag,
		FloorVersion:     floor.Version,
		FloorGeneratedAt: floorGenAt,
		ConfigRevision:   rev,
		Provenance:       provenance,
	}
}

func provenanceToSource(p string) effectiveSource {
	switch p {
	case activationProvenanceDownloaded:
		return sourceDownloaded
	case activationProvenanceResumed:
		return sourceResumed
	case activationProvenanceCached:
		return sourceCached
	default:
		return sourceEmbedded
	}
}

// RebuildForOverrides recomposes the live view from the CURRENTLY-ACTIVE generation and
// the current authoritative overrides, then performs ONE atomic swap — WITHOUT changing
// the active generation, the floor, or the activation record (overrides are separate
// CP-authoritative policy; the base generation is unchanged). It builds the new view
// off-path so an invalid override snapshot (provider error) leaves the live store
// untouched, and it never mutates the stored generation files. Serialized through the
// SAME mutex as Activate, so an override rebuild and an activation can never interleave.
// A no-op (no active generation) leaves any embedded baseline in place.
func (c *activationCoordinator) RebuildForOverrides(ctx context.Context) (activationResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return activationResult{}, err
	}
	arec, st, _ := c.activation.Read()
	if st != activationValid {
		// No committed signed generation ⇒ recompose the EMBEDDED baseline with the new
		// overrides and swap atomically (F3b-4 finding #5: an override-only change takes
		// effect on the policy hot path even before the first signed activation; an explicit
		// empty override set restores the raw base categories). An invalid/unavailable
		// override snapshot propagates an error, leaving the current live view UNTOUCHED.
		view, err := c.composeEmbeddedForOverrides()
		if err != nil {
			return activationResult{}, err
		}
		c.live.Swap(view)
		return activationResult{
			Outcome: activationCommitted, Version: 0,
			Provenance: activationProvenanceCached, ConfigRev: view.ConfigRevision,
		}, nil
	}
	// Re-verify the exact active generation offline (bound to the record's digests).
	rg, err := reverifyGeneration(c.read, c.verifier, c.genRoot, arec.GenerationID, bindingFromActivation(arec))
	if err != nil {
		return activationResult{}, fmt.Errorf("%w: %v", errActivateReverify, err)
	}
	stale, err := c.classifyFreshness(rg, true) // the committed active gen may be stale; never fail-closed on age
	if err != nil {
		return activationResult{}, err
	}
	ov, rev, err := c.overrides.Current()
	if err != nil {
		// Invalid/unavailable override snapshot ⇒ leave the current live store untouched.
		return activationResult{}, fmt.Errorf("%w: %v", errActivateOverrides, err)
	}
	view, err := c.buildEffectiveView(rg, ov, rev, activationProvenanceCached, stale)
	if err != nil {
		return activationResult{}, err
	}
	c.live.Swap(view)
	return activationResult{
		Outcome: activationCommitted, Version: rg.Version, GenerationID: rg.GenerationID,
		Stale: stale, Provenance: activationProvenanceCached, ConfigRev: rev,
	}, nil
}

// bindingFromActivation extracts the exact-identity binding a valid activation record
// carries (for the offline re-verify of the active generation).
func bindingFromActivation(a activationRecord) *generationBinding {
	return &generationBinding{
		GenerationID:   a.GenerationID,
		ManifestSHA256: a.ManifestSHA256,
		ArtifactSHA256: a.ArtifactSHA256,
	}
}

// validateEffectiveComposition validates the composed effective store as a whole: every
// host key is a normalized non-empty single host and every category name is non-empty. It
// does NOT re-run kernel normalization (the feed hosts are kernel-verified and the
// override hosts are catoverride-normalized) — it is the whole-store sanity gate (§B.5 S2
// "validate the effective store as a whole").
func validateEffectiveComposition(composed map[string]string) error {
	for host, cat := range composed {
		if host == "" || cat == "" {
			return fmt.Errorf("empty host or category in composed store")
		}
	}
	return nil
}
