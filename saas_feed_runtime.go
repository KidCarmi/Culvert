package main

// saas_feed_runtime.go — F3b-4: the signed-feed runtime coordinator + refresh
// orchestrator.
//
// This ties the F3b-2 one-shot acquire pipeline to the F3b-3 activation transaction and
// the runtime status model. ONE coordinator owns the durable stores, the trust kernel,
// the live view, and the authoritative override source. A single run-mutex serializes
// EVERY refresh (scheduled AND manual) so no two acquire/activation cycles interleave —
// the codebase's serialization-over-singleflight pattern (release_api.go runRefresh).
//
// A refresh cycle is: resolve config + authority → readiness gate → AcquireGeneration
// (fetch → verify → immutable-generation commit) → on a new candidate, the F3b-3
// activation transaction (re-verify → floor quorum → activation record → atomic cutover)
// → status update. Only a strictly-greater network version can activate; any failure
// leaves the live content unchanged and never deletes the LKG; shutdown cancellation is
// never a failure; integrity failures collapse to bounded error classes (never raw
// untrusted strings). Manual and scheduled refresh share this exact path.

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// saasFeedMaxNearExpiryWindow caps the near-expiry unconditional-refetch window so a
// very long refresh cadence cannot make every fetch unconditional.
const saasFeedMaxNearExpiryWindow = 7 * 24 * time.Hour

// feedOverrideProvider is the coordinator's authoritative override source. On every node
// it reads the durable override store (overrides.json); its opaque revision is the
// deterministic override fingerprint (changes iff the override set changes), which the
// coordinator uses to detect config churn between build and cutover. On a managed DP the
// store holds the CP-authoritative overrides (validated consistent by the authority
// resolver before the scheduler runs).
type feedOverrideProvider struct{ store *catoverride.Store }

func (p feedOverrideProvider) Current() (catoverride.Overrides, string, error) {
	ov := p.store.Get()
	return ov, saasFeedOverridesFingerprint(ov), nil
}

// saasFeedRefreshOutcome classifies one refresh cycle for the scheduler's backoff logic.
type saasFeedRefreshOutcome int

const (
	refreshSkipped   saasFeedRefreshOutcome = iota // readiness gate: disabled / waiting / not-authoritative
	refreshNoChange                                // 304 / same-version idempotent — nothing activated
	refreshActivated                               // a strictly-greater generation activated
	refreshFailed                                  // an attempt failed (drives backoff)
	refreshCanceled                                // shutdown cancellation (NOT a failure)
)

func (o saasFeedRefreshOutcome) String() string {
	switch o {
	case refreshSkipped:
		return "skipped"
	case refreshNoChange:
		return "no_change"
	case refreshActivated:
		return "activated"
	case refreshFailed:
		return "failed"
	case refreshCanceled:
		return "canceled"
	default:
		return "unknown"
	}
}

// generationAcquirer is the F3b-2 one-shot acquire seam (production is *saasFeedClient;
// tests inject a fake so orchestration is exercised without the network).
type generationAcquirer interface {
	AcquireGeneration(ctx context.Context, in AcquireInput) (AcquireResult, error)
}

// saasFeedRuntime owns the wired signed-feed engine. All refresh cycles run under runMu.
type saasFeedRuntime struct {
	dir     string
	genRoot string

	client     generationAcquirer
	coord      *activationCoordinator
	live       *feedLiveStore
	floor      *floorStore
	activation *activationStore
	authority  *saasFeedAuthorityStore
	overrides  *catoverride.Store
	status     *saasFeedStatus
	now        func() time.Time

	runMu sync.Mutex // serializes every refresh (manual + scheduled)

	etagMu sync.Mutex
	etag   string // last manifest ETag (seeded from the activation record on recovery)

	refreshIntervalNs atomic.Int64 // last resolved effective refresh cadence (ns), read by the scheduler
}

// currentInterval reports the last-resolved effective refresh cadence (default until the
// first resolve). Read by the scheduler so an authoritative interval change reschedules.
func (rt *saasFeedRuntime) currentInterval() time.Duration {
	ns := rt.refreshIntervalNs.Load()
	if ns <= 0 {
		return saasFeedDefaultRefresh
	}
	return time.Duration(ns)
}

// newSaaSFeedRuntime wires the production runtime rooted at dir (<dataDir>/saas_feed).
func newSaaSFeedRuntime(dir string, overrides *catoverride.Store, status *saasFeedStatus, now func() time.Time) (*saasFeedRuntime, error) {
	if now == nil {
		now = time.Now
	}
	genRoot := filepath.Join(dir, "generations")
	client, err := newProductionSaaSFeedClient(genRoot)
	if err != nil {
		return nil, err
	}
	floor, err := newFloorStore(dir, compiledMinFeedVersion)
	if err != nil {
		return nil, err
	}
	activation, err := newActivationStore(dir)
	if err != nil {
		return nil, err
	}
	// Re-use the authority store wired early (before the DP last-good replay, F3b-4
	// finding #2) when present; otherwise construct it now. Both target the same file.
	authority := globalSaaSFeedAuthorityStore
	if authority == nil {
		authority, err = newSaaSFeedAuthorityStore(dir)
		if err != nil {
			return nil, err
		}
	}
	// Use the PROCESS-WIDE effective-view holder the policy hot path reads, so a signed
	// cutover / override recompose is observed by matchCategory/lookupHostCategory as a
	// single atomic pointer swap (F3b-4 hot-path routing).
	live := saasEffectiveView
	coord := newActivationCoordinator(genRoot, floor, activation, client.verifier, live,
		feedOverrideProvider{store: overrides}, osReverifyReader, compiledMinFeedVersion, now, saasFeedDefaultFutureSkew)
	return &saasFeedRuntime{
		dir: dir, genRoot: genRoot, client: client, coord: coord, live: live,
		floor: floor, activation: activation, authority: authority, overrides: overrides,
		status: status, now: now,
	}, nil
}

// ─── ETag (seeded durably from the activation record) ──────────────────────────────

func (rt *saasFeedRuntime) getETag() string {
	rt.etagMu.Lock()
	defer rt.etagMu.Unlock()
	return rt.etag
}

func (rt *saasFeedRuntime) setETag(v string) {
	rt.etagMu.Lock()
	rt.etag = v
	rt.etagMu.Unlock()
}

// ─── authority resolution (reads the process globals) ──────────────────────────────

func (rt *saasFeedRuntime) resolveAuthority() feedAuthorityResolution {
	auth := currentFeedAuthority()
	var mrec saasFeedAuthorityRecord
	mst := saasFeedAuthorityAbsent
	if auth == authorityManagedDP && rt.authority != nil {
		mrec, mst, _ = rt.authority.Read()
	}
	return resolveFeedAuthority(resolveFeedAuthorityInput{
		Authority:    auth,
		Durable:      getSaaSFeedDurable(),
		Overrides:    rt.overrides.Get(),
		MirrorRecord: mrec,
		MirrorStatus: mst,
		EpochFloor:   dpLastSeenEpoch.Load(),
	})
}

// ─── startup / crash recovery (offline) ────────────────────────────────────────────

// recover runs the record-driven offline recovery, installs the recovered view, seeds
// the ETag from the durable activation record, and folds the outcome into the status.
func (rt *saasFeedRuntime) recover(ctx context.Context) (recoveryResult, error) {
	rt.status.noteRecoveryStart()
	res, err := rt.coord.Recover(ctx)
	if err != nil {
		// A recovery error is itself surfaced (it should be rare — Recover installs the
		// embedded baseline rather than erroring on content problems).
		rt.status.noteAttemptFailure(saasFeedErrInternal, 0, errors.Is(err, context.Canceled), "recovery error")
		return recoveryResult{}, err
	}
	rt.status.noteRecovery(res)
	rt.noteOverrideFootprint()
	saasFeedRecordRecovery(res)
	if arec, st, _ := rt.activation.Read(); st == activationValid {
		rt.setETag(arec.ETag)
	}
	return res, nil
}

// ─── one refresh cycle (serialized: manual + scheduled) ─────────────────────────────

// runRefresh performs one full acquire→activate cycle under the run mutex (the single
// serialization point: a scheduled tick and a manual refresh can never overlap). Metrics
// and latched alerts are recorded/fired AFTER the lock releases (no dispatch under a
// mutex). trigger is a bounded label ("startup"/"loop"/"manual") for logging only.
func (rt *saasFeedRuntime) runRefresh(ctx context.Context, trigger string) saasFeedRefreshOutcome {
	rt.runMu.Lock()
	outcome := rt.runRefreshLocked(ctx)
	rt.runMu.Unlock()
	rt.recordAndAlert(outcome)
	if outcome == refreshFailed && logger != nil {
		logger.Printf("SaaSFeed: %s refresh failed (serving last-known-good; class=%s)", sanitizeLog(trigger), rt.status.Snapshot().LastErrorClass)
	}
	return outcome
}

// manualRefresh runs one refresh cycle for the admin API, returning ran=false WITHOUT
// blocking when a refresh (scheduled or manual) is already in flight — deterministic
// "in_progress" with no second concurrent refresh (the run-mutex is the singleflight).
func (rt *saasFeedRuntime) manualRefresh(ctx context.Context) (outcome saasFeedRefreshOutcome, ran bool) {
	if !rt.runMu.TryLock() {
		return refreshSkipped, false
	}
	outcome = rt.runRefreshLocked(ctx)
	rt.runMu.Unlock()
	rt.recordAndAlert(outcome)
	return outcome, true
}

// recordAndAlert folds one refresh outcome into metrics + latched alerts (called after
// the run-mutex releases — no dispatch under a lock).
func (rt *saasFeedRuntime) recordAndAlert(outcome saasFeedRefreshOutcome) {
	snap := rt.status.Snapshot()
	saasFeedRecordRefreshOutcome(outcome, snap.LastErrorClass)
	evaluateSaaSFeedAlerts(snap)
}

// runRefreshLocked is the refresh cycle body; the caller holds runMu.
func (rt *saasFeedRuntime) runRefreshLocked(ctx context.Context) saasFeedRefreshOutcome {
	res := rt.resolveAuthority()
	rt.status.noteConfig(res)
	rt.refreshIntervalNs.Store(int64(res.Config.Refresh))
	if res.WaitingForAuthority {
		rt.status.noteWaitingForAuthority(res.Detail)
		return refreshSkipped
	}
	// Fetch ONLY under explicit enablement (managed && enabled). A default/unmanaged
	// install is dormant — zero requests to the (pre-F6, unpublished) official host.
	if !res.Config.runtimeEnabled() {
		rt.status.noteDisabled()
		return refreshSkipped
	}

	floorRec := rt.floor.Recover(rt.activeVersion())
	priorETag := rt.conditionalETag(res.Config)

	rt.status.noteSyncStart()
	defer rt.status.noteSyncEnd()

	ar, err := rt.client.AcquireGeneration(ctx, AcquireInput{
		Config:         res.Config,
		Authority:      res.Authority,
		SnapshotReady:  res.Ready,
		RecoveredFloor: floorRec.Floor.Version,
		PriorETag:      priorETag,
		Now:            rt.now,
		FutureSkew:     saasFeedDefaultFutureSkew,
	})
	if err != nil {
		return rt.recordAcquireError(err)
	}
	// NOTE (F3b-4 finding #4): the observed ETag is NOT committed here. It is advanced only
	// once we know the candidate is the live generation — a true 304 keeps the current ETag,
	// a committed activation adopts the new one, and a FAILED activation deliberately retains
	// the previous ETag so the next poll re-fetches the candidate instead of a 304 masking
	// the failed activation as fresh. applyAcquireResult owns that decision per outcome.
	return rt.applyAcquireResult(ctx, ar)
}

// applyAcquireResult maps a successful (non-error) AcquireResult to the activation +
// status update. Split out to keep runRefresh under the cyclop bound.
func (rt *saasFeedRuntime) applyAcquireResult(ctx context.Context, ar AcquireResult) saasFeedRefreshOutcome {
	switch ar.Outcome {
	case acquireNoFetch:
		// Readiness rejected before any network I/O (defense-in-depth; the outer gate
		// already handled disabled/waiting). Not a failure.
		return refreshSkipped
	case acquireNotModified:
		// TRUE HTTP 304: upstream unchanged since the ETag we sent (which belongs to the
		// active generation). Recompute freshness on the CURRENT active manifest; no
		// activation, provenance unchanged, and the ETag stays as-is. A 304 near expiry is
		// impossible here (we sent no If-None-Match near expiry), so it means genuinely
		// unchanged upstream.
		exp, stale := rt.activeExpiryAndStale()
		rt.status.noteNoChange(exp, stale)
		return refreshNoChange
	case acquireIdempotent:
		// The verified generation bytes already existed on disk (F3b-4 finding #3). This is
		// NOT a 304: it carries a full verified Generation. Two cases, distinguished by
		// version:
		//   (a) it IS the currently-active generation (a near-expiry unconditional refetch)
		//       — a genuine no-change; refresh the ETag to the just-fetched manifest's.
		//   (b) it is an ORPHAN — persisted before a crash that interrupted its floor/
		//       activation commit, so it is on disk yet never became live and is strictly
		//       newer than the active generation. It MUST run the activation coordinator so
		//       its floor/activation transaction completes; mere file existence is NOT a
		//       successful activation.
		// Re-activating an already-active generation would trip the strictly-greater floor
		// gate, so only a genuinely-newer orphan is routed to activation.
		if ar.Generation != nil && ar.Generation.FeedVersion > rt.activeVersion() {
			return rt.activateAcquired(ctx, ar)
		}
		if ar.ETag != "" {
			rt.setETag(ar.ETag) // the refetched bytes ARE the active generation — ETag is valid
		}
		exp, stale := rt.activeExpiryAndStale()
		rt.status.noteNoChange(exp, stale)
		return refreshNoChange
	case acquireCommitted:
		return rt.activateAcquired(ctx, ar)
	default:
		rt.status.noteAttemptFailure(saasFeedErrInternal, 0, false, "unknown acquire outcome")
		return refreshFailed
	}
}

// activateAcquired runs the F3b-3 activation transaction for a freshly-committed
// generation and folds the outcome into the status. A strictly-greater version is
// guaranteed by the acquire floor gate; the coordinator re-checks the floor.
func (rt *saasFeedRuntime) activateAcquired(ctx context.Context, ar AcquireResult) saasFeedRefreshOutcome {
	prev := rt.live.Current()
	act, err := rt.coord.Activate(ctx, activateInput{
		GenerationID: ar.Generation.GenerationID,
		Provenance:   activationProvenanceDownloaded,
		ETag:         ar.ETag,
	})
	if err != nil {
		canceled := errors.Is(err, context.Canceled)
		class := saasFeedErrPersist
		switch {
		case errors.Is(err, errActivateReverify):
			class = saasFeedErrVerify
		case errors.Is(err, errActivateFloorGate), errors.Is(err, errActivateFloorWrite):
			class = saasFeedErrFloor
		case errors.Is(err, errActivateExpired), errors.Is(err, errActivateFuture):
			class = saasFeedErrFreshness
		case errors.Is(err, errActivateConfigChurn), errors.Is(err, errActivateOverrides):
			class = saasFeedErrConfig
		}
		// Activation FAILED: the previous LKG is still live. Deliberately do NOT advance the
		// ETag (finding #4) — leaving it retained means the next poll re-fetches this
		// candidate rather than receiving a 304 that would mask the failed activation as a
		// successful no-change and stall re-activation until the origin ETag changes.
		rt.status.noteAttemptFailure(class, 200, canceled, "activation failed")
		return rt.failedOrCanceled(canceled)
	}
	if act.Outcome != activationCommitted {
		// Aborted to LKG (config churn / durability) or idempotent no-op: live content
		// unchanged, so the ETag must keep matching the still-live generation — do NOT
		// advance it. Treat a non-error abort-to-LKG as a no-change (LKG preserved).
		exp, stale := rt.activeExpiryAndStale()
		rt.status.noteNoChange(exp, stale)
		return refreshNoChange
	}
	// Cutover committed: the candidate is now the live generation, so its manifest ETag is
	// the active ETag. Advance it ONLY now — never before we know activation succeeded.
	if ar.ETag != "" {
		rt.setETag(ar.ETag)
	}
	view := rt.live.Current()
	delta := computeActivationDelta(prev, view)
	rt.status.noteActivation(view, delta)
	rt.noteOverrideFootprint()
	return refreshActivated
}

// recomposeOverrides rebuilds and atomically swaps the effective category view for the
// CURRENT authoritative overrides with NO network fetch (F3b-4 finding #5). An override-only
// change therefore takes effect on the policy hot path immediately — it does not depend on a
// new feed generation or a non-304 response (a 304 is irrelevant to whether overrides apply).
// It recomposes onto the committed signed generation when one is active, else onto the
// embedded baseline. Serialized through the coordinator mutex, so it can never interleave
// with a signed activation and readers observe only a complete old/new view. An invalid or
// unavailable override snapshot leaves the live view UNTOUCHED (logged, no swap).
func (rt *saasFeedRuntime) recomposeOverrides(ctx context.Context) {
	res, err := rt.coord.RebuildForOverrides(ctx)
	if err != nil {
		if logger != nil {
			logger.Printf("SaaSFeed: override recompose failed (previous view unchanged): %s", sanitizeLog(err.Error()))
		}
		return
	}
	if res.Outcome == activationCommitted {
		rt.noteOverrideFootprint()
	}
}

// recomposeSignedFeedOverrides triggers a local, no-network effective-view recompose for the
// current authoritative overrides (F3b-4 finding #5). Safe no-op when the signed-feed
// lifecycle is unarmed. Call AFTER the durable override set has been updated (admin PUT /
// import / config-version rollback / accepted CP snapshot).
func recomposeSignedFeedOverrides() {
	rt := globalSaaSFeedRuntime
	if rt == nil {
		return
	}
	rt.recomposeOverrides(resolveLifecycleCtx())
}

// noteOverrideFootprint publishes the current applied-override count + revision so the
// status/API/metrics reflect the composed override footprint alongside the served view.
func (rt *saasFeedRuntime) noteOverrideFootprint() {
	ov := rt.overrides.Get()
	count := len(ov.Added) + len(ov.Recategorized) + len(ov.Tombstones)
	rt.status.noteOverrides(count, saasFeedOverridesFingerprint(ov))
}

// recordAcquireError classifies an AcquireGeneration error into a bounded class + folds
// it into the status. Returns the scheduler outcome.
func (rt *saasFeedRuntime) recordAcquireError(err error) saasFeedRefreshOutcome {
	canceled := errors.Is(err, context.Canceled) || errors.Is(err, errAcquireCanceled) || errors.Is(err, errFeedFetchCanceled)
	// The acquire error sentinels do not carry an HTTP status, so httpStatus is 0 here
	// (the HTTP class is still distinguished via saasFeedErrHTTP).
	rt.status.noteAttemptFailure(classifyAcquireError(err), 0, canceled, "acquire failed")
	return rt.failedOrCanceled(canceled)
}

func (rt *saasFeedRuntime) failedOrCanceled(canceled bool) saasFeedRefreshOutcome {
	if canceled {
		return refreshCanceled
	}
	return refreshFailed
}

// ─── helpers ────────────────────────────────────────────────────────────────────────

// activeVersion returns the committed active generation version (0 if none) for the
// floor recovery's active-gen context.
func (rt *saasFeedRuntime) activeVersion() int64 {
	if v := rt.live.Current(); v != nil {
		return v.FeedVersion
	}
	return 0
}

// activeExpiryAndStale reads the current live view's expiry and whether it is now past.
func (rt *saasFeedRuntime) activeExpiryAndStale() (time.Time, bool) {
	live := rt.live.Current()
	if live == nil || live.FeedVersion == 0 {
		return time.Time{}, false
	}
	exp, ok := canonicalUTCSecond(live.ExpiresAt)
	if !ok {
		return time.Time{}, false
	}
	return exp, !rt.now().Before(exp)
}

// conditionalETag decides the If-None-Match value for the next fetch. Near/after the
// active manifest's expiry it returns "" (UNCONDITIONAL refetch) so a CDN cannot pin
// staleness via a false 304 (F0 §10 / §B.11); otherwise it returns the last ETag. It
// only sends an ETag when there is an active generation whose ETag it belongs to.
func (rt *saasFeedRuntime) conditionalETag(cfg SaaSFeedConfig) string {
	et := rt.getETag()
	if et == "" {
		return ""
	}
	live := rt.live.Current()
	if live == nil || live.FeedVersion == 0 {
		return "" // no active generation the ETag belongs to — fetch unconditionally
	}
	exp, ok := canonicalUTCSecond(live.ExpiresAt)
	if !ok {
		return et
	}
	window := 2 * cfg.Refresh
	if window > saasFeedMaxNearExpiryWindow {
		window = saasFeedMaxNearExpiryWindow
	}
	if !rt.now().Add(window).Before(exp) {
		return "" // within the near-expiry window (or past): unconditional refetch
	}
	return et
}

// classifyAcquireError maps an AcquireGeneration error to a bounded failure class.
func classifyAcquireError(err error) string {
	switch {
	case errors.Is(err, errAcquireVerify):
		return saasFeedErrVerify
	case errors.Is(err, errAcquireExpired), errors.Is(err, errAcquireFuture), errors.Is(err, errAcquireFresh):
		return saasFeedErrFreshness
	case errors.Is(err, errAcquireFloor):
		return saasFeedErrFloor
	case errors.Is(err, errAcquirePersist):
		return saasFeedErrPersist
	case errors.Is(err, errFeedFetchStatus):
		return saasFeedErrHTTP
	case errors.Is(err, errFeedFetchBody), errors.Is(err, errFeedFetchEncoding):
		return saasFeedErrParse
	default:
		return saasFeedErrFetch
	}
}

// computeActivationDelta diffs two immutable composed views by host key, reporting hosts
// added / removed / recategorized. Same-package access to the unexported entries map.
func computeActivationDelta(prev, next *effectiveCategoryView) saasFeedActivationDelta {
	var d saasFeedActivationDelta
	var prevEntries, nextEntries map[string]string
	if prev != nil {
		prevEntries = prev.entries
	}
	if next != nil {
		nextEntries = next.entries
	}
	for h, c := range nextEntries {
		pc, ok := prevEntries[h]
		switch {
		case !ok:
			d.HostsAdded++
		case pc != c:
			d.HostsChanged++
		}
	}
	for h := range prevEntries {
		if _, ok := nextEntries[h]; !ok {
			d.HostsRemoved++
		}
	}
	return d
}
