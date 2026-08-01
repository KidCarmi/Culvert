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
	authority, err := newSaaSFeedAuthorityStore(dir)
	if err != nil {
		return nil, err
	}
	live := newFeedLiveStore()
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
	if ar.ETag != "" {
		rt.setETag(ar.ETag)
	}
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
	case acquireNotModified, acquireIdempotent:
		// 304 or same-version: recompute freshness on the CURRENT active manifest; no
		// activation, provenance unchanged. A 304 near expiry is impossible here (we sent
		// no If-None-Match near expiry), so a 304 means genuinely-unchanged upstream.
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
		rt.status.noteAttemptFailure(class, 200, canceled, "activation failed")
		return rt.failedOrCanceled(canceled)
	}
	if act.Outcome != activationCommitted {
		// Aborted to LKG (config churn / durability) or idempotent no-op: live content
		// unchanged. Treat a non-error abort-to-LKG as a no-change (LKG preserved).
		exp, stale := rt.activeExpiryAndStale()
		rt.status.noteNoChange(exp, stale)
		return refreshNoChange
	}
	view := rt.live.Current()
	delta := computeActivationDelta(prev, view)
	rt.status.noteActivation(view, delta, 200)
	return refreshActivated
}

// recordAcquireError classifies an AcquireGeneration error into a bounded class + folds
// it into the status. Returns the scheduler outcome.
func (rt *saasFeedRuntime) recordAcquireError(err error) saasFeedRefreshOutcome {
	canceled := errors.Is(err, context.Canceled) || errors.Is(err, errAcquireCanceled) || errors.Is(err, errFeedFetchCanceled)
	class, httpStatus := classifyAcquireError(err)
	rt.status.noteAttemptFailure(class, httpStatus, canceled, "acquire failed")
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

// classifyAcquireError maps an AcquireGeneration error to a bounded (class, httpStatus).
func classifyAcquireError(err error) (string, int) {
	switch {
	case errors.Is(err, errAcquireVerify):
		return saasFeedErrVerify, 0
	case errors.Is(err, errAcquireExpired), errors.Is(err, errAcquireFuture), errors.Is(err, errAcquireFresh):
		return saasFeedErrFreshness, 0
	case errors.Is(err, errAcquireFloor):
		return saasFeedErrFloor, 0
	case errors.Is(err, errAcquirePersist):
		return saasFeedErrPersist, 0
	case errors.Is(err, errFeedFetchStatus):
		return saasFeedErrHTTP, 0
	case errors.Is(err, errFeedFetchBody), errors.Is(err, errFeedFetchEncoding):
		return saasFeedErrParse, 0
	case errors.Is(err, errFeedFetchSSRF), errors.Is(err, errFeedFetchResolve),
		errors.Is(err, errFeedFetchRedirect), errors.Is(err, errFeedFetchTooMany),
		errors.Is(err, errFeedFetchURLContract), errors.Is(err, errAcquireManifest), errors.Is(err, errAcquireArtifact):
		return saasFeedErrFetch, 0
	default:
		return saasFeedErrFetch, 0
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
