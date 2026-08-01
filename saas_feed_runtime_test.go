package main

// saas_feed_runtime_test.go — F3b-4: refresh orchestration — success→activation,
// 304/no-change provenance retention, failure leaves content unchanged, cancellation
// exclusion, disabled/waiting skip (no fetch), near-expiry unconditional ETag.

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// fakeAcquirer is an injectable generationAcquirer.
type fakeAcquirer struct {
	result AcquireResult
	err    error
	calls  int
}

func (f *fakeAcquirer) AcquireGeneration(_ context.Context, in AcquireInput) (AcquireResult, error) {
	f.calls++
	_ = in
	return f.result, f.err
}

// f3b4TestRuntime assembles a runtime around a real activation coordinator (generation g
// persisted on disk, fake verifier) plus an injected acquirer.
func f3b4TestRuntime(t *testing.T, g feedGen, acq generationAcquirer, now func() time.Time) *saasFeedRuntime {
	t.Helper()
	dir := t.TempDir()
	genRoot := dir + "/generations"
	persistRealGen(t, genRoot, g)

	floor, err := newFloorStore(dir, compiledMinFeedVersion)
	if err != nil {
		t.Fatal(err)
	}
	activation, err := newActivationStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newSaaSFeedAuthorityStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	overrides := catoverride.New()
	overrides.SetPathForTest(filepath.Join(dir, "overrides.json"))
	live := newFeedLiveStore()
	coord := newActivationCoordinator(genRoot, floor, activation, newFakeVerifier(g), live,
		feedOverrideProvider{store: overrides}, osReverifyReader, compiledMinFeedVersion, now, 0)
	return &saasFeedRuntime{
		dir: dir, genRoot: genRoot, client: acq, coord: coord, live: live,
		floor: floor, activation: activation, authority: authority, overrides: overrides,
		status: newSaaSFeedStatus(now), now: now,
	}
}

func enableStandaloneFeed(t *testing.T) {
	t.Helper()
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	swapClusterRole(t, "standalone")
	setSaaSFeedDurable(saasFeedDurable{Managed: true, Enabled: true, Protocol: saasFeedProtocolV1, SchemaVersion: saasStoreSchemaVersion})
}

func committedResult(g feedGen, etag string) AcquireResult {
	return AcquireResult{
		Outcome: acquireCommitted, ETag: etag,
		Generation: &VerifiedGeneration{
			FeedVersion:  g.Manifest.FeedVersion,
			GenerationID: feedVersionID(g.Manifest.FeedVersion),
			GeneratedAt:  g.Manifest.GeneratedAt,
			ExpiresAt:    g.Manifest.ExpiresAt,
		},
	}
}

func TestF3b4_Runtime_SuccessPipeline(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "etag-42")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)

	out := rt.runRefresh(context.Background(), "test")
	if out != refreshActivated {
		t.Fatalf("outcome = %s, want activated", out)
	}
	if v := rt.live.Current(); v == nil || v.FeedVersion != 42 {
		t.Fatalf("live view not activated: %+v", v)
	}
	snap := rt.status.Snapshot()
	if snap.State != saasFeedStateFresh || snap.Provenance != "downloaded" || snap.ActiveFeedVersion != 42 {
		t.Errorf("status wrong after activation: %+v", snap)
	}
	if snap.LastActivationDelta == nil || snap.LastActivationDelta.HostsAdded == 0 {
		t.Errorf("activation delta should report added hosts: %+v", snap.LastActivationDelta)
	}
	if rt.getETag() != "etag-42" {
		t.Errorf("etag not threaded: %q", rt.getETag())
	}
}

func TestF3b4_Runtime_NoChangeRetainsProvenance(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "etag-42")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)
	rt.runRefresh(context.Background(), "seed") // activate v42

	// Now a 304: no new generation, provenance retained, freshness recomputed.
	acq.result = AcquireResult{Outcome: acquireNotModified, ETag: "etag-42"}
	out := rt.runRefresh(context.Background(), "test")
	if out != refreshNoChange {
		t.Fatalf("outcome = %s, want no_change", out)
	}
	snap := rt.status.Snapshot()
	if snap.Provenance != "downloaded" || snap.ActiveFeedVersion != 42 || !snap.Last304 {
		t.Errorf("304 must retain provenance/version + mark 304: %+v", snap)
	}
	if snap.State != saasFeedStateFresh {
		t.Errorf("state after 304 = %s, want fresh", snap.State)
	}
}

func TestF3b4_Runtime_FailureLeavesContentUnchanged(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "etag-42")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)
	rt.runRefresh(context.Background(), "seed") // activate v42

	// Next attempt fails: live content must stay v42, failures counted, state degraded.
	acq.result = AcquireResult{}
	acq.err = errAcquireVerify
	out := rt.runRefresh(context.Background(), "test")
	if out != refreshFailed {
		t.Fatalf("outcome = %s, want failed", out)
	}
	if v := rt.live.Current(); v == nil || v.FeedVersion != 42 {
		t.Errorf("failure changed live content: %+v", v)
	}
	snap := rt.status.Snapshot()
	if snap.FailuresSinceStart != 1 || snap.ConsecutiveFailures != 1 {
		t.Errorf("failure not counted: %+v", snap)
	}
	if snap.State != saasFeedStateDegraded || snap.LastErrorClass != saasFeedErrVerify {
		t.Errorf("state/class after failure wrong: %+v", snap)
	}
}

func TestF3b4_Runtime_CancellationNotCounted(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{err: errAcquireCanceled}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)

	out := rt.runRefresh(context.Background(), "test")
	if out != refreshCanceled {
		t.Fatalf("outcome = %s, want canceled", out)
	}
	if snap := rt.status.Snapshot(); snap.FailuresSinceStart != 0 {
		t.Errorf("cancellation counted as failure: %+v", snap)
	}
}

func TestF3b4_Runtime_DisabledSkipsNoFetch(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	swapClusterRole(t, "standalone")
	setSaaSFeedDurable(saasFeedDurable{Managed: true, Enabled: false, Protocol: saasFeedProtocolV1, SchemaVersion: saasStoreSchemaVersion})
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "e")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)

	out := rt.runRefresh(context.Background(), "test")
	if out != refreshSkipped {
		t.Fatalf("disabled outcome = %s, want skipped", out)
	}
	if acq.calls != 0 {
		t.Errorf("disabled feed made %d fetch attempts — must be zero", acq.calls)
	}
	if snap := rt.status.Snapshot(); snap.State != saasFeedStateDisabled {
		t.Errorf("state = %s, want disabled", snap.State)
	}
}

func TestF3b4_Runtime_ManagedDPWaitingSkipsNoFetch(t *testing.T) {
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	swapClusterRole(t, "data-plane") // managed DP
	origEpoch := dpLastSeenEpoch.Load()
	t.Cleanup(func() { dpLastSeenEpoch.Store(origEpoch) })
	dpLastSeenEpoch.Store(0)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "e")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)
	// No authority mirror written ⇒ waiting_for_authority ⇒ zero fetches, never local defaults.

	out := rt.runRefresh(context.Background(), "test")
	if out != refreshSkipped {
		t.Fatalf("waiting outcome = %s, want skipped", out)
	}
	if acq.calls != 0 {
		t.Errorf("managed DP without authority made %d fetches — must be zero", acq.calls)
	}
	if snap := rt.status.Snapshot(); snap.State != saasFeedStateWaitingForAuthority {
		t.Errorf("state = %s, want waiting_for_authority", snap.State)
	}
}

func TestF3b4_Runtime_NearExpiryUnconditionalETag(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	// Generation expiring 2026-08-14; validity 14d.
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "etag-42")}

	// Clock well before expiry ⇒ conditional (ETag sent).
	early := func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) }
	rt := f3b4TestRuntime(t, g, acq, early)
	rt.runRefresh(context.Background(), "seed")
	cfg := SaaSFeedConfig{Refresh: 24 * time.Hour}
	if et := rt.conditionalETag(cfg); et != "etag-42" {
		t.Errorf("early: expected conditional ETag, got %q", et)
	}

	// Clock within the near-expiry window (2*24h before 2026-08-14 → after 2026-08-12).
	rt.now = func() time.Time { return time.Date(2026, 8, 13, 0, 0, 0, 0, time.UTC) }
	if et := rt.conditionalETag(cfg); et != "" {
		t.Errorf("near expiry: expected unconditional refetch (empty ETag), got %q", et)
	}
}

func TestF3b4_Runtime_ConcurrentRefreshAndStatus(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	rt := f3b4TestRuntime(t, g, &fakeAcquirer{result: committedResult(g, "e")}, f3b3Now)

	var wg sync.WaitGroup
	ctx := context.Background()
	for i := 0; i < 8; i++ {
		wg.Add(3)
		go func() { defer wg.Done(); rt.runRefresh(ctx, "loop") }()
		go func() { defer wg.Done(); _ = rt.status.Snapshot() }()
		go func() { defer wg.Done(); rt.manualRefresh(ctx) }()
	}
	wg.Wait()
	// No torn state: the live view is the activated generation (or embedded), never a blend.
	if v := rt.live.Current(); v != nil && v.FeedVersion != 42 && v.FeedVersion != 0 {
		t.Errorf("unexpected live version after concurrent refresh: %d", v.FeedVersion)
	}
}

func TestF3b4_ClassifyAcquireError(t *testing.T) {
	cases := map[error]string{
		errAcquireVerify:      saasFeedErrVerify,
		errAcquireExpired:     saasFeedErrFreshness,
		errAcquireFuture:      saasFeedErrFreshness,
		errAcquireFloor:       saasFeedErrFloor,
		errAcquirePersist:     saasFeedErrPersist,
		errFeedFetchStatus:    saasFeedErrHTTP,
		errFeedFetchSSRF:      saasFeedErrFetch,
		errors.New("unknown"): saasFeedErrFetch,
	}
	for err, want := range cases {
		if got, _ := classifyAcquireError(err); got != want {
			t.Errorf("classify(%v) = %s, want %s", err, got, want)
		}
	}
}
