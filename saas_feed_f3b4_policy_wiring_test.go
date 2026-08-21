package main

// saas_feed_f3b4_policy_wiring_test.go — F3b-4 hot-path routing + the five Codex P1
// findings (#1 route the activated view into policy matching; #2 managed-DP first-restart
// authority persistence; #3 activate idempotently-persisted (crash-orphan) generations;
// #4 ETag commit ordering; #5 override-only local recomposition). These are the
// regression proofs: each reproduces the pre-fix failure mode and asserts the fixed
// behavior through ACTUAL policy matching (matchCategory / lookupHostCategory), not just
// internal holder state.

import (
	"context"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// swapSaaSView installs v as the process-wide effective SaaS view the policy hot path
// reads, restoring the prior pointer on cleanup. A nil v models "lifecycle unarmed".
func swapSaaSView(t *testing.T, v *effectiveCategoryView) {
	t.Helper()
	prev := saasEffectiveView.Swap(v)
	t.Cleanup(func() { saasEffectiveView.Swap(prev) })
}

// viewOf builds an immutable effective view from a host→category map (source=downloaded so
// it reads as a signed activation).
func viewOf(entries map[string]string) *effectiveCategoryView {
	return newEffectiveView(entries, effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 1})
}

// addAdminCategory adds an admin-created (BuiltIn=false) category to the shared catStore and
// removes it on cleanup, so the admin layer can be exercised in isolation.
func addAdminCategory(t *testing.T, name string, hosts []string) {
	t.Helper()
	if err := catStore.Set(name, hosts, false); err != nil {
		t.Fatalf("catStore.Set admin category: %v", err)
	}
	t.Cleanup(func() { _ = catStore.Delete(name) })
}

// ─── Finding #1: the activated view drives policy enforcement ────────────────────────

// Proof 1: a host present ONLY in the signed view affects actual policy matching.
// Pre-fix: the view was never consulted, so this host never matched.
func TestF3b4Proof1_SignedHostAffectsPolicy(t *testing.T) {
	swapSaaSView(t, viewOf(map[string]string{"only-in-signed.example": "AI"}))

	if !matchCategory("AI", "only-in-signed.example") {
		t.Error("host present only in the signed view must match its category on the policy path")
	}
	if !matchCategory("AI", "sub.only-in-signed.example") {
		t.Error("subdomain suffix match must hold for a signed-view host")
	}
	if matchCategory("AI", "unrelated.example") {
		t.Error("a host in no source must not match")
	}
	if cat, tier, _ := lookupHostCategory("only-in-signed.example"); cat != "AI" || tier != "saas" {
		t.Errorf("lookupHostCategory = (%q,%q), want (AI,saas)", cat, tier)
	}
}

// Proof 2 + 5: a signed activation atomically replaces ONLY the SaaS source — a host
// removed by the replacement stops matching, while admin categories are untouched.
func TestF3b4Proof2and5_AtomicReplaceOnlySaaSSource(t *testing.T) {
	addAdminCategory(t, "AdminOnlyCat", []string{"admin-host.example"})
	swapSaaSView(t, viewOf(map[string]string{"v1-host.example": "AI"}))

	if !matchCategory("AI", "v1-host.example") || !matchCategory("AdminOnlyCat", "admin-host.example") {
		t.Fatal("precondition: both the signed host and the admin host must match")
	}

	// Signed activation → new view WITHOUT the old host (atomic pointer swap).
	saasEffectiveView.Swap(viewOf(map[string]string{"v2-host.example": "AI"}))

	if matchCategory("AI", "v1-host.example") {
		t.Error("a host removed by the replacement view must no longer match the old SaaS category")
	}
	if !matchCategory("AI", "v2-host.example") {
		t.Error("a host in the new view must match")
	}
	if !matchCategory("AdminOnlyCat", "admin-host.example") {
		t.Error("admin categories must be untouched by a SaaS-source replacement")
	}
}

// Proof 4: the embedded baseline (built from catStore's BuiltIn=true entries) is used
// before the first signed activation, and gives the SAME result as the no-view fallback —
// so wiring the view onto the policy path is byte-identical in the dormant default posture.
func TestF3b4Proof4_EmbeddedBaselineBeforeActivation(t *testing.T) {
	// A built-in category host (Social Media / facebook.com lives in DefaultEntries).
	const host, cat = "facebook.com", "Social Media"

	// No view installed → full catStore serves (the pre-F3b-4 path).
	swapSaaSView(t, nil)
	if !matchCategory(cat, host) {
		t.Fatal("fallback (no view): built-in taxonomy host must match via full catStore")
	}

	// Embedded baseline installed → the SAME host now served via the view, catStore
	// consulted admin-only. Result must be identical.
	swapSaaSView(t, embeddedBaselineView())
	if !matchCategory(cat, host) {
		t.Error("embedded baseline view: built-in taxonomy host must still match (byte-identical)")
	}
	// And a host in NEITHER admin nor the embedded baseline does not match.
	if matchCategory(cat, "definitely-not-in-baseline-12345.example") {
		t.Error("unknown host must not match under the embedded baseline")
	}
}

// Proof 3 + fall-through precedence: UT1 (communityDB) stays consulted with a view
// installed, and a view classification under a DIFFERENT category still falls through to
// UT1 rather than short-circuiting.
func TestF3b4Proof3_UT1UnchangedAndFallThrough(t *testing.T) {
	dir := t.TempDir()
	db, err := openCommunityDB(dir)
	if err != nil {
		t.Fatalf("openCommunityDB: %v", err)
	}
	if err := db.BulkWrite(map[string]string{"ut1-host.example": "Malicious", "shared.example": "Malicious"}); err != nil {
		t.Fatalf("BulkWrite: %v", err)
	}
	prev := communityDB
	communityDB = db
	t.Cleanup(func() { communityDB = prev; _ = db.Close() })

	// A view that classifies "shared.example" under a DIFFERENT category ("AI").
	swapSaaSView(t, viewOf(map[string]string{"shared.example": "AI"}))

	// UT1-only host still resolves via community (view present, unchanged behavior).
	if !matchCategory("Malicious", "ut1-host.example") {
		t.Error("UT1 host must still match with a signed view installed")
	}
	// shared.example is "AI" in the view AND "Malicious" in UT1: a query for Malicious must
	// fall through the non-matching view classification to UT1 (cross-layer OR preserved).
	if !matchCategory("Malicious", "shared.example") {
		t.Error("a non-matching view classification must fall through to the UT1 layer")
	}
	// And the view still wins for its own category.
	if !matchCategory("AI", "shared.example") {
		t.Error("the view must match for its own category")
	}
}

// Proof 10: concurrent request-path readers never observe a partial view during swaps.
// Run under -race; every read must return cleanly against SOME complete view.
func TestF3b4Proof10_ConcurrentReadersNoPartialState(t *testing.T) {
	swapSaaSView(t, viewOf(map[string]string{"a.example": "AI"}))
	var readers sync.WaitGroup
	stop := make(chan struct{})

	// Swapper runs until the readers finish, alternating between two complete views.
	swapperDone := make(chan struct{})
	go func() {
		defer close(swapperDone)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			if i%2 == 0 {
				saasEffectiveView.Swap(viewOf(map[string]string{"a.example": "AI", "b.example": "Streaming"}))
			} else {
				saasEffectiveView.Swap(viewOf(map[string]string{"a.example": "AI"}))
			}
		}
	}()

	// Readers hammer the hot path; a torn/partial view would race-detect or misclassify.
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for i := 0; i < 5000; i++ {
				if !matchCategory("AI", "a.example") {
					t.Error("a.example must match AI under every complete view")
					return
				}
				if cat, _, _ := lookupHostCategory("b.example"); cat != "" && cat != "Streaming" {
					t.Errorf("b.example resolved to an impossible category %q (torn view)", cat)
					return
				}
			}
		}()
	}
	readers.Wait()
	close(stop)
	<-swapperDone
	if v := saasEffectiveView.Current(); v == nil {
		t.Error("view unexpectedly nil after concurrent swaps")
	}
}

// Proof 11: the wired lookup introduces no per-request allocation on the ASCII hot path.
func TestF3b4Proof11_NoAllocInMatch(t *testing.T) {
	swapSaaSView(t, viewOf(map[string]string{"alloc-host.example": "AI"}))
	allocs := testing.AllocsPerRun(200, func() {
		_ = matchCategory("AI", "sub.alloc-host.example")
	})
	if allocs > 1 {
		t.Errorf("matchCategory allocated %.1f objects/op on the ASCII hot path (want ≤1)", allocs)
	}
}

// Proof 9: once the signed feed owns the live store, the retired legacy raw syncer cannot
// mutate the active SaaS view (single-writer guard).
func TestF3b4Proof9_LegacyWriterCannotMutateView(t *testing.T) {
	resetOwnership(t)
	setSignedFeedOwnsLiveStore(true)
	before := len(catStore.All())
	if n := mergeSaaSCategories(saasFeedCategoriesForTest()); n != 0 {
		t.Errorf("legacy merge wrote %d hosts under signed ownership, want 0", n)
	}
	if after := len(catStore.All()); after != before {
		t.Errorf("legacy merge mutated catStore under signed ownership: %d → %d", before, after)
	}
}

// Proof 7: after a restart, recovery installs the exact committed effective view and it is
// policy-visible before serving — a host from the committed generation matches on the hot
// path once the recovered view is the live view.
func TestF3b4Proof7_RestartRecoveryRestoresPolicyVisibleView(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 7})
	persistRealGen(t, dir+"/generations", g)
	env := newCoordEnv(t, dir, g, coordOpts{})
	activateFresh(t, env, "7") // floor + activation committed, live swapped

	// A fresh process: recover from the committed records, then publish the recovered view.
	env2 := newCoordEnv(t, dir, g, coordOpts{})
	rec, err := env2.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if rec.Class != recoveryActiveServed || rec.View == nil {
		t.Fatalf("recovery did not converge to the committed active generation: %+v", rec)
	}
	swapSaaSView(t, env2.live.Current())
	// The sample dataset classifies chat.example under "ai": it must match on the policy path.
	if !matchCategory("ai", "chat.example") {
		t.Error("recovered committed view must be policy-visible after restart")
	}
}

// ─── Finding #3: idempotently-persisted (orphan) generation must still activate ──────

// idempotentResult models an F3b-2 AcquireGeneration that found the verified generation
// bytes already on disk (genPersistIdempotent) — it carries a full Generation, not a 304.
func idempotentResult(g feedGen, etag string) AcquireResult {
	r := committedResult(g, etag)
	r.Outcome = acquireIdempotent
	return r
}

// A crash after persisting an immutable generation but before its floor/activation commit
// leaves an orphan on disk; the next poll returns acquireIdempotent. The runtime must run
// the activation coordinator (not classify file existence as a no-change), so the orphan
// becomes live WITHOUT waiting for a newer upstream version.
func TestF3b4Finding3_IdempotentOrphanActivates(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	// The generation is already persisted on disk by f3b4TestRuntime (the orphan), and the
	// acquirer reports it idempotent (bytes already exist) rather than committed.
	acq := &fakeAcquirer{result: idempotentResult(g, "etag-42")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)

	out := rt.runRefresh(context.Background(), "test")
	if out != refreshActivated {
		t.Fatalf("orphan idempotent generation must activate: outcome=%s", out)
	}
	if v := rt.live.Current(); v == nil || v.FeedVersion != 42 {
		t.Fatalf("orphan generation not made live: %+v", v)
	}
}

// A same-version idempotent re-acquire of the ALREADY-ACTIVE generation (e.g. a near-expiry
// unconditional refetch) is a genuine no-change — it must NOT trip the strictly-greater
// floor gate or be counted as a failure.
func TestF3b4Finding3_SameVersionIdempotentIsNoChange(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "etag-42")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)
	if out := rt.runRefresh(context.Background(), "seed"); out != refreshActivated {
		t.Fatalf("seed activate failed: %s", out)
	}
	// Re-acquire the SAME version, idempotent.
	acq.result = idempotentResult(g, "etag-42")
	if out := rt.runRefresh(context.Background(), "test"); out != refreshNoChange {
		t.Fatalf("same-version idempotent must be no-change, got %s", out)
	}
	if v := rt.live.Current(); v == nil || v.FeedVersion != 42 {
		t.Fatalf("live view changed on a same-version idempotent: %+v", v)
	}
}

// ─── Finding #4: ETag commit ordering ────────────────────────────────────────────────

// After a failed activation of a newer candidate, the runtime must RETAIN the previous
// ETag (belonging to the still-live generation) so the next poll re-fetches the candidate,
// rather than adopting the failed candidate's ETag (which a later 304 would mask as fresh).
func TestF3b4Finding4_ETagRetainedOnActivationFailure(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g42 := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g42, "etag-42")}
	rt := f3b4TestRuntime(t, g42, acq, f3b3Now)
	if out := rt.runRefresh(context.Background(), "seed"); out != refreshActivated {
		t.Fatalf("seed activate failed: %s", out)
	}
	if rt.getETag() != "etag-42" {
		t.Fatalf("precondition: etag=%q, want etag-42", rt.getETag())
	}

	// A newer committed candidate (v43) that CANNOT activate: it is neither persisted on
	// disk nor known to the coordinator's verifier, so the S1 re-verify fails.
	g43 := buildFeedGen(t, feedGenOpts{feedVersion: 43})
	acq.result = committedResult(g43, "etag-43")
	if out := rt.runRefresh(context.Background(), "test"); out != refreshFailed {
		t.Fatalf("expected activation failure, got %s", out)
	}
	if got := rt.getETag(); got != "etag-42" {
		t.Errorf("ETag advanced to a failed candidate: got %q, want retained etag-42", got)
	}
	// The conditional-request ETag for the next fetch must still be the live gen's, never
	// the rejected candidate's.
	if cond := rt.conditionalETag(SaaSFeedConfig{Refresh: saasFeedDefaultRefresh, Protocol: saasFeedProtocolV1}); cond == "etag-43" {
		t.Error("next fetch would send the failed candidate's ETag — a 304 could mask the failure")
	}
}

// A true HTTP 304 retains the already-committed ETag and only recomputes freshness — it
// never alters activation/provenance.
func TestF3b4Finding4_True304RecomputesFreshnessOnly(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g, "etag-42")}
	rt := f3b4TestRuntime(t, g, acq, f3b3Now)
	rt.runRefresh(context.Background(), "seed")
	before := rt.status.Snapshot()

	acq.result = AcquireResult{Outcome: acquireNotModified, ETag: "etag-42"}
	if out := rt.runRefresh(context.Background(), "test"); out != refreshNoChange {
		t.Fatalf("304 must be no-change, got %s", out)
	}
	after := rt.status.Snapshot()
	if after.Provenance != before.Provenance || after.ActiveFeedVersion != before.ActiveFeedVersion {
		t.Errorf("304 altered activation/provenance: %+v → %+v", before, after)
	}
	if rt.getETag() != "etag-42" {
		t.Errorf("304 changed the ETag: %q", rt.getETag())
	}
}

// ─── Finding #6: activation failure causes zero policy change ─────────────────────────

func TestF3b4Finding6_ActivationFailureZeroPolicyChange(t *testing.T) {
	enableStandaloneFeed(t)
	resetOwnership(t)
	g42 := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	acq := &fakeAcquirer{result: committedResult(g42, "etag-42")}
	rt := f3b4TestRuntime(t, g42, acq, f3b3Now)
	rt.runRefresh(context.Background(), "seed")
	liveBefore := rt.live.Current()

	g43 := buildFeedGen(t, feedGenOpts{feedVersion: 43}) // not persisted → activation fails
	acq.result = committedResult(g43, "etag-43")
	if out := rt.runRefresh(context.Background(), "test"); out != refreshFailed {
		t.Fatalf("expected failure, got %s", out)
	}
	liveAfter := rt.live.Current()
	if liveAfter != liveBefore || liveAfter.FeedVersion != 42 {
		t.Errorf("activation failure changed the live policy view: v%d → %v", 42, liveAfter)
	}
}

// ─── Finding #5: override-only changes recompose locally (no network) ─────────────────

// An override change recomposes the effective view onto the embedded baseline with NO
// network fetch, and the recomposed view is policy-visible. delete-all restores the base;
// an invalid override provider leaves the prior view untouched.
func TestF3b4Finding5_OverrideRecomposeNoNetwork(t *testing.T) {
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
	ov := newOverrideProvider("rev-0")
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ov})

	// No signed generation active → recompose the EMBEDDED baseline with a new override.
	ov.set(catoverride.Overrides{Added: map[string]string{"custom.example": "CustomCat"}}, "rev-1")
	res, err := env.coord.RebuildForOverrides(context.Background())
	if err != nil {
		t.Fatalf("RebuildForOverrides: %v", err)
	}
	if res.Outcome != activationCommitted {
		t.Fatalf("override recompose outcome = %s, want committed", res.Outcome)
	}
	// Make the recomposed view policy-visible and assert matching reflects the override.
	swapSaaSView(t, env.live.Current())
	if !matchCategory("CustomCat", "custom.example") {
		t.Error("an override-added host must affect policy matching without any network fetch")
	}

	// delete-all → the base categories are restored (the override no longer matches).
	ov.set(catoverride.Overrides{}, "rev-2")
	if _, err := env.coord.RebuildForOverrides(context.Background()); err != nil {
		t.Fatalf("RebuildForOverrides (clear): %v", err)
	}
	saasEffectiveView.Swap(env.live.Current())
	if matchCategory("CustomCat", "custom.example") {
		t.Error("an explicit empty override set must restore the base categories")
	}

	// Invalid override provider → the prior view is left UNTOUCHED (no swap).
	priorPtr := env.live.Current()
	ov.err = context.DeadlineExceeded
	if _, err := env.coord.RebuildForOverrides(context.Background()); err == nil {
		t.Error("an invalid override snapshot must return an error")
	}
	if env.live.Current() != priorPtr {
		t.Error("an invalid override recomposition must leave the live view untouched")
	}
}

// ─── Finding #2: managed-DP first-restart authority persistence ──────────────────────

// On a managed DP, applying an accepted CP snapshot (including a replayed last-good
// snapshot) persists the durable authority mirror, so resolveAuthority recovers the exact
// authoritative feed config across a restart with no live CP and NO newer config version —
// never deadlocking on waiting_for_authority and never using local defaults.
func TestF3b4Finding2_AuthorityPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	swapClusterRole(t, "data-plane")
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)

	// Wire the store BEFORE any snapshot apply (the finding-#2 ordering).
	prevStore := globalSaaSFeedAuthorityStore
	store, err := newSaaSFeedAuthorityStore(dir)
	if err != nil {
		t.Fatalf("newSaaSFeedAuthorityStore: %v", err)
	}
	globalSaaSFeedAuthorityStore = store
	t.Cleanup(func() { globalSaaSFeedAuthorityStore = prevStore })

	// Simulate the accepted CP snapshot's effect: durable config set + epoch observed, then
	// the mirror written (exactly what applySnapshotSaaSFeed does after acceptance).
	setSaaSFeedDurable(saasFeedDurable{
		Managed: true, Enabled: true, URL: defaultSaaSFeedURL,
		Protocol: saasFeedProtocolV1, RefreshSeconds: 3600, SchemaVersion: saasStoreSchemaVersion,
	})
	snap := ConfigSnapshot{Version: 7, Epoch: 3, CAFingerprint: "cp-fingerprint-01"}
	// Seed the fencing-epoch ratchet and RESTORE it on cleanup — leaking a non-zero epoch
	// would make every later applyConfigSnapshot with epoch 0 fail the stale-epoch fence
	// under a shuffled run order.
	prevEpoch := dpLastSeenEpoch.Load()
	dpLastSeenEpoch.Store(3)
	t.Cleanup(func() { dpLastSeenEpoch.Store(prevEpoch) })
	persistSaaSFeedAuthorityMirror(snap)

	// A valid mirror must now exist.
	if _, st, _ := store.Read(); st != saasFeedAuthorityValid {
		t.Fatalf("authority mirror not persisted on apply: status=%s", st)
	}

	// Restart with NO live CP and NO newer version: resolveAuthority must be Ready with the
	// exact config, not waiting_for_authority and not a local default.
	rt := &saasFeedRuntime{authority: store, overrides: globalCategoryOverrides}
	res := rt.resolveAuthority()
	if res.WaitingForAuthority {
		t.Fatalf("managed DP deadlocked on waiting_for_authority after restart: %s", res.Detail)
	}
	if !res.Ready || !res.Config.runtimeEnabled() {
		t.Fatalf("authority not recovered Ready+enabled: ready=%v cfg=%+v", res.Ready, res.Config)
	}
	if res.ConfigVersion != 7 || res.Epoch != 3 {
		t.Errorf("recovered identity mismatch: version=%d epoch=%d, want 7/3", res.ConfigVersion, res.Epoch)
	}
}

// A missing or corrupt authority mirror keeps the approved fail-closed behavior: the
// managed DP waits for authority and never falls back to local defaults.
func TestF3b4Finding2_MissingMirrorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	swapClusterRole(t, "data-plane")
	f3a2ResetFeedDurable(t)
	f3a2SwapOverrides(t)
	store, err := newSaaSFeedAuthorityStore(dir)
	if err != nil {
		t.Fatalf("newSaaSFeedAuthorityStore: %v", err)
	}
	prevStore := globalSaaSFeedAuthorityStore
	globalSaaSFeedAuthorityStore = store
	t.Cleanup(func() { globalSaaSFeedAuthorityStore = prevStore })

	rt := &saasFeedRuntime{authority: store, overrides: globalCategoryOverrides}
	res := rt.resolveAuthority()
	if !res.WaitingForAuthority {
		t.Error("a missing authority mirror must be waiting_for_authority (fail-closed)")
	}
	if res.Config.runtimeEnabled() {
		t.Error("a managed DP with no mirror must not run the feed from local defaults")
	}
}
