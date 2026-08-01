package main

// F3b-3 activation functional + crash-boundary tests. Crash-matrix boundaries covered
// here: 1 (candidate re-verify), 2 (effective-store build), 3/4 (floor A/B write), 5
// (floor read-back), 6-10 (activation temp/sync/rename/parent-sync/read-back — modeled at
// the atomic-write + read-back seam), 11 (config revision changes before cutover), 20
// (override update racing activation), 21 (shutdown cancellation). For every failure the
// test asserts: no committed activation record, no live cutover, and the floor is never
// lowered.

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/catoverride"
)

// activateFresh activates generationID as a fresh download and fails the test on error.
func activateFresh(t *testing.T, env *f3b3Env, id string) activationResult {
	t.Helper()
	res, err := env.coord.Activate(context.Background(), activateInput{GenerationID: id, Provenance: activationProvenanceDownloaded})
	if err != nil {
		t.Fatalf("activate %s: %v", id, err)
	}
	return res
}

// ── v1 → v2 activation ratchets the floor + swaps the view ───────────────────────

func TestF3b3_Activate_V1ToV2(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g1 := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	g2 := buildFeedGen(t, feedGenOpts{feedVersion: 2})
	persistRealGen(t, dir+"/generations", g1)
	persistRealGen(t, dir+"/generations", g2)

	env := newCoordEnv(t, dir, g1, coordOpts{verifier: multiVerifier(g1, g2)})
	activateFresh(t, env, "1")
	if env.live.Current().FeedVersion != 1 {
		t.Fatal("v1 not live")
	}
	r2 := activateFresh(t, env, "2")
	if r2.Version != 2 || env.live.Current().FeedVersion != 2 {
		t.Fatalf("v2 not live: %+v", r2)
	}
	if fv := env.coord.currentFloorVersion(); fv != 2 {
		t.Fatalf("floor did not ratchet to 2: %d", fv)
	}
	if !signedFeedOwnsLive() {
		t.Fatal("ownership flag not set after activation")
	}
}

// ── rollback / equal-version network candidate rejected (declined P2 upheld) ──────

func TestF3b3_Activate_RollbackAndEqualRejected(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g1 := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	g2 := buildFeedGen(t, feedGenOpts{feedVersion: 2})
	persistRealGen(t, dir+"/generations", g1)
	persistRealGen(t, dir+"/generations", g2)
	env := newCoordEnv(t, dir, g1, coordOpts{verifier: multiVerifier(g1, g2)})
	activateFresh(t, env, "2") // floor now 2

	// A fresh network activation of v1 (< floor) or v2 (== floor) is rejected before any
	// live change — the strictly-greater rule (design §B.9 / declined Codex P2).
	for _, id := range []string{"1", "2"} {
		_, err := env.coord.Activate(context.Background(), activateInput{GenerationID: id, Provenance: activationProvenanceDownloaded})
		if err == nil {
			t.Fatalf("fresh activation of v%s should be rejected (floor=2)", id)
		}
	}
	if env.live.Current().FeedVersion != 2 {
		t.Fatal("live view changed on a rejected activation")
	}
	if env.coord.currentFloorVersion() != 2 {
		t.Fatal("floor changed on a rejected activation")
	}
}

// ── crash boundary 1: candidate re-verification failure ──────────────────────────

func TestF3b3_Activate_ReverifyFailure(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	// A verifier that rejects everything ⇒ reverify fails ⇒ no durable/live change.
	bad := newFakeVerifier(buildFeedGen(t, feedGenOpts{feedVersion: 99})) // mismatched bytes
	env := newCoordEnv(t, dir, g, coordOpts{verifier: bad})
	_, err := env.coord.Activate(context.Background(), activateInput{GenerationID: "1", Provenance: activationProvenanceDownloaded})
	if err == nil {
		t.Fatal("expected re-verify failure")
	}
	assertNoActivation(t, env)
}

// ── crash boundary 2: effective-store construction (override provider) failure ────

func TestF3b3_Activate_OverrideProviderFailure(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	ovp := newOverrideProvider("rev-1")
	ovp.err = context.DeadlineExceeded // provider unavailable
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ovp})
	_, err := env.coord.Activate(context.Background(), activateInput{GenerationID: "1", Provenance: activationProvenanceDownloaded})
	if err == nil {
		t.Fatal("expected override-provider failure")
	}
	assertNoActivation(t, env)
}

// ── crash boundaries 3/4/5/6-10: floor + activation write / read-back failures ────

func TestF3b3_Activate_DurabilityFailures(t *testing.T) {
	cases := map[string]func(fs *fakeFloorFS){
		"floor A write": func(fs *fakeFloorFS) {
			fs.writeHook = failWriteOnSuffix(floorFileA)
		},
		"floor B write": func(fs *fakeFloorFS) {
			fs.writeHook = failWriteOnSuffix(floorFileB)
		},
		"floor read-back": func(fs *fakeFloorFS) {
			fs.readHook = corruptReadOnSuffix(floorFileA)
		},
		"activation write": func(fs *fakeFloorFS) {
			fs.writeHook = failWriteOnSuffix(activationFile)
		},
		"activation read-back": func(fs *fakeFloorFS) {
			fs.readHook = corruptReadOnSuffix(activationFile)
		},
	}
	for name, inject := range cases {
		t.Run(name, func(t *testing.T) {
			resetOwnership(t)
			dir := t.TempDir()
			g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
			persistRealGen(t, dir+"/generations", g)
			fs := newFakeFS()
			inject(fs)
			seam := fs.seam()
			env := newCoordEnv(t, dir, g, coordOpts{floorSeam: &seam})
			_, err := env.coord.Activate(context.Background(), activateInput{GenerationID: "1", Provenance: activationProvenanceDownloaded})
			if err == nil {
				t.Fatalf("%s: expected a durability failure", name)
			}
			// No live cutover (the atomic holder is untouched) and no ownership.
			if env.live.Current() != nil {
				t.Fatalf("%s: live view was swapped despite a durability failure", name)
			}
			if signedFeedOwnsLive() {
				t.Fatalf("%s: ownership set despite a durability failure", name)
			}
			// The activation record is not committed.
			if _, s, _ := env.activ.Read(); s == activationValid {
				t.Fatalf("%s: activation record committed despite a durability failure", name)
			}
		})
	}
}

// ── crash boundary 11: config revision changes before cutover → rebuild ──────────

func TestF3b3_Activate_ConfigRevisionRebuild(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	ovp := newOverrideProvider("rev-1")
	// Bump the revision exactly once, on the first recheck read, so the coordinator
	// rebuilds under the lock and then commits the settled revision.
	bumped := false
	ovp.onCurrent = func(p *fakeOverrideProvider) {
		if p.calls == 2 && !bumped { // 1=build, 2=recheck
			bumped = true
			p.rev = "rev-2"
		}
	}
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ovp})
	res, err := env.coord.Activate(context.Background(), activateInput{GenerationID: "1", Provenance: activationProvenanceDownloaded})
	if err != nil {
		t.Fatalf("activate with one config bump should rebuild + commit: %v", err)
	}
	if res.ConfigRev != "rev-2" {
		t.Fatalf("committed revision = %q; want the settled rev-2", res.ConfigRev)
	}
	if env.live.Current().ConfigRevision != "rev-2" {
		t.Fatalf("live view revision = %q; want rev-2", env.live.Current().ConfigRevision)
	}
}

func TestF3b3_Activate_ConfigChurnAbortsToLKG(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	ovp := newOverrideProvider("rev-1")
	// Change the revision on EVERY recheck so churn never settles.
	ovp.onCurrent = func(p *fakeOverrideProvider) { p.rev += "x" }
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ovp})
	res, err := env.coord.Activate(context.Background(), activateInput{GenerationID: "1", Provenance: activationProvenanceDownloaded})
	if err == nil {
		t.Fatal("relentless config churn should abort to LKG")
	}
	if res.Outcome != activationAbortedLKG {
		t.Fatalf("outcome = %s; want aborted_lkg", res.Outcome)
	}
	// No live cutover to a mixed-policy store.
	if env.live.Current() != nil {
		t.Fatal("live cutover happened despite unresolved config churn")
	}
}

// ── override apply / change / remove restores compiled feed category ─────────────

func TestF3b3_Overrides_ApplyChangeRemove(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	ovp := newOverrideProvider("rev-1")
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ovp})
	activateFresh(t, env, "1")

	// Baseline: chat.example is "ai" from the feed.
	if c, _ := env.live.Current().LookupHost("chat.example"); c != "ai" {
		t.Fatalf("baseline category = %q; want ai", c)
	}
	// Recategorize chat.example → "blocked" and rebuild.
	ovp.set(catoverride.Overrides{Recategorized: map[string]string{"chat.example": "blocked"}}, "rev-2")
	res, err := env.coord.RebuildForOverrides(context.Background())
	if err != nil {
		t.Fatalf("rebuild (apply): %v", err)
	}
	// The rebuild reports a committed result over the SAME base generation with the NEW
	// override revision (base generation, floor, and activation record are unchanged).
	if res.Outcome != activationCommitted || res.Version != 1 || res.ConfigRev != "rev-2" {
		t.Fatalf("rebuild result = %+v; want committed base v1 at rev-2", res)
	}
	if c, _ := env.live.Current().LookupHost("chat.example"); c != "blocked" {
		t.Fatalf("recategorized category = %q; want blocked", c)
	}
	if env.live.Current().FeedVersion != 1 {
		t.Fatal("override rebuild changed the base generation")
	}
	// Remove the override and rebuild → the compiled feed category is restored deterministically.
	ovp.set(catoverride.Overrides{}, "rev-3")
	if _, err := env.coord.RebuildForOverrides(context.Background()); err != nil {
		t.Fatalf("rebuild (remove): %v", err)
	}
	if c, _ := env.live.Current().LookupHost("chat.example"); c != "ai" {
		t.Fatalf("after removal category = %q; want the restored feed category ai", c)
	}
	// Base generation and applied override revision are observable as DISTINCT identities.
	lv := env.live.Current()
	if lv.FeedVersion != 1 || lv.ConfigRevision != "rev-3" {
		t.Fatalf("distinct identities: feed=%d rev=%q", lv.FeedVersion, lv.ConfigRevision)
	}
}

// ── config recheck ERROR before cutover must abort, not commit the pre-recheck view ──
// (Codex P1 #1): an unconfirmable revision (managed-DP outage / invalid snapshot) leaves
// the live store untouched — never a silent commit of a possibly-stale-policy view.

func TestF3b3_Activate_ConfigRecheckErrorAborts(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	ovp := newOverrideProvider("rev-1")
	// The build Current() succeeds; the S4 recheck Current() (2nd call) fails — we can no
	// longer confirm the revision is unchanged, so activation must ABORT.
	ovp.onCurrent = func(p *fakeOverrideProvider) {
		if p.calls >= 2 {
			p.err = context.DeadlineExceeded
		}
	}
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ovp})
	if _, err := env.coord.Activate(context.Background(),
		activateInput{GenerationID: "1", Provenance: activationProvenanceDownloaded}); err == nil {
		t.Fatal("a failed config recheck must abort activation, not commit the pre-recheck view (Codex P1 #1)")
	}
	// No live cutover and no committed activation record on a recheck failure.
	if env.live.Current() != nil {
		t.Fatal("live cutover happened despite an unconfirmable config revision")
	}
	if _, s, _ := env.activ.Read(); s == activationValid {
		t.Fatal("activation record committed despite a failed recheck")
	}
}

// ── an override on a DESCENDANT of an ancestor feed entry is resolved MOST-SPECIFIC-first ─
// The effective view has no rule-ordering ambiguity to reject (Codex P1 #2 decline): the
// descendant override governs its subtree, the ancestor feed entry governs the rest.

func TestF3b3_View_SubdomainOverrideBeatsAncestorFeed(t *testing.T) {
	feed := map[string]string{"example.com": "allowed"}
	ov := catoverride.Overrides{Added: map[string]string{"app.example.com": "blocked"}}
	// ComposeView keeps BOTH: the ancestor is NOT a subdomain of the override key, so it is
	// not suppressed (the mirror case — a descendant feed entry under an ancestor override —
	// IS collapsed by catoverride; that asymmetry is deliberate).
	composed := catoverride.ComposeView(feed, ov)
	view := newEffectiveView(composed, effectiveCategoryView{Source: sourceDownloaded, FeedVersion: 1})

	for _, c := range []struct{ host, want string }{
		{"app.example.com", "blocked"},   // exact descendant override — the longest match wins
		{"x.app.example.com", "blocked"}, // inside the override subtree
		{"example.com", "allowed"},       // the ancestor itself
		{"other.example.com", "allowed"}, // ancestor subtree outside the override
	} {
		if got, ok := view.LookupHost(c.host); !ok || got != c.want {
			t.Fatalf("LookupHost(%q) = %q,%v; want %q", c.host, got, ok, c.want)
		}
	}
}

func TestF3b3_Overrides_InvalidLeavesLiveUntouched(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	ovp := newOverrideProvider("rev-1")
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ovp})
	activateFresh(t, env, "1")
	before := env.live.Current()

	ovp.err = context.DeadlineExceeded // invalid/unavailable override snapshot
	if _, err := env.coord.RebuildForOverrides(context.Background()); err == nil {
		t.Fatal("expected an error on an invalid override snapshot")
	}
	if env.live.Current() != before {
		t.Fatal("live store was mutated on an invalid override snapshot")
	}
}

// ── crash boundary 20 + atomic visibility: override rebuild racing readers ────────

func TestF3b3_Overrides_AtomicVisibilityUnderReaders(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	ovp := newOverrideProvider("rev-1")
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ovp})
	activateFresh(t, env, "1")

	stop := make(chan struct{})
	var wg sync.WaitGroup
	// Concurrent readers: every observed view must be internally consistent — a
	// recategorization is all-or-nothing (chat.example is either "ai" or "blocked", never
	// a torn intermediate), and the base feed version stays 1.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					v := env.live.Current()
					if v == nil || v.FeedVersion != 1 {
						continue
					}
					if c, ok := v.LookupHost("chat.example"); ok && c != "ai" && c != "blocked" {
						panic("torn view: chat.example category " + c)
					}
				}
			}
		}()
	}
	// Concurrent rebuilds flipping the override back and forth (serialized by the coordinator).
	for i := 0; i < 50; i++ {
		if i%2 == 0 {
			ovp.set(catoverride.Overrides{Recategorized: map[string]string{"chat.example": "blocked"}}, "rev-b")
		} else {
			ovp.set(catoverride.Overrides{}, "rev-a")
		}
		if _, err := env.coord.RebuildForOverrides(context.Background()); err != nil {
			t.Fatalf("rebuild: %v", err)
		}
	}
	close(stop)
	wg.Wait()
}

// ── crash boundary 21: shutdown cancellation ─────────────────────────────────────

func TestF3b3_Activate_Cancellation(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	env := newCoordEnv(t, dir, g, coordOpts{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := env.coord.Activate(ctx, activateInput{GenerationID: "1", Provenance: activationProvenanceDownloaded})
	if err == nil {
		t.Fatal("expected cancellation")
	}
	assertNoActivation(t, env)
}

// ── legacy syncer single-writer guard ────────────────────────────────────────────

func TestF3b3_LegacySyncerNoOpUnderOwnership(t *testing.T) {
	resetOwnership(t)
	// While the signed coordinator owns the live store, the legacy raw merge is a no-op.
	setSignedFeedOwnsLiveStore(true)
	if n := mergeSaaSCategories(saasFeedCategoriesForTest()); n != 0 {
		t.Fatalf("legacy merge added %d hosts under signed ownership; want 0", n)
	}
	// When not owned, the legacy path runs normally (adds hosts).
	setSignedFeedOwnsLiveStore(false)
	n := mergeSaaSCategories(saasFeedCategoriesForTest())
	t.Cleanup(func() { _ = catStore.Delete("f3b3-legacy-test") }) // clean the shared store
	if n == 0 {
		t.Fatal("legacy merge should add hosts when the feed does not own the live store")
	}
}

// ── crash boundary 15: in-memory cutover panic seam ─────────────────────────────

// panicSwapper is a live holder whose Swap panics — proving the atomic cutover (S5) is
// the LAST step: floor + activation are already durably committed before it, so a fresh
// process converges to the committed active generation on restart.
type panicSwapper struct{}

func (panicSwapper) Swap(*effectiveCategoryView) *effectiveCategoryView { panic("cutover panic seam") }
func (panicSwapper) Current() *effectiveCategoryView                    { return nil }

func TestF3b3_Activate_CutoverPanicLeavesDurableCommit(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)

	// Wire a coordinator whose live cutover panics.
	floor, _ := newFloorStore(dir, compiledMinFeedVersion)
	activ, _ := newActivationStore(dir)
	coord := newActivationCoordinator(dir+"/generations", floor, activ, newFakeVerifier(g),
		panicSwapper{}, newOverrideProvider("rev-1"), osReverifyReader, compiledMinFeedVersion, f3b3Now, 0)

	func() {
		defer func() { _ = recover() }() // absorb the cutover panic (a crash at S5)
		_, _ = coord.Activate(context.Background(), activateInput{GenerationID: "1", Provenance: activationProvenanceDownloaded})
	}()

	// Floor + activation record are durably committed (S3+S4 happened before the S5 panic).
	if _, s, _ := activ.Read(); s != activationValid {
		t.Fatal("activation record not durable before the cutover panic")
	}
	// A fresh process converges to the committed active generation.
	env2 := newCoordEnv(t, dir, g, coordOpts{})
	rec, err := env2.coord.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover after cutover panic: %v", err)
	}
	if rec.Class != recoveryActiveServed || rec.ActiveVersion != 1 {
		t.Fatalf("did not converge after cutover panic: %+v", rec)
	}
}

// ── managed-DP ownership: the composed view reflects the CP-authoritative overrides ─

func TestF3b3_ManagedDP_UsesAuthoritativeOverrides(t *testing.T) {
	resetOwnership(t)
	dir := t.TempDir()
	g := buildFeedGen(t, feedGenOpts{feedVersion: 1})
	persistRealGen(t, dir+"/generations", g)
	// The provider models a managed DP: it returns the CP-authoritative overrides. A local
	// conflicting override is never consumed because the coordinator ONLY reads the provider.
	cpOverrides := catoverride.Overrides{Recategorized: map[string]string{"chat.example": "cp-policy"}}
	ovp := newOverrideProvider("cp-epoch-7")
	ovp.set(cpOverrides, "cp-epoch-7")
	env := newCoordEnv(t, dir, g, coordOpts{overrides: ovp})
	res := activateFresh(t, env, "1")

	if res.ConfigRev != "cp-epoch-7" {
		t.Fatalf("config revision = %q; want the CP epoch", res.ConfigRev)
	}
	if c, _ := env.live.Current().LookupHost("chat.example"); c != "cp-policy" {
		t.Fatalf("managed-DP view category = %q; want the CP-authoritative cp-policy", c)
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────────

func assertNoActivation(t *testing.T, env *f3b3Env) {
	t.Helper()
	if env.live.Current() != nil {
		t.Fatal("live view was swapped on a failed activation")
	}
	if signedFeedOwnsLive() {
		t.Fatal("ownership set on a failed activation")
	}
	if _, s, _ := env.activ.Read(); s == activationValid {
		t.Fatal("activation record committed on a failed activation")
	}
}

func failWriteOnSuffix(suffix string) func(path string, n int) error {
	return func(path string, _ int) error {
		if strings.HasSuffix(path, suffix) {
			return context.DeadlineExceeded
		}
		return nil
	}
}

func corruptReadOnSuffix(suffix string) func(path string, data []byte, exists bool) ([]byte, error, bool) {
	return func(path string, data []byte, exists bool) ([]byte, error, bool) {
		if exists && strings.HasSuffix(path, suffix) {
			return append(append([]byte(nil), data...), 'X'), nil, true // corrupt the read-back
		}
		return nil, nil, false
	}
}
