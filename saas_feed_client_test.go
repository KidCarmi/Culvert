package main

// F3b-2 acquisition-pipeline tests. Required-test classes: 10/11 (manifest wrapper
// strictness + tampered manifest ⇒ no parsed object ⇒ zero artifact fetches), 12
// (wrong identity ⇒ reject — via the real kernel rejection path), 13 (expired/future/
// overlong-validity), 14 (floor equality/lower rejection BEFORE artifact acquisition),
// 16/17/18 (artifact digest/size/binding mismatch ⇒ no content), 19 (valid end-to-end
// acquisition), 27 (no floor mutation), 28 (no activation-record mutation), 29 (no
// live category-store mutation), 30 (no fetch before authoritative managed-DP config),
// 31 (no legacy SaaS-syncer interaction).

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// newClientWithFake wires the pipeline with the fake verifier + a real fetcher against
// a TLS origin serving gen, and a generation store under a temp dir.
func newClientWithFake(t *testing.T, g feedGen) (*saasFeedClient, *feedMux, string) {
	t.Helper()
	mux := newFeedMux(g)
	fo := newFeedOrigin(t, mux)
	root := filepath.Join(t.TempDir(), "generations")
	store, err := newGenerationStore(root)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	c, err := newSaaSFeedClient(newFakeVerifier(g), fo.fetcher, store)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	return c, mux, root
}

// ── 19. valid end-to-end candidate acquisition ───────────────────────────────────

func TestF3b2_Acquire_ValidEndToEnd(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	c, mux, root := newClientWithFake(t, g)

	res, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g))
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	if res.Outcome != acquireCommitted {
		t.Fatalf("outcome = %s; want committed", res.Outcome)
	}
	if res.Generation == nil || res.Generation.FeedVersion != 42 {
		t.Fatalf("generation = %+v", res.Generation)
	}
	if res.Generation.Dir != filepath.Join(root, "42") {
		t.Fatalf("dir = %q", res.Generation.Dir)
	}
	if res.Generation.ManifestSHA256 != sha256Hex(g.EnvelopeBytes) ||
		res.Generation.ArtifactSHA256 != g.Manifest.ArtifactSHA256 {
		t.Fatalf("digests not bound: %+v", res.Generation)
	}
	if mux.manifestHits.Load() != 1 || mux.artifactHits.Load() != 1 || mux.bundleHits.Load() != 1 {
		t.Fatalf("hits: manifest=%d artifact=%d bundle=%d", mux.manifestHits.Load(), mux.artifactHits.Load(), mux.bundleHits.Load())
	}
	// A second acquisition is idempotent (existing immutable generation).
	res2, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g))
	if err != nil || res2.Outcome != acquireIdempotent {
		t.Fatalf("second acquire: outcome=%s err=%v; want idempotent", res2.Outcome, err)
	}
}

// ── 11. tampered/forged manifest ⇒ no parsed object ⇒ ZERO artifact fetches ───────

func TestF3b2_Acquire_ForgedEnvelope_ZeroArtifactFetch(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	c, mux, root := newClientWithFake(t, g)
	// Serve a tampered envelope the fake verifier will reject.
	mux.gen.EnvelopeBytes = append(append([]byte(nil), g.EnvelopeBytes...), '!')

	_, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g))
	if !errors.Is(err, errAcquireVerify) {
		t.Fatalf("err = %v; want errAcquireVerify", err)
	}
	if mux.artifactHits.Load() != 0 || mux.bundleHits.Load() != 0 {
		t.Fatalf("verify-before-parse violated: artifact=%d bundle=%d fetches after a bad envelope",
			mux.artifactHits.Load(), mux.bundleHits.Load())
	}
	assertNoGeneration(t, root)
}

// ── 12. wrong identity ⇒ reject (genuine kernel rejection, zero artifact fetch) ───

func TestF3b2_Acquire_RealKernelRejectsForged_ZeroArtifactFetch(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	mux := newFeedMux(g)
	// Serve a forged envelope (real payload, garbage bundle) so the REAL kernel — the
	// production verifier — rejects it with genuine crypto (verify-before-parse). This
	// exercises the same rejection path a wrong SAN/issuer/workflow/tag takes; the
	// identity cases themselves are proven in internal/urlcatfeed/verify_test.go.
	mux.gen.EnvelopeBytes = forgedEnvelope(t, g.ManifestBytes)
	fo := newFeedOrigin(t, mux)
	root := filepath.Join(t.TempDir(), "generations")
	store, _ := newGenerationStore(root)
	c, _ := newSaaSFeedClient(realFeedVerifier(t), fo.fetcher, store)

	_, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g))
	if !errors.Is(err, errAcquireVerify) {
		t.Fatalf("err = %v; want errAcquireVerify", err)
	}
	if mux.artifactHits.Load() != 0 {
		t.Fatalf("real kernel rejection still fetched %d artifacts", mux.artifactHits.Load())
	}
	assertNoGeneration(t, root)
}

// ── 18. tampered artifact ⇒ no content, no generation ────────────────────────────

func TestF3b2_Acquire_TamperedArtifact(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	c, mux, root := newClientWithFake(t, g)
	// Serve an artifact whose bytes no longer match the manifest digest/size.
	mux.artifactExtra = func(w http.ResponseWriter, r *http.Request) bool {
		_, _ = w.Write(append(append([]byte(nil), g.ArtifactBytes...), 'Z'))
		return true
	}
	_, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g))
	if !errors.Is(err, errAcquireVerify) {
		t.Fatalf("err = %v; want errAcquireVerify", err)
	}
	assertNoGeneration(t, root)
}

// ── 16/17. artifact size/digest binding mismatch ⇒ no content ────────────────────

func TestF3b2_Acquire_ArtifactSizeMismatch(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	c, mux, root := newClientWithFake(t, g)
	mux.artifactExtra = func(w http.ResponseWriter, r *http.Request) bool {
		_, _ = w.Write(g.ArtifactBytes[:len(g.ArtifactBytes)-1]) // wrong size
		return true
	}
	_, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g))
	if !errors.Is(err, errAcquireVerify) {
		t.Fatalf("err = %v; want errAcquireVerify", err)
	}
	assertNoGeneration(t, root)
}

// ── 17. artifact↔manifest binding mismatch (version/time/count) ⇒ no content ──────

func TestF3b2_Acquire_ArtifactManifestBindingMismatch(t *testing.T) {
	// The kernel binds artifact feed_version / generated_at / counts to the manifest
	// (internal/urlcatfeed VerifyArtifact; the mismatch cases are proven there). At the
	// pipeline level, any VerifyArtifact rejection must abort the whole candidate with
	// no persisted generation. Model it via the verifier's binding-error path.
	g := buildFeedGen(t, feedGenOpts{})
	mux := newFeedMux(g)
	fo := newFeedOrigin(t, mux)
	root := filepath.Join(t.TempDir(), "generations")
	store, _ := newGenerationStore(root)
	fv := newFakeVerifier(g)
	fv.artifactErr = urlcatfeed.ErrBinding // artifact does not match the manifest binding
	c, _ := newSaaSFeedClient(fv, fo.fetcher, store)

	_, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g))
	if !errors.Is(err, errAcquireVerify) {
		t.Fatalf("err = %v; want errAcquireVerify", err)
	}
	assertNoGeneration(t, root)
}

// ── 13. freshness: expired / future-dated / (overlong validity is kernel-enforced) ─

func TestF3b2_Acquire_ExpiredRejected(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{generatedAt: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC), validity: 24 * time.Hour})
	c, _, root := newClientWithFake(t, g)
	in := baseAcquireInput(g)
	in.Now = func() time.Time { return time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC) } // long after expiry
	_, err := c.AcquireGeneration(context.Background(), in)
	if !errors.Is(err, errAcquireExpired) {
		t.Fatalf("err = %v; want errAcquireExpired", err)
	}
	assertNoGeneration(t, root)
}

func TestF3b2_Acquire_FutureDatedRejected(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{generatedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)})
	c, _, root := newClientWithFake(t, g)
	in := baseAcquireInput(g)
	// now is well BEFORE generated_at (beyond the 5m skew) ⇒ future-dated.
	in.Now = func() time.Time { return time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC) }
	_, err := c.AcquireGeneration(context.Background(), in)
	if !errors.Is(err, errAcquireFuture) {
		t.Fatalf("err = %v; want errAcquireFuture", err)
	}
	assertNoGeneration(t, root)
}

// ── 14. floor equality / lower version rejected BEFORE artifact acquisition ───────

func TestF3b2_Acquire_FloorRejectBeforeArtifact(t *testing.T) {
	for _, floor := range []int64{42, 43, 100} { // equal or higher ⇒ reject (strictly-greater required)
		g := buildFeedGen(t, feedGenOpts{feedVersion: 42})
		c, mux, root := newClientWithFake(t, g)
		in := baseAcquireInput(g)
		in.RecoveredFloor = floor
		_, err := c.AcquireGeneration(context.Background(), in)
		if !errors.Is(err, errAcquireFloor) {
			t.Fatalf("floor %d: err = %v; want errAcquireFloor", floor, err)
		}
		// The floor rejection happens BEFORE any artifact byte is fetched.
		if mux.artifactHits.Load() != 0 || mux.bundleHits.Load() != 0 {
			t.Fatalf("floor %d: artifact fetched before floor accept (a=%d b=%d)", floor, mux.artifactHits.Load(), mux.bundleHits.Load())
		}
		assertNoGeneration(t, root)
	}
}

// ── 30. no fetch before authoritative managed-DP configuration ───────────────────

func TestF3b2_Acquire_ManagedDPNotReady_NoFetch(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	c, mux, root := newClientWithFake(t, g)
	in := baseAcquireInput(g)
	in.Authority = authorityManagedDP
	in.SnapshotReady = false // CP snapshot not yet applied
	res, err := c.AcquireGeneration(context.Background(), in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Outcome != acquireNoFetch {
		t.Fatalf("outcome = %s; want no_fetch", res.Outcome)
	}
	if mux.manifestHits.Load() != 0 {
		t.Fatalf("managed DP fetched %d manifests before an authoritative snapshot", mux.manifestHits.Load())
	}
	assertNoGeneration(t, root)

	// Once the authoritative snapshot is ready, the SAME managed DP proceeds.
	in.SnapshotReady = true
	res2, err := c.AcquireGeneration(context.Background(), in)
	if err != nil || res2.Outcome != acquireCommitted {
		t.Fatalf("managed DP ready: outcome=%s err=%v; want committed", res2.Outcome, err)
	}
}

// ── readiness: disabled / unsupported / bad-url all no-fetch deterministically ────

func TestF3b2_Acquire_ReadinessNoFetch(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	cases := map[string]func(in *AcquireInput){
		"disabled":          func(in *AcquireInput) { in.Config.Enabled = false },
		"unsupported proto": func(in *AcquireInput) { in.Config.Protocol = "raw" },
		"empty url":         func(in *AcquireInput) { in.Config.URL = "" },
		"non-official url":  func(in *AcquireInput) { in.Config.URL = "https://evil.example/x" },
		"unknown authority": func(in *AcquireInput) { in.Authority = feedAuthority(99) },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c, mux, root := newClientWithFake(t, g)
			in := baseAcquireInput(g)
			mut(&in)
			res, err := c.AcquireGeneration(context.Background(), in)
			if err != nil {
				t.Fatalf("%s: unexpected error %v", name, err)
			}
			if res.Outcome != acquireNoFetch || res.Reason == "" {
				t.Fatalf("%s: outcome=%s reason=%q; want no_fetch with a reason", name, res.Outcome, res.Reason)
			}
			if mux.manifestHits.Load() != 0 {
				t.Fatalf("%s: a no-fetch case still hit the origin", name)
			}
			assertNoGeneration(t, root)
		})
	}
}

// ── 27/28. no floor write, no activation-record write ────────────────────────────

func TestF3b2_Acquire_NoFloorOrActivationMutation(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	mux := newFeedMux(g)
	fo := newFeedOrigin(t, mux)
	// Use a shared saas_feed dir so we can assert the floor/activation files are
	// untouched by acquisition.
	saasDir := t.TempDir()
	genRoot := filepath.Join(saasDir, "generations")
	store, _ := newGenerationStore(genRoot)
	c, _ := newSaaSFeedClient(newFakeVerifier(g), fo.fetcher, store)

	// Pre-place floor + activation files and snapshot their bytes.
	floorA := filepath.Join(saasDir, floorFileA)
	floorB := filepath.Join(saasDir, floorFileB)
	activation := filepath.Join(saasDir, "activation-state.json")
	_ = os.WriteFile(floorA, []byte(`{"floor":"a"}`), 0o600)
	_ = os.WriteFile(floorB, []byte(`{"floor":"b"}`), 0o600)
	_ = os.WriteFile(activation, []byte(`{"active":"none"}`), 0o600)
	beforeA, _ := os.ReadFile(floorA)
	beforeB, _ := os.ReadFile(floorB)
	beforeAct, _ := os.ReadFile(activation)

	if _, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g)); err != nil {
		t.Fatalf("acquire: %v", err)
	}

	afterA, _ := os.ReadFile(floorA)
	afterB, _ := os.ReadFile(floorB)
	afterAct, _ := os.ReadFile(activation)
	if string(beforeA) != string(afterA) || string(beforeB) != string(afterB) {
		t.Fatal("acquisition mutated a floor record")
	}
	if string(beforeAct) != string(afterAct) {
		t.Fatal("acquisition mutated the activation record")
	}
}

// ── 29. no live category-store mutation ──────────────────────────────────────────

func TestF3b2_Acquire_NoLiveCategoryStoreMutation(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	c, _, _ := newClientWithFake(t, g)

	before := catStore.All()
	if _, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g)); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	after := catStore.All()
	if len(before) != len(after) {
		t.Fatalf("live category store changed: before=%d after=%d categories", len(before), len(after))
	}
}

// ── 31. no legacy SaaS-syncer interaction ────────────────────────────────────────

func TestF3b2_Acquire_NoLegacySyncerInteraction(t *testing.T) {
	// The acquisition engine composes only the verifier + fetcher + generation store.
	// It must not touch the legacy globalSaaSFeed additive syncer. We assert the
	// legacy syncer's last-sync state is unchanged across an acquisition.
	g := buildFeedGen(t, feedGenOpts{})
	c, _, _ := newClientWithFake(t, g)
	beforeURL, _, beforeCount, _ := globalSaaSFeed.Stats()
	if _, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g)); err != nil {
		t.Fatalf("acquire: %v", err)
	}
	afterURL, _, afterCount, _ := globalSaaSFeed.Stats()
	if beforeURL != afterURL || beforeCount != afterCount {
		t.Fatalf("acquisition perturbed the legacy syncer: url %q→%q count %d→%d", beforeURL, afterURL, beforeCount, afterCount)
	}
}

// ── cancellation classification at the pipeline level ────────────────────────────

func TestF3b2_Acquire_CancelClassified(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	c, _, _ := newClientWithFake(t, g)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.AcquireGeneration(ctx, baseAcquireInput(g))
	if err == nil || !isAcquireCanceled(err) {
		t.Fatalf("err = %v; want a classified cancellation", err)
	}
}

// ── 10. manifest wrapper strictness (real kernel) ────────────────────────────────

func TestF3b2_Acquire_WrapperStrictness(t *testing.T) {
	g := buildFeedGen(t, feedGenOpts{})
	// A structurally-malformed envelope (unknown field) is rejected by the real kernel
	// before any artifact fetch.
	mux := newFeedMux(g)
	mux.gen.EnvelopeBytes = []byte(`{"payload_b64":"AA==","bundle":{"a":1},"extra":true}`)
	fo := newFeedOrigin(t, mux)
	store, _ := newGenerationStore(filepath.Join(t.TempDir(), "generations"))
	c, _ := newSaaSFeedClient(realFeedVerifier(t), fo.fetcher, store)
	_, err := c.AcquireGeneration(context.Background(), baseAcquireInput(g))
	if !errors.Is(err, errAcquireVerify) {
		t.Fatalf("err = %v; want errAcquireVerify", err)
	}
	if mux.artifactHits.Load() != 0 {
		t.Fatalf("wrapper-strict rejection still fetched artifacts")
	}
}

// ── production client assembles from the baked Sigstore root + pinned identity ────

func TestF3b2_ProductionClientBuilds(t *testing.T) {
	// The production constructor wires the real trust kernel (baked public-good
	// Sigstore root + the pinned feed identity), the hardened fetcher, and the
	// generation store. It must assemble without error — but stays DORMANT (nothing
	// in this slice calls it from startup).
	c, err := newProductionSaaSFeedClient(filepath.Join(t.TempDir(), "generations"))
	if err != nil {
		t.Fatalf("newProductionSaaSFeedClient: %v", err)
	}
	if c == nil || c.verifier == nil || c.fetcher == nil || c.store == nil {
		t.Fatalf("production client not fully assembled: %+v", c)
	}
	// Authority stringers are stable identifiers used in no-fetch reasons.
	if authorityManagedDP.String() != "managed-data-plane" ||
		authorityStandalone.String() != "standalone" ||
		authorityControlPlane.String() != "control-plane" {
		t.Fatal("authority stringers drifted")
	}
	if acquireNoFetch.String() != "no_fetch" || acquireCommitted.String() != "committed" {
		t.Fatal("outcome stringers drifted")
	}
}

// ─── helpers ─────────────────────────────────────────────────────────────────────

func assertNoGeneration(t *testing.T, root string) {
	t.Helper()
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if e.Name() == "42" || e.Name() == "43" {
				t.Fatalf("unexpected committed generation %q", e.Name())
			}
		}
	}
}
