package main

// saas_feed_client.go — F3b-2: the one-shot candidate-acquisition orchestrator for
// the signed SaaS URL-category feed.
//
// Authority: roadmap/FEEDS-DISTRIBUTION-F3-DESIGN.md — the F3b-2 slice + §A.8
// (URL/SSRF), §B.4/§B.5 (immutable generation), and F0 §6 (verify order). This file
// composes the transport (saas_feed_download.go), the trust kernel
// (internal/urlcatfeed VerifyEnvelope/VerifyArtifact), the F3b-1 rollback floor
// (READ-ONLY, for the accept decision), and the immutable generation store
// (saas_feed_genstore.go) into ONE explicit, one-shot pipeline.
//
// This engine is DORMANT: it is NOT wired into startup, arms NO scheduler/loop,
// performs NO automatic fetch, writes/advances NO rollback floor, writes NO
// activation record, and mutates NO live category store or in-memory serving point.
// It fetches on demand, verifies, and persists an immutable generation, then returns
// a TYPED verified-generation result for F3b-3 to activate. F3b-3 owns activation,
// recovery cutover, GC, scheduling, and observability wiring.
//
// Verify-before-parse is the security spine (F0 §6, enforced here as an ORDER):
//
//	fetch envelope (bounded) → strict outer-wrapper parse → verify manifest
//	signature + pinned identity → ONLY THEN expose manifest fields → schema/
//	protocol/feed/canonical/validity checks (kernel) → current-time freshness +
//	future-skew (here) → rollback-floor accept (here, strictly-greater) → fetch
//	artifact+bundle (bounded, key from the VERIFIED manifest) → bind size+digest →
//	verify artifact signature → parse artifact → bind protocol/feed/version/
//	generated_at/counts to the manifest → persist immutable generation.
//
// No unverified manifest or artifact field reaches caller-visible typed content: the
// kernel returns a COMPLETE verified object or nothing, and this pipeline aborts the
// WHOLE candidate on any mismatch.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

// ─── feed verifier seam ──────────────────────────────────────────────────────────

// feedVerifier is the trust-kernel seam. Production is *urlcatfeed.Verifier (built
// from the baked Sigstore public-good root + the pinned feed identity). The two
// methods return a COMPLETE verified object or no object (verify-before-parse).
type feedVerifier interface {
	VerifyEnvelope(envelopeBytes []byte) (*urlcatfeed.ManifestPayload, error)
	VerifyArtifact(artifactBytes, bundleJSON []byte, manifest *urlcatfeed.ManifestPayload) (*urlcatfeed.ArtifactPayload, error)
}

// ─── authority / readiness ───────────────────────────────────────────────────────

// feedAuthority names the source of the effective configuration's authority (F3a
// §A.0). It gates readiness: a managed data plane must NOT fetch before an
// authoritative Control-Plane snapshot is available (never a local/default/stale
// fallback); standalone / CP nodes are locally authoritative.
type feedAuthority int

const (
	authorityStandalone feedAuthority = iota
	authorityControlPlane
	authorityManagedDP
)

func (a feedAuthority) String() string {
	switch a {
	case authorityStandalone:
		return "standalone"
	case authorityControlPlane:
		return "control-plane"
	case authorityManagedDP:
		return "managed-data-plane"
	default:
		return "unknown"
	}
}

func (a feedAuthority) valid() bool {
	return a == authorityStandalone || a == authorityControlPlane || a == authorityManagedDP
}

// saasFeedDefaultFutureSkew is the accepted forward clock skew for a candidate's
// generated_at (F0 §10 / §B.11). A candidate dated beyond now+skew is rejected.
const saasFeedDefaultFutureSkew = 5 * time.Minute

// ─── acquisition input / result ──────────────────────────────────────────────────

// AcquireInput is the explicit, already-resolved input to one acquisition. The
// client REQUIRES an explicit effective configuration and authority — it never reads
// global/default/stale state to decide whether or where to fetch.
type AcquireInput struct {
	// Config is the RESOLVED, validated effective feed configuration (F3a
	// ResolveSaaSFeedConfig for standalone/CP; the applied CP snapshot for a managed
	// DP). Disabled/incomplete/unsupported ⇒ a deterministic no-fetch.
	Config SaaSFeedConfig

	// Authority is where Config's authority comes from (readiness gating).
	Authority feedAuthority

	// SnapshotReady is meaningful ONLY for a managed DP: true iff an authoritative CP
	// snapshot has been applied. False ⇒ ownership-unresolved ⇒ no fetch.
	SnapshotReady bool

	// RecoveredFloor is the effective recovered rollback-floor VERSION, resolved by
	// the caller READ-ONLY from the F3b-1 floor subsystem. A network candidate is
	// accepted only if its feed_version is STRICTLY GREATER. This engine never writes
	// or advances the floor.
	RecoveredFloor int64

	// PriorETag, when non-empty, makes the manifest fetch conditional (If-None-Match).
	// A 304 is a typed NotModified result, never verified new content.
	PriorETag string

	// Now is the injected clock for freshness (nil ⇒ time.Now).
	Now func() time.Time

	// FutureSkew overrides the accepted forward skew for generated_at (0 ⇒ default).
	FutureSkew time.Duration
}

func (in AcquireInput) now() time.Time {
	if in.Now != nil {
		return in.Now().UTC()
	}
	return time.Now().UTC()
}

func (in AcquireInput) skew() time.Duration {
	if in.FutureSkew > 0 {
		return in.FutureSkew
	}
	return saasFeedDefaultFutureSkew
}

// acquireOutcome classifies the one-shot result.
type acquireOutcome int

const (
	acquireNoFetch     acquireOutcome = iota // readiness gate rejected before any network I/O
	acquireNotModified                       // conditional 304 — no new content
	acquireCommitted                         // a NEW immutable generation was persisted
	acquireIdempotent                        // the generation already existed, byte/digest-identical
)

func (o acquireOutcome) String() string {
	switch o {
	case acquireNoFetch:
		return "no_fetch"
	case acquireNotModified:
		return "not_modified"
	case acquireCommitted:
		return "committed"
	case acquireIdempotent:
		return "idempotent"
	default:
		return "unknown"
	}
}

// VerifiedGeneration is the typed, fully-verified result handed to F3b-3. It carries
// the verified manifest+artifact payloads, the digest bindings, and the immutable
// on-disk directory — enough for activation and for reconstructing the floor record.
// It does NOT imply the generation is active: activation is F3b-3.
type VerifiedGeneration struct {
	FeedVersion    int64
	GenerationID   string
	GeneratedAt    string
	ExpiresAt      string
	ManifestSHA256 string // sha256 of the stored manifest.envelope.json
	ArtifactSHA256 string // sha256 of the stored artifact.json (== manifest.artifact_sha256)
	ArtifactSize   int64
	CategoryCount  int
	HostCount      int
	Dir            string // absolute immutable generation directory
	Persisted      genPersistOutcome
	Manifest       *urlcatfeed.ManifestPayload
	Artifact       *urlcatfeed.ArtifactPayload
}

// AcquireResult is the one-shot outcome. Exactly one of NotModified/Generation is set
// for a fetch that reached the origin; NoFetch carries a human-readable Reason.
type AcquireResult struct {
	Outcome    acquireOutcome
	Reason     string // set for acquireNoFetch
	ETag       string // manifest ETag (200 or 304), for the caller's next conditional fetch
	Generation *VerifiedGeneration
}

// ─── acquisition errors ──────────────────────────────────────────────────────────

var (
	errAcquireVerify   = errors.New("saas feed acquire: manifest/artifact verification failed")
	errAcquireFresh    = errors.New("saas feed acquire: candidate failed freshness")
	errAcquireExpired  = errors.New("saas feed acquire: candidate already expired")
	errAcquireFuture   = errors.New("saas feed acquire: candidate generated_at is beyond the accepted future skew")
	errAcquireFloor    = errors.New("saas feed acquire: candidate feed_version is not strictly greater than the rollback floor")
	errAcquirePersist  = errors.New("saas feed acquire: immutable generation persist failed")
	errAcquireManifest = errors.New("saas feed acquire: manifest fetch failed")
	errAcquireArtifact = errors.New("saas feed acquire: artifact fetch failed")
	errAcquireInternal = errors.New("saas feed acquire: internal invariant violated")
	errAcquireCanceled = errors.New("saas feed acquire: canceled")
)

// ─── the client ──────────────────────────────────────────────────────────────────

// saasFeedClient composes the verifier, fetcher, and immutable generation store. It
// holds NO mutable feed state; each AcquireGeneration call is a self-contained
// one-shot pipeline.
type saasFeedClient struct {
	verifier feedVerifier
	fetcher  *feedFetcher
	store    *generationStore
}

// newSaaSFeedClient composes an explicitly-provided verifier, fetcher, and store
// (the test-friendly core).
func newSaaSFeedClient(verifier feedVerifier, fetcher *feedFetcher, store *generationStore) (*saasFeedClient, error) {
	if verifier == nil || fetcher == nil || store == nil {
		return nil, fmt.Errorf("%w: nil dependency", errAcquireInternal)
	}
	return &saasFeedClient{verifier: verifier, fetcher: fetcher, store: store}, nil
}

// newProductionSaaSFeedClient builds the production client: the trust kernel from the
// baked Sigstore public-good root + the pinned feed identity, the hardened fetcher,
// and the immutable generation store rooted under generationsRoot
// (<dataDir>/saas_feed/generations). It is DORMANT until F3b-3 wires it; nothing in
// this slice calls it from startup.
func newProductionSaaSFeedClient(generationsRoot string) (*saasFeedClient, error) {
	verifier, err := urlcatfeed.NewVerifierFromJSON(bakedSigstoreTrustedRootJSON, urlcatfeed.OfficialIdentity())
	if err != nil {
		return nil, fmt.Errorf("saas feed acquire: build verifier: %w", err)
	}
	store, err := newGenerationStore(generationsRoot)
	if err != nil {
		return nil, err
	}
	return newSaaSFeedClient(verifier, newFeedFetcher(feedFetcherOpts{}), store)
}

// AcquireGeneration runs the one-shot pipeline. It returns a typed AcquireResult and
// an error only for a genuine failure (verification/network/persist). A readiness
// rejection is a NON-error acquireNoFetch result (deterministic no-fetch). A
// cancellation is classified so a caller can exclude shutdown from failure counters.
func (c *saasFeedClient) AcquireGeneration(ctx context.Context, in AcquireInput) (AcquireResult, error) {
	// ── Step 0: readiness (no network before this passes). ──
	if reason, ok := c.readiness(in); !ok {
		return AcquireResult{Outcome: acquireNoFetch, Reason: reason}, nil
	}

	// ── Steps 1–7: fetch + verify the manifest, then freshness + floor accept. ──
	manifest, envelopeBytes, etag, notModified, err := c.acquireManifest(ctx, in)
	if err != nil {
		return AcquireResult{}, err
	}
	if notModified {
		return AcquireResult{Outcome: acquireNotModified, ETag: etag}, nil
	}

	// ── Steps 8–14: fetch + verify + bind the artifact (keys from the VERIFIED
	// manifest). Only reached because the manifest passed verify + freshness + floor. ──
	artifactBytes, bundleBytes, artifact, err := c.acquireArtifact(ctx, in, manifest)
	if err != nil {
		return AcquireResult{}, err
	}

	// ── Step 15: persist the fully-verified candidate as an immutable generation. ──
	// Derive the feed-owned normalized snapshot from the VERIFIED artifact and stage it
	// with the signed evidence, so §B.4's snapshot.normalized.json is durable inside the
	// immutable generation (F3b-3 composes it with overrides; it never has to be added
	// later by mutating the immutable dir).
	snapshotBytes, err := normalizedSnapshotBytes(artifact)
	if err != nil {
		return AcquireResult{}, fmt.Errorf("%w: normalized snapshot: %v", errAcquireInternal, err)
	}
	cand := generationCandidate{
		FeedVersion:    manifest.FeedVersion,
		GenerationID:   feedVersionID(manifest.FeedVersion),
		GeneratedAt:    manifest.GeneratedAt,
		ExpiresAt:      manifest.ExpiresAt,
		ManifestSHA256: sha256Hex(envelopeBytes),
		ArtifactSHA256: manifest.ArtifactSHA256,
		ArtifactSize:   manifest.ArtifactSize,
		CategoryCount:  manifest.CategoryCount,
		HostCount:      manifest.HostCount,
		EnvelopeBytes:  envelopeBytes,
		ArtifactBytes:  artifactBytes,
		BundleBytes:    bundleBytes,
		SnapshotBytes:  snapshotBytes,
	}
	persisted, err := c.store.Persist(ctx, cand)
	if err != nil {
		if isFeedFetchCanceled(err) {
			return AcquireResult{}, classifyAcquireCtx(err)
		}
		return AcquireResult{}, fmt.Errorf("%w: %v", errAcquirePersist, err)
	}

	out := acquireCommitted
	if persisted.Outcome == genPersistIdempotent {
		out = acquireIdempotent
	}
	return AcquireResult{
		Outcome: out,
		ETag:    etag,
		Generation: &VerifiedGeneration{
			FeedVersion:    manifest.FeedVersion,
			GenerationID:   cand.GenerationID,
			GeneratedAt:    manifest.GeneratedAt,
			ExpiresAt:      manifest.ExpiresAt,
			ManifestSHA256: cand.ManifestSHA256,
			ArtifactSHA256: cand.ArtifactSHA256,
			ArtifactSize:   manifest.ArtifactSize,
			CategoryCount:  manifest.CategoryCount,
			HostCount:      manifest.HostCount,
			Dir:            persisted.Dir,
			Persisted:      persisted.Outcome,
			Manifest:       manifest,
			Artifact:       artifact,
		},
	}, nil
}

// acquireManifest fetches the manifest envelope (bounded), verifies it BEFORE parse,
// then applies current-time freshness + future-skew (steps 5–6) and the rollback-floor
// accept (step 7, strictly-greater) — all BEFORE any artifact byte is fetched. It
// returns notModified=true for a conditional 304 (no manifest).
func (c *saasFeedClient) acquireManifest(ctx context.Context, in AcquireInput) (manifest *urlcatfeed.ManifestPayload, envelopeBytes []byte, etag string, notModified bool, err error) {
	if e := ctx.Err(); e != nil {
		return nil, nil, "", false, classifyAcquireCtx(e)
	}
	fetched, ferr := c.fetcher.fetchManifest(ctx, in.Config.URL, in.PriorETag)
	if ferr != nil {
		if isFeedFetchCanceled(ferr) {
			return nil, nil, "", false, classifyAcquireCtx(ferr)
		}
		return nil, nil, "", false, fmt.Errorf("%w: %v", errAcquireManifest, ferr)
	}
	if fetched.NotModified {
		return nil, nil, fetched.ETag, true, nil
	}
	m, verr := c.verifier.VerifyEnvelope(fetched.Body)
	if verr != nil {
		// A forged/unsigned/tampered envelope yields NO manifest object — and, by
		// construction, drives ZERO artifact fetches (we return here).
		return nil, nil, "", false, fmt.Errorf("%w: envelope: %v", errAcquireVerify, verr)
	}
	if m == nil { // defensive: the kernel never returns (nil,nil)
		return nil, nil, "", false, fmt.Errorf("%w: nil manifest on success", errAcquireInternal)
	}
	if ferr := c.checkFreshness(m, in); ferr != nil {
		return nil, nil, "", false, ferr
	}
	// Rollback-floor accept — STRICTLY greater than the recovered floor. The floor is
	// only READ here; nothing writes or advances it.
	if m.FeedVersion <= in.RecoveredFloor {
		return nil, nil, "", false, fmt.Errorf("%w: v%d <= floor v%d", errAcquireFloor, m.FeedVersion, in.RecoveredFloor)
	}
	return m, fetched.Body, fetched.ETag, false, nil
}

// acquireArtifact fetches the artifact + its Sigstore bundle (keys from the VERIFIED
// manifest, bounded), verifies + binds them (size + digest + signature + counts +
// version + generated_at), and returns the raw bytes + verified artifact.
func (c *saasFeedClient) acquireArtifact(ctx context.Context, in AcquireInput, manifest *urlcatfeed.ManifestPayload) (artifactBytes, bundleBytes []byte, artifact *urlcatfeed.ArtifactPayload, err error) {
	if e := ctx.Err(); e != nil {
		return nil, nil, nil, classifyAcquireCtx(e)
	}
	// Bound the artifact read by the SIGNED, verified artifact_size (clamped to the
	// protocol cap): min(artifact_size, MaxArtifactSize)+1 (§A.8). The kernel already
	// validated artifact_size ∈ (0, MaxArtifactSize], so an oversized/malformed body is
	// rejected at read time — before VerifyArtifact — instead of reading up to the full
	// 8 MiB cap for a small declared artifact (Codex P2).
	artifactLimit := manifest.ArtifactSize
	if artifactLimit > urlcatfeed.MaxArtifactSize {
		artifactLimit = urlcatfeed.MaxArtifactSize
	}
	artifactBytes, aerr := c.fetcher.fetchArtifactObject(ctx, in.Config.URL, manifest.ArtifactPath, artifactLimit)
	if aerr != nil {
		return nil, nil, nil, c.wrapArtifactErr(aerr, "")
	}
	bundleBytes, berr := c.fetcher.fetchArtifactObject(ctx, in.Config.URL, manifest.ArtifactSigPath, urlcatfeed.MaxBundleBytes)
	if berr != nil {
		return nil, nil, nil, c.wrapArtifactErr(berr, "bundle: ")
	}
	art, verr := c.verifier.VerifyArtifact(artifactBytes, bundleBytes, manifest)
	if verr != nil {
		// A tampered/mis-signed/mis-bound artifact yields NO artifact object and NO
		// persisted generation.
		return nil, nil, nil, fmt.Errorf("%w: artifact: %v", errAcquireVerify, verr)
	}
	if art == nil {
		return nil, nil, nil, fmt.Errorf("%w: nil artifact on success", errAcquireInternal)
	}
	return artifactBytes, bundleBytes, art, nil
}

func (c *saasFeedClient) wrapArtifactErr(err error, prefix string) error {
	if isFeedFetchCanceled(err) {
		return classifyAcquireCtx(err)
	}
	return fmt.Errorf("%w: %s%v", errAcquireArtifact, prefix, err)
}

// readiness enforces the config-readiness contract. It returns (reason, false) for a
// deterministic no-fetch and ("", true) to proceed. It performs NO network I/O.
func (c *saasFeedClient) readiness(in AcquireInput) (string, bool) {
	if !in.Authority.valid() {
		return "unknown configuration authority", false
	}
	if !in.Config.Enabled {
		return "feed disabled", false
	}
	// A managed DP MUST NOT fetch before an authoritative CP snapshot is available —
	// never fall back to local/default/stale policy because CP is temporarily
	// unavailable (ownership-unresolved ⇒ deterministic no-fetch).
	if in.Authority == authorityManagedDP && !in.SnapshotReady {
		return "managed data plane: awaiting authoritative control-plane snapshot", false
	}
	if in.Config.Protocol != saasFeedProtocolV1 {
		return fmt.Sprintf("unsupported protocol %q", in.Config.Protocol), false
	}
	if in.Config.URL == "" {
		return "no manifest url", false
	}
	// Re-check the official-origin URL contract before any fetch (defense-in-depth
	// over the settings-write validation; §A.8 "re-checked before every fetch").
	if err := validateOfficialManifestURL(in.Config.URL); err != nil {
		return fmt.Sprintf("url contract: %v", err), false
	}
	return "", true
}

// checkFreshness enforces the client-side, current-time freshness the trust kernel
// deliberately leaves to the client (F0 §10): reject an already-expired candidate and
// a future-dated one (generated_at beyond now+skew). The kernel already proved the
// timestamps are canonical and expires>generated with a ≤30d window. A wall-clock
// anomaly produces a conservative REJECTION (never activation); no malicious-clock
// protection is claimed (§B.11).
func (c *saasFeedClient) checkFreshness(m *urlcatfeed.ManifestPayload, in AcquireInput) error {
	gen, ok := canonicalUTCSecond(m.GeneratedAt)
	if !ok {
		return fmt.Errorf("%w: non-canonical generated_at %q", errAcquireFresh, m.GeneratedAt)
	}
	exp, ok := canonicalUTCSecond(m.ExpiresAt)
	if !ok {
		return fmt.Errorf("%w: non-canonical expires_at %q", errAcquireFresh, m.ExpiresAt)
	}
	now := in.now()
	if !now.Before(exp) { // now >= expires ⇒ expired
		return fmt.Errorf("%w: expires_at %s <= now %s", errAcquireExpired, m.ExpiresAt, now.Format(time.RFC3339))
	}
	if gen.After(now.Add(in.skew())) {
		return fmt.Errorf("%w: generated_at %s > now+skew", errAcquireFuture, m.GeneratedAt)
	}
	return nil
}

// classifyAcquireCtx maps a context error to the canceled class so callers can
// exclude shutdown from failure accounting.
func classifyAcquireCtx(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %v", errAcquireCanceled, err)
	}
	return err
}

// isAcquireCanceled reports whether err is the acquisition cancellation class.
func isAcquireCanceled(err error) bool {
	return errors.Is(err, errAcquireCanceled) || isFeedFetchCanceled(err)
}

// feedVersionID renders the immutable generation id for a feed version (the decimal
// string; §B.3/§B.4).
func feedVersionID(v int64) string { return fmt.Sprintf("%d", v) }

// normalizedFeedSnapshot is the feed-owned normalized category layer persisted as
// snapshot.normalized.json (§B.4). It is a deterministic projection of the VERIFIED
// artifact — the feed's normalized, sorted categories — WITHOUT admin overrides
// (overrides are CP-synced/mutable and are layered on at F3b-3 activation, so they must
// NOT live in the immutable per-generation dir). Its bytes are canonical (fixed field
// order, no HTML escaping, no trailing newline), so the snapshot is byte-stable.
type normalizedFeedSnapshot struct {
	SchemaVersion int                        `json:"schema_version"`
	Feed          string                     `json:"feed"`
	FeedVersion   int64                      `json:"feed_version"`
	GeneratedAt   string                     `json:"generated_at"`
	Categories    []normalizedFeedCategoryJS `json:"categories"`
}

type normalizedFeedCategoryJS struct {
	Name  string   `json:"name"`
	Hosts []string `json:"hosts"`
}

// normalizedSnapshotBytes derives the canonical normalized-snapshot bytes from the
// verified artifact. The artifact's categories are already normalized, deduplicated,
// and strictly sorted (kernel-enforced), so this is a pure, order-preserving projection.
func normalizedSnapshotBytes(a *urlcatfeed.ArtifactPayload) ([]byte, error) {
	if a == nil {
		return nil, fmt.Errorf("%w: nil artifact", errAcquireInternal)
	}
	cats := make([]normalizedFeedCategoryJS, 0, len(a.Categories))
	for i := range a.Categories {
		cats = append(cats, normalizedFeedCategoryJS{Name: a.Categories[i].Name, Hosts: a.Categories[i].Hosts})
	}
	snap := normalizedFeedSnapshot{
		SchemaVersion: a.SchemaVersion,
		Feed:          a.Feed,
		FeedVersion:   a.FeedVersion,
		GeneratedAt:   a.GeneratedAt,
		Categories:    cats,
	}
	return floorCanonicalBytes(snap)
}
