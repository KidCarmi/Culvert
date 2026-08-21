package main

// F5 feed-generator + gate tests. Deterministic, network-free, credential-free.
// No secret/key/certificate fixtures. The POSITIVE keyless-signature round-trip is
// the env-gated CI gate TestFeedGenKeylessVerify (real cosign, like the catalog's
// TestReleaseCatalogKeylessVerify); local tests cover generation, strictness, the
// version/validity contracts, the structural envelope round-trip, and the
// no-fail-open verify negative.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/urlcatfeed"
)

func writeDataset(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "dataset.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write dataset: %v", err)
	}
	return p
}

// A small, readiness-clean dataset (single-category, no suffix pairs).
const cleanDatasetJSON = `[
  {"name":"AI","hosts":["anthropic.com","claude.ai"]},
  {"name":"Storage","hosts":["files.example.net"]}
]`

func cleanSpec(t *testing.T) feedGenSpec {
	return feedGenSpec{
		DatasetPath: writeDataset(t, cleanDatasetJSON),
		GeneratedAt: time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC),
	}
}

// ─── #1 source strictness + readiness ────────────────────────────────────────

func TestFeedGen_LoaderStrictness(t *testing.T) {
	cases := map[string]string{
		"unknown field":     `[{"name":"AI","hosts":["a.com"],"bogus":1}]`,
		"trailing data":     `[{"name":"AI","hosts":["a.com"]}] {}`,
		"duplicate name":    `[{"name":"AI","hosts":["a.com"]},{"name":"ai","hosts":["b.com"]}]`,
		"empty set":         `[]`,
		"not an array":      `{"categories":[]}`,
		"malformed":         `[{"name":"AI","hosts":`,
		"non-canonical num": `[{"name":"AI","hosts":["a.com"],}]`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := loadFeedSourceDataset(writeDataset(t, body)); err == nil {
				t.Errorf("%s: loader accepted invalid dataset", name)
			}
		})
	}
	// A valid dataset loads.
	ds, err := loadFeedSourceDataset(writeDataset(t, cleanDatasetJSON))
	if err != nil {
		t.Fatalf("valid dataset rejected: %v", err)
	}
	if len(ds.Categories) != 2 {
		t.Errorf("categories = %d, want 2", len(ds.Categories))
	}
}

func TestFeedGen_ReadinessGate(t *testing.T) {
	// example.com and a.example.com in DIFFERENT categories = ancestor/descendant
	// suffix conflict ⇒ not Ready ⇒ generateFeed must refuse.
	body := `[
	  {"name":"AI","hosts":["example.com"]},
	  {"name":"Storage","hosts":["a.example.com"]}
	]`
	_, err := generateFeed(feedGenSpec{DatasetPath: writeDataset(t, body), GeneratedAt: time.Now()})
	if !errors.Is(err, errFeedNotReady) {
		t.Fatalf("err = %v; want errFeedNotReady", err)
	}
}

// ─── #2 generator determinism + #7 exact bytes ───────────────────────────────

func TestFeedGen_Deterministic(t *testing.T) {
	spec := cleanSpec(t)
	a, err := generateFeed(spec)
	if err != nil {
		t.Fatalf("gen a: %v", err)
	}
	b, err := generateFeed(spec)
	if err != nil {
		t.Fatalf("gen b: %v", err)
	}
	if !bytes.Equal(a.ArtifactBytes, b.ArtifactBytes) {
		t.Error("artifact bytes not deterministic")
	}
	if !bytes.Equal(a.ManifestBytes, b.ManifestBytes) {
		t.Error("manifest bytes not deterministic")
	}
	if a.Inventory != b.Inventory {
		t.Error("inventory not deterministic")
	}
	// Host ordering in the source must not change output (deterministic normalization).
	shuf := `[
	  {"name":"Storage","hosts":["files.example.net"]},
	  {"name":"AI","hosts":["claude.ai","anthropic.com"]}
	]`
	c, err := generateFeed(feedGenSpec{DatasetPath: writeDataset(t, shuf), GeneratedAt: spec.GeneratedAt})
	if err != nil {
		t.Fatalf("gen c: %v", err)
	}
	if !bytes.Equal(a.ArtifactBytes, c.ArtifactBytes) {
		t.Error("artifact bytes depend on source ordering (non-deterministic)")
	}
}

// ─── #4 Unix-second version + #5 same-second/monotonic ────────────────────────

func TestFeedGen_VersionDerivation(t *testing.T) {
	inst := time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC)
	if got, want := deriveFeedVersion(inst), inst.Unix(); got != want {
		t.Errorf("deriveFeedVersion = %d, want Unix %d", got, want)
	}
	// Sub-second differences collapse to the SAME whole-second version (idempotent).
	if deriveFeedVersion(inst) != deriveFeedVersion(inst.Add(400*time.Millisecond)) {
		t.Error("sub-second instants must derive the same feed_version")
	}
	// A later whole second is strictly greater (monotonic over wall-clock).
	if deriveFeedVersion(inst.Add(time.Second)) <= deriveFeedVersion(inst) {
		t.Error("a later instant must derive a strictly greater feed_version")
	}
	// Non-UTC input normalizes to the same instant's Unix seconds.
	loc := time.FixedZone("x", 5*3600)
	if deriveFeedVersion(inst) != deriveFeedVersion(inst.In(loc)) {
		t.Error("timezone must not affect the derived version")
	}
	// The generated manifest carries exactly the derived version.
	b, err := generateFeed(feedGenSpec{DatasetPath: writeDataset(t, cleanDatasetJSON), GeneratedAt: inst})
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	if b.Inventory.FeedVersion != inst.Unix() {
		t.Errorf("manifest feed_version = %d, want %d", b.Inventory.FeedVersion, inst.Unix())
	}
}

// TestFeedGen_ArtifactNameShape pins the immutable artifact-name GRAMMAR that the
// publisher workflow's shell validation depends on: `saas-<feed_version>-<YYYYMMDD>.json`,
// where the VERSION segment is the raw decimal feed_version (variable length) and only
// the DATE segment is fixed at 8 digits. The generator uses `%08d` — a MINIMUM width —
// so a Unix-second version is 10 digits today; a workflow regex that pinned the version
// to exactly 8 digits (`[0-9]{8}`) would reject every real run before cosign. This test
// is the regression guard: it asserts the name matches the version-variable grammar AND
// that the version segment is NOT fixed-width (it exceeds 8 digits for a real instant),
// so the workflow's `[0-9]+` anchor and the generator format can never silently diverge.
func TestFeedGen_ArtifactNameShape(t *testing.T) {
	// Same grammar the sign + publish steps encode in publish-feeds.yml.
	nameRE := regexp.MustCompile(`^saas-(\d+)-\d{8}\.json$`)
	inst := time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC)
	b, err := generateFeed(feedGenSpec{DatasetPath: writeDataset(t, cleanDatasetJSON), GeneratedAt: inst})
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	m := nameRE.FindStringSubmatch(b.Result.ArtifactPath)
	if m == nil {
		t.Fatalf("artifact_path %q does not match the workflow grammar %q", b.Result.ArtifactPath, nameRE)
	}
	// The version segment must be exactly the decimal feed_version.
	ver, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || ver != b.Inventory.FeedVersion {
		t.Fatalf("version segment %q != feed_version %d", m[1], b.Inventory.FeedVersion)
	}
	// A real Unix-second version is >8 digits — proving the version segment is NOT
	// fixed-width, which is exactly the assumption a `[0-9]{8}` anchor would break.
	if len(m[1]) <= 8 {
		t.Fatalf("version segment %q is <=8 digits; the workflow must not pin it to a fixed width", m[1])
	}
	if b.Result.ArtifactSigPath != b.Result.ArtifactPath+".sigstore" {
		t.Errorf("artifact_sig_path %q != %q", b.Result.ArtifactSigPath, b.Result.ArtifactPath+".sigstore")
	}
	// Belt-and-suspenders: the sig name matches the same grammar with a .sigstore tail.
	if !strings.HasSuffix(b.Result.ArtifactSigPath, ".json.sigstore") {
		t.Errorf("artifact_sig_path %q lacks the .json.sigstore tail", b.Result.ArtifactSigPath)
	}
}

// The generator rejects a version that is not strictly greater than the previous
// (the sign job passes prev=0; a re-sign that supplied a stale prev would fail here,
// and the publisher CAS enforces > published regardless).
func TestFeedGen_RejectsNonIncreasingVersion(t *testing.T) {
	inst := time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC)
	spec := feedGenSpec{DatasetPath: writeDataset(t, cleanDatasetJSON), GeneratedAt: inst, PrevFeedVersion: inst.Unix()}
	if _, err := generateFeed(spec); err == nil {
		t.Error("generateFeed accepted a version equal to prev (must be strictly greater)")
	}
	// A strictly-greater version (one second later) is accepted.
	spec.GeneratedAt = inst.Add(time.Second)
	if _, err := generateFeed(spec); err != nil {
		t.Errorf("strictly-greater version rejected: %v", err)
	}
}

// ─── #3 14-day validity, 30-day ceiling ───────────────────────────────────────

func TestFeedGen_ValidityWindow(t *testing.T) {
	inst := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	// Default = 14 days.
	b, err := generateFeed(feedGenSpec{DatasetPath: writeDataset(t, cleanDatasetJSON), GeneratedAt: inst})
	if err != nil {
		t.Fatalf("default validity: %v", err)
	}
	gen, _ := time.Parse(time.RFC3339, b.Inventory.GeneratedAt)
	exp, _ := time.Parse(time.RFC3339, b.Inventory.ExpiresAt)
	if exp.Sub(gen) != feedNormalValidity {
		t.Errorf("default validity = %s, want %s", exp.Sub(gen), feedNormalValidity)
	}
	// Over the 30-day ceiling is rejected.
	if _, err := generateFeed(feedGenSpec{DatasetPath: writeDataset(t, cleanDatasetJSON), GeneratedAt: inst, Validity: 31 * 24 * time.Hour}); !errors.Is(err, errFeedValidity) {
		t.Errorf("31-day validity err = %v; want errFeedValidity", err)
	}
	// Exactly 30 days (the ceiling) is allowed.
	if _, err := generateFeed(feedGenSpec{DatasetPath: writeDataset(t, cleanDatasetJSON), GeneratedAt: inst, Validity: urlcatfeed.MaxValidity}); err != nil {
		t.Errorf("30-day validity rejected: %v", err)
	}
}

// ─── #7 exact binding: cross-check helpers (pure, no signing) ─────────────────

func TestFeedGen_CrossCheckBinding(t *testing.T) {
	b, err := generateFeed(cleanSpec(t))
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	// A verified manifest whose artifact digest matches the generated result passes;
	// a mismatch (the poisoning vector) is rejected.
	good := &urlcatfeed.ManifestPayload{ArtifactSHA256: b.Result.ArtifactSHA256, HostCount: b.Inventory.HostCount, CategoryCount: b.Inventory.CategoryCount}
	if err := crossCheckVerifiedManifest(good, b.Result); err != nil {
		t.Errorf("matching manifest rejected: %v", err)
	}
	bad := &urlcatfeed.ManifestPayload{ArtifactSHA256: "0000000000000000000000000000000000000000000000000000000000000000"}
	if err := crossCheckVerifiedManifest(bad, b.Result); err == nil {
		t.Error("mismatched artifact digest accepted")
	}
	if b.Inventory.EnvelopeKey != "manifest.sigstore.json" {
		t.Errorf("envelope key = %q, want manifest.sigstore.json", b.Inventory.EnvelopeKey)
	}
}

// ─── #17/#25 offline verify does not fail open ────────────────────────────────

func TestFeedGen_VerifyRejectsUnsignedEnvelope(t *testing.T) {
	b, err := generateFeed(cleanSpec(t))
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	// A structurally-plausible but unsigned/garbage bundle must be REJECTED by the
	// production baked-root verifier — the publisher never promotes on a fail-open.
	garbage := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"messageSignature":{"signature":"AAAA"}}`)
	if _, err := assembleAndVerifyFeedEnvelope(b, garbage, garbage); err == nil {
		t.Fatal("assembleAndVerifyFeedEnvelope accepted an unsigned/garbage bundle (fail-open)")
	}
}

// ─── the real publication-ready dataset is loadable + ready + generable ───────

func TestFeedGen_RealDatasetReadyAndGenerable(t *testing.T) {
	const datasetPath = "internal/urlcat/default_categories.json"
	ds, err := loadFeedSourceDataset(datasetPath)
	if err != nil {
		t.Fatalf("load real dataset: %v", err)
	}
	if rep := urlcatfeed.EvaluateReadiness(ds); !rep.Ready {
		t.Fatalf("real dataset not Ready: %s", summarizeReadiness(rep))
	}
	b, err := generateFeed(feedGenSpec{DatasetPath: datasetPath, GeneratedAt: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("generate from real dataset: %v", err)
	}
	if b.Inventory.CategoryCount < 1 || b.Inventory.HostCount < 1 {
		t.Errorf("degenerate counts: cats=%d hosts=%d", b.Inventory.CategoryCount, b.Inventory.HostCount)
	}
	if b.Inventory.ArtifactSize > urlcatfeed.MaxArtifactSize {
		t.Errorf("artifact %d exceeds the %d ceiling", b.Inventory.ArtifactSize, urlcatfeed.MaxArtifactSize)
	}
}

// ─── writeFeedGenOutput materializes the handoff safely ───────────────────────

func TestFeedGen_WriteOutput(t *testing.T) {
	b, err := generateFeed(cleanSpec(t))
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	dir := t.TempDir()
	if err := writeFeedGenOutput(dir, b); err != nil {
		t.Fatalf("write: %v", err)
	}
	for _, name := range []string{b.Result.ArtifactPath, "manifest-payload.json", "metadata.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("expected output file %q: %v", name, err)
		}
	}
	// metadata.json is valid inventory JSON binding the artifact.
	raw, _ := os.ReadFile(filepath.Join(dir, "metadata.json"))
	var inv feedInventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatalf("metadata.json invalid: %v", err)
	}
	if inv.ArtifactSHA256 != b.Result.ArtifactSHA256 || inv.FeedVersion != b.Inventory.FeedVersion {
		t.Error("metadata.json does not bind the generated artifact")
	}
}

// ─── CI gate: generate to CULVERT_FEED_GEN_OUT (env-gated; skips locally) ──────

func TestFeedGenGate(t *testing.T) {
	out := os.Getenv("CULVERT_FEED_GEN_OUT")
	if out == "" {
		t.Skip("CULVERT_FEED_GEN_OUT unset — CI-only gate")
	}
	spec, err := resolveFeedGateSpec()
	if err != nil {
		t.Fatalf("resolve gate spec: %v", err)
	}
	b, err := generateFeed(spec)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if err := writeFeedGenOutput(out, b); err != nil {
		t.Fatalf("write output: %v", err)
	}
	t.Logf("feed gate: version=%d artifact=%s cats=%d hosts=%d", b.Inventory.FeedVersion, b.Inventory.ArtifactPath, b.Inventory.CategoryCount, b.Inventory.HostCount)
}

// TestFeedGenKeylessVerify assembles the envelope from the REAL cosign bundles the
// signing step produced and runs the production offline verify (baked root + pinned
// feed identity). Env-gated; skips unless CULVERT_FEED_GEN_VERIFY_SIGSTORE is set.
func TestFeedGenKeylessVerify(t *testing.T) {
	if os.Getenv("CULVERT_FEED_GEN_VERIFY_SIGSTORE") == "" {
		t.Skip("CULVERT_FEED_GEN_VERIFY_SIGSTORE unset — CI-only keyless verify")
	}
	out := os.Getenv("CULVERT_FEED_GEN_OUT")
	if out == "" {
		t.Fatal("CULVERT_FEED_GEN_OUT required for keyless verify")
	}
	spec, err := resolveFeedGateSpec()
	if err != nil {
		t.Fatalf("resolve gate spec: %v", err)
	}
	b, err := generateFeed(spec) // deterministic — reproduces the exact signed bytes
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	manBundle, err := os.ReadFile(filepath.Join(out, "manifest-payload.json.sigstore"))
	if err != nil {
		t.Fatalf("read manifest bundle: %v", err)
	}
	artBundle, err := os.ReadFile(filepath.Join(out, b.Result.ArtifactSigPath))
	if err != nil {
		t.Fatalf("read artifact bundle: %v", err)
	}
	env, err := assembleAndVerifyFeedEnvelope(b, manBundle, artBundle)
	if err != nil {
		t.Fatalf("assemble+verify: %v", err)
	}
	if err := os.WriteFile(filepath.Join(out, feedEnvelopeKey), env, 0o600); err != nil {
		t.Fatalf("write envelope: %v", err)
	}
	t.Logf("keyless verify OK: envelope %d bytes for version %d", len(env), b.Inventory.FeedVersion)
}

// TestFeedPublishVerifyGate is the PUBLISHER's (Job B) re-verify gate: it runs the
// FULL production offline verifier over an ALREADY-ASSEMBLED bundle in
// CULVERT_FEED_PUBLISH_DIR (envelope + the artifact it names + the artifact bundle)
// WITHOUT regenerating, and on success emits the VERIFIED manifest facts the
// publisher needs — feed_version for the §11.3 CAS strictly-greater check, plus the
// artifact keys/digests — to CULVERT_FEED_PUBLISH_VERIFIED_OUT. The publisher runs
// this THREE times: over Job A's downloaded workflow artifact, over the public
// artifact fetched through feeds.culvertlabs.com, and over the public envelope after
// promotion. Env-gated (CI-only); the feed_version emitted here is taken from SIGNED
// bytes, so the CAS is never driven by unsigned metadata.
func TestFeedPublishVerifyGate(t *testing.T) {
	dir := os.Getenv("CULVERT_FEED_PUBLISH_DIR")
	if dir == "" {
		t.Skip("CULVERT_FEED_PUBLISH_DIR unset — CI-only publisher re-verify gate")
	}
	manifest, err := verifyFeedBundleDir(dir)
	if err != nil {
		t.Fatalf("publisher re-verify failed: %v", err)
	}
	if out := os.Getenv("CULVERT_FEED_PUBLISH_VERIFIED_OUT"); out != "" {
		facts := feedInventory{
			SchemaVersion:   manifest.SchemaVersion,
			Protocol:        manifest.Protocol,
			Feed:            manifest.Feed,
			FeedVersion:     manifest.FeedVersion,
			GeneratedAt:     manifest.GeneratedAt,
			ExpiresAt:       manifest.ExpiresAt,
			ArtifactPath:    manifest.ArtifactPath,
			ArtifactSigPath: manifest.ArtifactSigPath,
			ArtifactSHA256:  manifest.ArtifactSHA256,
			ArtifactSize:    manifest.ArtifactSize,
			EnvelopeKey:     feedEnvelopeKey,
			CategoryCount:   manifest.CategoryCount,
			HostCount:       manifest.HostCount,
		}
		b, err := json.MarshalIndent(facts, "", "  ")
		if err != nil {
			t.Fatalf("marshal verified facts: %v", err)
		}
		if err := os.WriteFile(out, append(b, '\n'), 0o600); err != nil {
			t.Fatalf("write verified facts: %v", err)
		}
	}
	t.Logf("publisher re-verify OK: feed_version=%d artifact=%s cats=%d hosts=%d",
		manifest.FeedVersion, manifest.ArtifactPath, manifest.CategoryCount, manifest.HostCount)
}

// TestFeedPublishVerifyGate_RejectsTampered proves the publisher gate FAILS CLOSED
// when the on-disk envelope is not a validly-signed feed envelope — the local proof
// that the CI gate cannot pass on unsigned/forged bytes (the positive signed path is
// the env-gated TestFeedPublishVerifyGate driven by real cosign bundles in CI). The
// envelope is verified FIRST, so an un-verifiable manifest.sigstore.json aborts the
// gate before any artifact file is even read.
func TestFeedPublishVerifyGate_RejectsTampered(t *testing.T) {
	dir := t.TempDir()
	// A garbage envelope (not a validly-signed feed envelope). verifyFeedBundleDir
	// must reject it via the production verifier rather than fail open.
	if err := os.WriteFile(filepath.Join(dir, feedEnvelopeKey),
		[]byte(`{"payload_b64":"eyJib2d1cyI6dHJ1ZX0=","bundle":{}}`), 0o600); err != nil {
		t.Fatalf("write garbage envelope: %v", err)
	}
	if _, err := verifyFeedBundleDir(dir); err == nil {
		t.Fatal("verifyFeedBundleDir accepted an unverifiable envelope — publisher gate must fail closed")
	}
}

// resolveFeedGateSpec builds the generation spec from the CI env. Extracted +
// separately tested so the shell→Go handoff cannot silently drift.
func resolveFeedGateSpec() (feedGenSpec, error) {
	return buildFeedGateSpec(os.Getenv)
}

// TestResolveFeedGateSpec_MatchesBuild closes the env→spec seam.
func TestResolveFeedGateSpec_MatchesBuild(t *testing.T) {
	env := map[string]string{
		"CULVERT_FEED_GEN_DATASET":      "internal/urlcat/default_categories.json",
		"CULVERT_FEED_GEN_GENERATED_AT": "2026-08-02T03:04:05Z",
		"CULVERT_FEED_GEN_VALIDITY_HRS": "336",
	}
	spec, err := buildFeedGateSpec(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if spec.DatasetPath != env["CULVERT_FEED_GEN_DATASET"] {
		t.Errorf("dataset = %q", spec.DatasetPath)
	}
	if !spec.GeneratedAt.Equal(time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("generated_at = %s", spec.GeneratedAt)
	}
	if spec.Validity != 336*time.Hour {
		t.Errorf("validity = %s", spec.Validity)
	}
	wantVer := time.Date(2026, 8, 2, 3, 4, 5, 0, time.UTC).Unix()
	if got := deriveFeedVersion(spec.GeneratedAt); got != wantVer {
		t.Errorf("derived version = %d, want %d", got, wantVer)
	}
}
