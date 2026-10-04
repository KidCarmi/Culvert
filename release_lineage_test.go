package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/releaseproof"
)

const lineageRepo = "ghcr.io/kidcarmi/culvert"

// lineageSigner signs every catalog in a test with ONE ed25519 key, the shape
// of the production situation (one release identity signs every catalog).
type lineageSigner struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newLineageSigner(t *testing.T) *lineageSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &lineageSigner{pub: pub, priv: priv}
}

func (s *lineageSigner) sig(t *testing.T, idx []byte) []byte {
	t.Helper()
	b, err := json.Marshal(catalogSigEnvelope{SchemaVersion: catalogSchemaMajor, Alg: catalogSigAlg, KeyID: "lineage",
		Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, idx))})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (s *lineageSigner) trust(t *testing.T) TrustStore {
	t.Helper()
	ts, err := NewTrustStore([]TrustKey{{KeyID: "lineage", Alg: catalogSigAlg, PublicKey: s.pub}}, VerifyEnforce)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func lineageEntry(v string) releaseEntrySpec {
	return releaseEntrySpec{ReleaseID: "culvert-" + v, VersionID: v, Severity: "normal", Repo: lineageRepo,
		ListDigest: lineageDigestFor(v), Platforms: []string{"linux/amd64"}, CreatedAt: "2026-09-01T00:00:00Z",
		MinUpgradeFrom: "1.0.250", Channels: []Channel{ChannelRecommended}}
}

// lineageDigestFor gives each version a distinct, well-formed digest.
func lineageDigestFor(v string) string {
	h := fmt.Sprintf("%064x", []byte(v))
	return "sha256:" + h[len(h)-64:]
}

// publishSingle writes the catalog a release was published with (only itself),
// as every pre-lineage release did, and returns its directory.
func publishSingle(t *testing.T, s *lineageSigner, v string, carried []carriedRelease) string {
	t.Helper()
	b, err := generateReleaseCatalog(releaseCatalogSpec{GeneratedAt: "2026-09-01T00:00:00Z", ExpiresAt: "2027-03-01T00:00:00Z",
		CatalogVersion: 1000000000 + int(lineagePatch(v)), Entries: []releaseEntrySpec{lineageEntry(v)}, Carried: carried})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "v"+v)
	if err := writeReleaseBundle(dir, b, s.sig(t, b.Index)); err != nil {
		t.Fatal(err)
	}
	return dir
}

func lineagePatch(v string) int64 {
	var a, b, c int64
	_, _ = fmt.Sscanf(v, "%d.%d.%d", &a, &b, &c)
	return c
}

func carriedVersions(c []carriedRelease) string {
	vs := make([]string, len(c))
	for i := range c {
		vs[i] = c[i].VersionID
	}
	return strings.Join(vs, ",")
}

func TestLineage_CarriesEverySupportedSourceVerbatim(t *testing.T) {
	s := newLineageSigner(t)
	var srcs []lineageSource
	for _, v := range []string{"1.0.249", "1.0.250", "1.0.251", "1.0.252"} {
		srcs = append(srcs, lineageSource{Dir: publishSingle(t, s, v, nil)})
	}
	got, err := collectVerifiedPredecessors(srcs, s.trust(t), lineageRepo, "1.0.250", "1.0.253", []string{"v1.0.250", "1.0.251", "1.0.252"})
	if err != nil {
		t.Fatal(err)
	}
	if carriedVersions(got) != "1.0.250,1.0.251,1.0.252" {
		t.Fatalf("carried %s; want the supported sources only (1.0.249 is below the floor)", carriedVersions(got))
	}
	for i := range got {
		want, err := os.ReadFile(filepath.Join(srcs[i+1].Dir, "manifests", got[i].ReleaseID+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got[i].Manifest) {
			t.Fatalf("%s: carried manifest is not byte-identical to the verified source", got[i].ReleaseID)
		}
	}
}

func TestLineage_RefusesWhatItCannotVerify(t *testing.T) {
	s := newLineageSigner(t)
	good := publishSingle(t, s, "1.0.251", nil)
	other := newLineageSigner(t)
	foreign := publishSingle(t, other, "1.0.252", nil) // signed by a key the trust store does not hold
	if _, err := collectVerifiedPredecessors([]lineageSource{{good}, {foreign}}, s.trust(t), lineageRepo, "1.0.250", "1.0.253", nil); err == nil {
		t.Fatal("a source signed by an untrusted key contributed to the lineage")
	}
	// A tampered manifest no longer matches the signed index hash.
	tampered := publishSingle(t, s, "1.0.252", nil)
	p := filepath.Join(tampered, "manifests", "culvert-1.0.252.json")
	raw, _ := os.ReadFile(p)
	if err := os.WriteFile(p, bytes.Replace(raw, []byte(`"normal"`), []byte(`"critical"`), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := collectVerifiedPredecessors([]lineageSource{{good}, {tampered}}, s.trust(t), lineageRepo, "1.0.250", "1.0.253", nil); err == nil {
		t.Fatal("a tampered manifest was carried")
	}
	// Permissive/disabled trust never feeds a lineage.
	perm, err := NewTrustStore(nil, VerifyPermissive)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collectVerifiedPredecessors([]lineageSource{{good}}, perm, lineageRepo, "1.0.250", "1.0.253", nil); err == nil {
		t.Fatal("a non-enforce trust store fed the lineage")
	}
}

func TestLineage_MissingSupportedSourceFailsPublication(t *testing.T) {
	s := newLineageSigner(t)
	srcs := []lineageSource{{publishSingle(t, s, "1.0.250", nil)}, {publishSingle(t, s, "1.0.252", nil)}}
	_, err := collectVerifiedPredecessors(srcs, s.trust(t), lineageRepo, "1.0.250", "1.0.253", []string{"1.0.250", "1.0.251", "1.0.252"})
	if err == nil || !strings.Contains(err.Error(), "1.0.251") {
		t.Fatalf("missing supported source not reported: %v", err)
	}
}

func TestLineage_ConflictingVerifiedManifestsFailClosed(t *testing.T) {
	s := newLineageSigner(t)
	a := publishSingle(t, s, "1.0.251", nil)
	e := lineageEntry("1.0.251")
	e.Severity = "critical" // same release id, different signed content
	b2, err := generateReleaseCatalog(releaseCatalogSpec{GeneratedAt: "2026-09-02T00:00:00Z", ExpiresAt: "2027-03-01T00:00:00Z", CatalogVersion: 5, Entries: []releaseEntrySpec{e}})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "conflict")
	if err := writeReleaseBundle(dir, b2, s.sig(t, b2.Index)); err != nil {
		t.Fatal(err)
	}
	if _, err := collectVerifiedPredecessors([]lineageSource{{a}, {dir}}, s.trust(t), lineageRepo, "1.0.250", "1.0.253", nil); err == nil {
		t.Fatal("two different signed manifests for one release were merged")
	}
}

func TestLineage_OtherRepositoryIsNeverCarried(t *testing.T) {
	s := newLineageSigner(t)
	e := lineageEntry("1.0.251")
	e.Repo = "ghcr.io/someone/else"
	b, err := generateReleaseCatalog(releaseCatalogSpec{GeneratedAt: "2026-09-01T00:00:00Z", ExpiresAt: "2027-03-01T00:00:00Z", CatalogVersion: 3, Entries: []releaseEntrySpec{e}})
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "elsewhere")
	if err := writeReleaseBundle(dir, b, s.sig(t, b.Index)); err != nil {
		t.Fatal(err)
	}
	got, err := collectVerifiedPredecessors([]lineageSource{{dir}}, s.trust(t), lineageRepo, "1.0.250", "1.0.253", nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("carried %d release(s) from another repository (err %v)", len(got), err)
	}
}

func TestLineage_GeneratorRejectsCarriedIdentityMismatch(t *testing.T) {
	s := newLineageSigner(t)
	got, err := collectVerifiedPredecessors([]lineageSource{{publishSingle(t, s, "1.0.251", nil)}}, s.trust(t), lineageRepo, "", "1.0.253", nil)
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	bad := got[0]
	bad.ListDigest = lineageDigestFor("9.9.9")
	spec := releaseCatalogSpec{GeneratedAt: "2026-09-03T00:00:00Z", ExpiresAt: "2027-03-01T00:00:00Z", CatalogVersion: 9,
		Entries: []releaseEntrySpec{lineageEntry("1.0.253")}, Carried: []carriedRelease{bad}}
	if _, err := generateReleaseCatalog(spec); err == nil {
		t.Fatal("a carried release whose identity disagrees with its manifest was emitted")
	}
	dup := got[0]
	dup.ReleaseID = "culvert-1.0.253"
	spec.Carried = []carriedRelease{dup}
	if _, err := generateReleaseCatalog(spec); err == nil {
		t.Fatal("a carried release collided with the generated target")
	}
}

// lineageCatalog builds the TARGET's catalog the way CI does now: the target
// generated, every supported predecessor carried from its verified catalog.
func lineageCatalog(t *testing.T, s *lineageSigner, target string, published []string) (*Catalog, string) {
	t.Helper()
	var srcs []lineageSource
	for _, v := range published {
		srcs = append(srcs, lineageSource{Dir: publishSingle(t, s, v, nil)})
	}
	carried, err := collectVerifiedPredecessors(srcs, s.trust(t), lineageRepo, "1.0.250", target, published)
	if err != nil {
		t.Fatal(err)
	}
	dir := publishSingle(t, s, target, carried)
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, s.trust(t))
	if err != nil {
		t.Fatalf("the lineage catalog failed real verification: %v", err)
	}
	return cat, dir
}

func agentVerifier(t *testing.T, s *lineageSigner) *releaseproof.Verifier {
	t.Helper()
	v, err := releaseproof.NewVerifier(releaseproof.Policy{CatalogRepository: lineageRepo, ProxyRepository: lineageRepo,
		Ed25519Keys: map[string][]byte{"lineage": s.pub}})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// TestLineage_RealDispatchCarriesProofTheAgentAccepts drives the real planner
// for a direct predecessor and a SKIPPED-release source, and verifies both
// pieces of evidence with the agent's own verifier — the boundary that
// returned 403 for every real upgrade before.
func TestLineage_RealDispatchCarriesProofTheAgentAccepts(t *testing.T) {
	s := newLineageSigner(t)
	cat, _ := lineageCatalog(t, s, "1.0.253", []string{"1.0.250", "1.0.251", "1.0.252"})
	if r, err := cat.Resolve(ChannelRecommended); err != nil || r.VersionID != "1.0.253" {
		t.Fatalf("recommended channel = %+v, %v; want the target only", r, err)
	}
	d, err := NewDispatcher(e2eCatalogProvider{cat: cat}, DispatchConfig{ProxyRepo: lineageRepo})
	if err != nil {
		t.Fatal(err)
	}
	av := agentVerifier(t, s)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for _, running := range []string{"1.0.252", "1.0.250"} { // direct and skipped (two releases skipped)
		ref := lineageRepo + "@" + lineageDigestFor(running)
		plan := d.Plan(DispatchTarget{Channel: ChannelRecommended}, []string{ref}, DispatchOptions{})
		if plan.Outcome != OutcomePlan {
			t.Fatalf("from %s: outcome %v (%v)", running, plan.Outcome, plan.Reason)
		}
		if plan.Apply.ReleaseProof == nil || plan.Apply.PriorReleaseProof == nil {
			t.Fatalf("from %s: dispatch carries no baseline proof — the agent refuses with an empty ledger", running)
		}
		ta, err := av.Verify(*plan.Apply.ReleaseProof, plan.Apply.ImageRef, now)
		if err != nil {
			t.Fatalf("from %s: agent rejects target proof: %v", running, err)
		}
		pa, err := av.Verify(*plan.Apply.PriorReleaseProof, ref, now)
		if err != nil {
			t.Fatalf("from %s: agent rejects baseline proof for the running digest: %v", running, err)
		}
		if err := ta.CheckUpgradeFrom(pa); err != nil {
			t.Fatalf("from %s: signed floor refuses a supported source: %v", running, err)
		}
		// A proof is bound to its digest: the baseline evidence must not
		// authorize any other image (1.0.251 is never the running one here).
		if _, err := av.Verify(*plan.Apply.PriorReleaseProof, lineageRepo+"@"+lineageDigestFor("1.0.251"), now); err == nil {
			t.Fatalf("from %s: baseline proof authorized a different digest", running)
		}
	}
}

// TestLineage_SingleEntryCatalogStillCannotProveTheBaseline pins the defect
// this replaces: with only the target in the catalog the planner has nothing
// to send, which is exactly the agent's 403.
func TestLineage_SingleEntryCatalogStillCannotProveTheBaseline(t *testing.T) {
	s := newLineageSigner(t)
	dir := publishSingle(t, s, "1.0.253", nil)
	cat, err := LoadVerifiedCatalog(&dirCatalogSource{dir: dir}, s.trust(t))
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDispatcher(e2eCatalogProvider{cat: cat}, DispatchConfig{ProxyRepo: lineageRepo, SelfVersion: "1.0.252"})
	if err != nil {
		t.Fatal(err)
	}
	plan := d.Plan(DispatchTarget{Channel: ChannelRecommended}, []string{lineageRepo + "@" + lineageDigestFor("1.0.252")}, DispatchOptions{})
	if plan.Outcome != OutcomePlan || plan.Apply.PriorReleaseProof != nil {
		t.Fatalf("outcome %v prior %v; want a plan with NO baseline proof (the pre-lineage shape)", plan.Outcome, plan.Apply.PriorReleaseProof != nil)
	}
}

// TestLineage_RealPublishedCatalogs verifies the REAL published catalog assets
// with the baked Sigstore root and pinned release identity, and builds a
// lineage from them. Opt-in (needs the downloaded assets): set
// CULVERT_RELEASE_LINEAGE_REAL_DIR to a directory of v<version>/ bundles.
func TestLineage_RealPublishedCatalogs(t *testing.T) {
	root := os.Getenv("CULVERT_RELEASE_LINEAGE_REAL_DIR")
	if root == "" {
		t.Skip("set CULVERT_RELEASE_LINEAGE_REAL_DIR to the extracted published catalog bundles")
	}
	srcs, want := lineageSourcesIn(t, root)
	target := os.Getenv("CULVERT_RELEASE_LINEAGE_REAL_TARGET")
	if target == "" {
		target = "1.0.260"
	}
	got, err := collectVerifiedPredecessors(srcs, productionLineageTrust(t), lineageRepo, releaseMinUpgradeFrom, target, want)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified and carried %d published release(s): %s", len(got), carriedVersions(got))
}

// productionLineageTrust is the trust a predecessor must verify against before
// it is carried: the baked Sigstore root + the pinned official release
// identity, enforce mode — the same verification an appliance applies.
func productionLineageTrust(t *testing.T) TrustStore {
	t.Helper()
	sv, err := newSigstoreVerifier(bakedSigstoreTrustedRootJSON, officialSigstoreIdentity())
	if err != nil {
		t.Fatal(err)
	}
	trust, err := NewTrustStoreWithSigstore(nil, VerifyEnforce, sv)
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

// lineageSourcesIn lists the v<version>/ bundle directories under root and the
// versions their names claim.
func lineageSourcesIn(t *testing.T, root string) ([]lineageSource, []string) {
	t.Helper()
	ents, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var srcs []lineageSource
	var names []string
	for _, e := range ents {
		if e.IsDir() && strings.HasPrefix(e.Name(), "v") {
			srcs = append(srcs, lineageSource{Dir: filepath.Join(root, e.Name())})
			names = append(names, strings.TrimPrefix(e.Name(), "v"))
		}
	}
	return srcs, names
}

// TestLineage_ReleasePipelineCarriesPredecessors pins the CI wiring: the
// catalog-pipeline job fetches the predecessor bundles UNCONDITIONALLY (both the
// main-push gate and the tag release) and hands them to the gate. Removing the
// step, gating it behind an `if:`, or dropping the env from the gate would
// silently publish single-entry catalogs again — every behavioural test stays
// green while every real upgrade is refused by the agent.
func TestLineage_ReleasePipelineCarriesPredecessors(t *testing.T) {
	raw, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	y := string(raw)
	start := strings.Index(y, "      - name: Fetch supported predecessor catalogs (release lineage)\n")
	if start < 0 {
		t.Fatal("ci.yml: the release-lineage fetch step is missing")
	}
	step := y[start:]
	if end := strings.Index(step[1:], "\n      - "); end > 0 {
		step = step[:end+1]
	}
	for _, want := range []string{"id: lineage", ".github/scripts/fetch-release-lineage.sh \"$VERSION\""} {
		if !strings.Contains(step, want) {
			t.Fatalf("lineage step lost %q:\n%s", want, step)
		}
	}
	if strings.Contains(step, "\n        if:") {
		t.Fatalf("the lineage step must run on every catalog-pipeline execution:\n%s", step)
	}
	gate := strings.Index(y, "      - name: Run release catalog gate (build spec + generate + verify + digest-match)\n")
	if gate < start {
		t.Fatal("the catalog gate must run after the lineage fetch")
	}
	gs := y[gate:]
	if end := strings.Index(gs[1:], "\n      - "); end > 0 {
		gs = gs[:end+1]
	}
	for _, want := range []string{
		"CULVERT_RELEASE_LINEAGE_SRC: ${{ steps.lineage.outputs.src }}",
		"CULVERT_RELEASE_LINEAGE_REQUIRE: ${{ steps.lineage.outputs.require }}",
	} {
		if !strings.Contains(gs, want) {
			t.Fatalf("catalog gate step lost %q:\n%s", want, gs)
		}
	}
}
