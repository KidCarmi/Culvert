package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ─── test source + builders ──────────────────────────────────────────────────

// memSource is an in-memory CatalogSource for content-variant tests. It does NOT
// validate the ref shape (that is the dir source's job); LoadCatalog content
// validation is exercised through here, and ref/symlink/size handling through
// the dir source.
type memSource struct {
	index     []byte
	manifests map[string][]byte
	indexErr  error
	manErr    error
}

func (m *memSource) ReadIndex() ([]byte, error) {
	if m.indexErr != nil {
		return nil, m.indexErr
	}
	return m.index, nil
}

func (m *memSource) ReadManifest(ref string) ([]byte, error) {
	if m.manErr != nil {
		return nil, m.manErr
	}
	b, ok := m.manifests[ref]
	if !ok {
		return nil, fmt.Errorf("memSource: no such manifest %q", ref)
	}
	return b, nil
}

func (m *memSource) clone() *memSource {
	nm := &memSource{index: append([]byte(nil), m.index...), manifests: map[string][]byte{}}
	for k, v := range m.manifests {
		nm.manifests[k] = append([]byte(nil), v...)
	}
	return nm
}

const (
	digA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	repo = "ghcr.io/kidcarmi/culvert"
)

type relSpec struct {
	ref       string
	releaseID string
	versionID string
	raw       string
}

func manifestJSON(releaseID, versionID, severity, repo, listDigest string) string {
	return fmt.Sprintf(`{"schema_version":1,"release_id":%q,"version_id":%q,"severity":%q,`+
		`"created_at":"2026-04-18T00:00:00Z","image":{"repo":%q,"list_digest":%q,`+
		`"platforms":["linux/amd64","linux/arm64"]},"min_upgrade_from":"1.2.0"}`,
		releaseID, versionID, severity, repo, listDigest)
}

// buildCatalogSource computes each manifest's sha256 and wires a matching index.
//
//nolint:unparam // test catalog builder; generated_at kept explicit for clarity
func buildCatalogSource(channels map[string]string, schemaVersion int, generatedAt string, rels []relSpec) *memSource {
	mans := map[string][]byte{}
	entries := make([]string, 0, len(rels))
	for _, r := range rels {
		b := []byte(r.raw)
		mans[r.ref] = b
		sum := sha256.Sum256(b)
		entries = append(entries, fmt.Sprintf(`{"release_id":%q,"version_id":%q,"manifest_ref":%q,"manifest_sha256":%q}`,
			r.releaseID, r.versionID, r.ref, hex.EncodeToString(sum[:])))
	}
	chJSON, _ := json.Marshal(channels)
	idx := fmt.Sprintf(`{"schema_version":%d,"generated_at":%q,"channels":%s,"releases":[%s]}`,
		schemaVersion, generatedAt, chJSON, strings.Join(entries, ","))
	return &memSource{index: []byte(idx), manifests: mans}
}

// validSource: rel_a (1.10.0, recommended+critical) and rel_b (1.9.0, lts), plus
// an unknown "beta" channel key that must be ignored.
func validSource() *memSource {
	return buildCatalogSource(
		map[string]string{"recommended": "rel_a", "lts": "rel_b", "critical": "rel_a", "beta": "rel_a"},
		1, "2026-04-18T00:00:00Z",
		[]relSpec{
			{ref: "a.json", releaseID: "rel_a", versionID: "1.10.0", raw: manifestJSON("rel_a", "1.10.0", "critical", repo, digA)},
			{ref: "b.json", releaseID: "rel_b", versionID: "1.9.0", raw: manifestJSON("rel_b", "1.9.0", "normal", repo, digB)},
		})
}

func mustLoad(t *testing.T, src CatalogSource) *Catalog {
	t.Helper()
	c, err := LoadCatalog(src)
	if err != nil {
		t.Fatalf("LoadCatalog: unexpected error: %v", err)
	}
	return c
}

func mustReject(t *testing.T, src CatalogSource, what string) {
	t.Helper()
	if c, err := LoadCatalog(src); err == nil {
		t.Fatalf("LoadCatalog should have rejected %s; got a catalog: %+v", what, c)
	}
}

// ─── happy path + queries ────────────────────────────────────────────────────

func TestLoadCatalog_HappyPath(t *testing.T) {
	c := mustLoad(t, validSource())
	if len(c.byReleaseID) != 2 || len(c.byPinnedRef) != 2 {
		t.Fatalf("maps not fully populated: byReleaseID=%d byPinnedRef=%d", len(c.byReleaseID), len(c.byPinnedRef))
	}
	if c.GeneratedAt().IsZero() {
		t.Error("GeneratedAt not set")
	}
	// Known channels resolved; the unknown "beta" key was ignored.
	if len(c.channels) != 3 {
		t.Errorf("expected 3 known channels (recommended/lts/critical); got %d", len(c.channels))
	}
}

func TestResolve_ForwardChannels(t *testing.T) {
	c := mustLoad(t, validSource())
	cases := map[Channel]struct {
		ver, ref string
		sev      Severity
	}{
		ChannelRecommended: {"1.10.0", repo + "@" + digA, SeverityCritical},
		ChannelCritical:    {"1.10.0", repo + "@" + digA, SeverityCritical},
		ChannelLTS:         {"1.9.0", repo + "@" + digB, SeverityNormal},
	}
	for ch, want := range cases {
		got, err := c.Resolve(ch)
		if err != nil {
			t.Errorf("Resolve(%s): %v", ch, err)
			continue
		}
		if got.VersionID != want.ver || got.PinnedRef != want.ref || got.Severity != want.sev {
			t.Errorf("Resolve(%s) = %+v; want ver=%s ref=%s sev=%s", ch, got, want.ver, want.ref, want.sev)
		}
	}
}

func TestResolve_PinnedRefIsRepoBound(t *testing.T) {
	c := mustLoad(t, validSource())
	got, err := c.Resolve(ChannelRecommended)
	if err != nil {
		t.Fatal(err)
	}
	// Must be the agent's repo@sha256:<64hex> shape, NOT a bare sha256:…
	shape := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:-]*@sha256:[0-9a-f]{64}$`)
	if !shape.MatchString(got.PinnedRef) {
		t.Errorf("PinnedRef %q is not repo-bound (agent shape)", got.PinnedRef)
	}
	if strings.HasPrefix(got.PinnedRef, "sha256:") {
		t.Errorf("PinnedRef must not be a bare digest: %q", got.PinnedRef)
	}
}

func TestResolve_UnknownChannelErrors(t *testing.T) {
	c := mustLoad(t, validSource())
	// "beta" was an unknown key (ignored at load) → not resolvable.
	if _, err := c.Resolve(Channel("beta")); err == nil {
		t.Error("Resolve(beta) should error (unknown channel)")
	}
	if _, err := c.Resolve(Channel("nope")); err == nil {
		t.Error("Resolve(nope) should error")
	}
}

func TestLookupAndCurrent(t *testing.T) {
	c := mustLoad(t, validSource())
	// Reverse: exact PinnedRef match.
	if rel, ok := c.Lookup(repo + "@" + digA); !ok || rel.ReleaseID != "rel_a" {
		t.Errorf("Lookup(known) = %+v ok=%v; want rel_a", rel, ok)
	}
	if _, ok := c.Lookup(repo + "@sha256:" + strings.Repeat("c", 64)); ok {
		t.Error("Lookup(unknown) should be ok=false")
	}
	// Current: Known only on exact match.
	if cur := c.Current(repo + "@" + digA); !cur.Known || cur.ReleaseID != "rel_a" {
		t.Errorf("Current(exact) = %+v; want Known rel_a", cur)
	}
}

// Current is Unknown/Custom (NOT an error) for per-arch / tag / legacy / foreign
// digests — every class the contract enumerates.
func TestCurrent_UnknownClassesAreCustomNotError(t *testing.T) {
	c := mustLoad(t, validSource())
	unknown := []string{
		repo + "@sha256:" + strings.Repeat("c", 64), // a different (per-arch/foreign) digest
		"ghcr.io/kidcarmi/culvert:1.10.0",           // a tag, not a digest
		"docker.io/library/nginx@" + digA,           // foreign repo, same digest hex
		"",                                          // empty / legacy
		"sha256:" + strings.Repeat("a", 64),         // bare digest (not repo-bound)
	}
	for _, ref := range unknown {
		if cur := c.Current(ref); cur.Known {
			t.Errorf("Current(%q) should be Unknown/Custom; got Known %+v", ref, cur)
		}
	}
}

func TestList_SemverOrderAndBadges(t *testing.T) {
	c := mustLoad(t, validSource())
	views := c.List()
	if len(views) != 2 {
		t.Fatalf("List len = %d; want 2", len(views))
	}
	// Semver-safe: 1.10.0 must sort ABOVE 1.9.0 (NOT lexical, which would invert).
	if views[0].VersionID != "1.10.0" || views[1].VersionID != "1.9.0" {
		t.Errorf("List order = [%s, %s]; want [1.10.0, 1.9.0] (semver, not lexical)", views[0].VersionID, views[1].VersionID)
	}
	// rel_a carries recommended + critical badges; digest-free view.
	wantBadges := []Channel{ChannelCritical, ChannelRecommended}
	if fmt.Sprint(views[0].Channels) != fmt.Sprint(wantBadges) {
		t.Errorf("rel_a badges = %v; want %v", views[0].Channels, wantBadges)
	}
}

// ─── forward-compatibility (B2) ──────────────────────────────────────────────

func TestForwardCompat_UnknownChannelKeyIgnored(t *testing.T) {
	c := mustLoad(t, validSource()) // already contains a "beta" key
	if _, ok := c.channels[Channel("beta")]; ok {
		t.Error("unknown channel key must not be stored")
	}
}

// An unknown channel key pointing at a MISSING release still loads (the key is
// ignored before its target is checked).
func TestForwardCompat_UnknownChannelDanglingStillLoads(t *testing.T) {
	src := buildCatalogSource(
		map[string]string{"recommended": "rel_a", "beta": "rel_missing"},
		1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: manifestJSON("rel_a", "1.0.0", "normal", repo, digA)}},
	)
	mustLoad(t, src)
}

func TestForwardCompat_UnknownSeverityRetained(t *testing.T) {
	src := buildCatalogSource(
		map[string]string{"recommended": "rel_a"},
		1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: manifestJSON("rel_a", "1.0.0", "spicy", repo, digA)}},
	)
	c := mustLoad(t, src)
	if c.byReleaseID["rel_a"].Severity != SeverityUnknown {
		t.Errorf("unknown severity = %q; want %q (neither coerced nor rejected)", c.byReleaseID["rel_a"].Severity, SeverityUnknown)
	}
}

// A MISSING (empty) severity is a missing required field → fail closed. This is
// distinct from a non-empty UNKNOWN value, which loads as SeverityUnknown
// (above). An omitted severity must NOT be silently treated as "unknown".
func TestFailClosed_MissingSeverity(t *testing.T) {
	raw := `{"schema_version":1,"release_id":"rel_a","version_id":"1.0.0",` +
		`"created_at":"2026-04-18T00:00:00Z","image":{"repo":"` + repo + `","list_digest":"` + digA + `"}}`
	src := buildCatalogSource(map[string]string{"recommended": "rel_a"}, 1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: raw}})
	mustReject(t, src, "missing severity")
}

func TestForwardCompat_AdditiveFieldTolerated(t *testing.T) {
	raw := `{"schema_version":1,"release_id":"rel_a","version_id":"1.0.0","severity":"normal",` +
		`"created_at":"2026-04-18T00:00:00Z","image":{"repo":"` + repo + `","list_digest":"` + digA + `"},` +
		`"future_field":"ignored","image_extra":{"x":1}}`
	src := buildCatalogSource(map[string]string{"recommended": "rel_a"}, 1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: raw}})
	mustLoad(t, src) // unknown fields tolerated within a supported major
}

func TestCompat_UnsupportedMajorRejected(t *testing.T) {
	for _, ver := range []int{0, 2, 99} {
		src := buildCatalogSource(map[string]string{"recommended": "rel_a"}, ver, "2026-04-18T00:00:00Z",
			[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: manifestJSON("rel_a", "1.0.0", "normal", repo, digA)}})
		mustReject(t, src, fmt.Sprintf("index schema_version=%d", ver))
	}
	// Manifest with an unsupported major also rejects.
	bad := strings.Replace(manifestJSON("rel_a", "1.0.0", "normal", repo, digA), `"schema_version":1`, `"schema_version":2`, 1)
	src := buildCatalogSource(map[string]string{"recommended": "rel_a"}, 1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: bad}})
	mustReject(t, src, "manifest schema_version=2")
}

// ─── fail-closed: required fields / shapes ───────────────────────────────────

func TestFailClosed_HashMismatch_RawBytes(t *testing.T) {
	// Appending whitespace keeps the JSON semantically identical but changes the
	// raw bytes → hash mismatch → reject. Proves the hash is over RAW bytes, not
	// re-marshaled/canonical JSON.
	src := validSource().clone()
	src.manifests["a.json"] = append(src.manifests["a.json"], ' ')
	mustReject(t, src, "manifest_sha256 mismatch (raw-byte)")
}

func TestFailClosed_ManifestMissing(t *testing.T) {
	src := validSource().clone()
	delete(src.manifests, "a.json")
	mustReject(t, src, "missing manifest")
}

func TestFailClosed_DanglingKnownChannel(t *testing.T) {
	src := buildCatalogSource(
		map[string]string{"recommended": "rel_missing"},
		1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: manifestJSON("rel_a", "1.0.0", "normal", repo, digA)}},
	)
	mustReject(t, src, "dangling known channel pointer")
}

func TestFailClosed_DuplicateReleaseID(t *testing.T) {
	src := buildCatalogSource(
		map[string]string{"recommended": "rel_a"},
		1, "2026-04-18T00:00:00Z",
		[]relSpec{
			{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: manifestJSON("rel_a", "1.0.0", "normal", repo, digA)},
			{ref: "a2.json", releaseID: "rel_a", versionID: "1.1.0", raw: manifestJSON("rel_a", "1.1.0", "normal", repo, digB)},
		},
	)
	mustReject(t, src, "duplicate release_id")
}

func TestFailClosed_DuplicatePinnedRef(t *testing.T) {
	src := buildCatalogSource(
		map[string]string{"recommended": "rel_a"},
		1, "2026-04-18T00:00:00Z",
		[]relSpec{
			{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: manifestJSON("rel_a", "1.0.0", "normal", repo, digA)},
			{ref: "b.json", releaseID: "rel_b", versionID: "1.1.0", raw: manifestJSON("rel_b", "1.1.0", "normal", repo, digA)}, // same digest
		},
	)
	mustReject(t, src, "duplicate pinned ref (one digest → one release)")
}

func TestFailClosed_EmptyReleases(t *testing.T) {
	src := buildCatalogSource(map[string]string{}, 1, "2026-04-18T00:00:00Z", nil)
	mustReject(t, src, "empty releases")
}

func TestFailClosed_BadShapes(t *testing.T) {
	mk := func(raw string) *memSource {
		return buildCatalogSource(map[string]string{"recommended": "rel_a"}, 1, "2026-04-18T00:00:00Z",
			[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: raw}})
	}
	bad := map[string]string{
		"non-semver version_id": manifestJSON("rel_a", "1.0", "normal", repo, digA),
		"tagged repo":           manifestJSON("rel_a", "1.0.0", "normal", "ghcr.io/kidcarmi/culvert:latest", digA),
		"repo with @digest":     manifestJSON("rel_a", "1.0.0", "normal", "ghcr.io/kidcarmi/culvert@x", digA),
		"short digest":          manifestJSON("rel_a", "1.0.0", "normal", repo, "sha256:"+strings.Repeat("a", 63)),
		"uppercase digest":      manifestJSON("rel_a", "1.0.0", "normal", repo, "sha256:"+strings.Repeat("A", 64)),
		"missing created_at":    `{"schema_version":1,"release_id":"rel_a","version_id":"1.0.0","severity":"normal","image":{"repo":"` + repo + `","list_digest":"` + digA + `"}}`,
		"bad created_at":        `{"schema_version":1,"release_id":"rel_a","version_id":"1.0.0","severity":"normal","created_at":"not-a-time","image":{"repo":"` + repo + `","list_digest":"` + digA + `"}}`,
	}
	for name, raw := range bad {
		// Note: version_id in the index entry must match the manifest, so for the
		// non-semver case the index entry version must equal the manifest's.
		idxVer := "1.0.0"
		if name == "non-semver version_id" {
			idxVer = "1.0"
		}
		src := buildCatalogSource(map[string]string{"recommended": "rel_a"}, 1, "2026-04-18T00:00:00Z",
			[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: idxVer, raw: raw}})
		_ = mk
		mustReject(t, src, name)
	}
}

// The bare-name/traversal contract holds for ANY source, not just the dir
// source — LoadCatalog validates manifest_ref before calling ReadManifest.
func TestFailClosed_ManifestRefTraversal_AnySource(t *testing.T) {
	src := buildCatalogSource(map[string]string{"recommended": "rel_a"}, 1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "../evil.json", releaseID: "rel_a", versionID: "1.0.0", raw: manifestJSON("rel_a", "1.0.0", "normal", repo, digA)}})
	mustReject(t, src, "traversal manifest_ref (source-independent)")
}

// Malformed SemVer (empty prerelease/build suffix, leading zeros, empty
// identifiers, non-numeric) must fail closed — not order as a final release.
func TestFailClosed_MalformedSemver(t *testing.T) {
	for _, ver := range []string{"1.0.0-", "1.0.0+", "1.02.0", "1.0.0-alpha..1", "1.0.0-+x", "v1.0.0", "1.0.0.0"} {
		src := buildCatalogSource(map[string]string{"recommended": "rel_a"}, 1, "2026-04-18T00:00:00Z",
			[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: ver, raw: manifestJSON("rel_a", ver, "normal", repo, digA)}})
		mustReject(t, src, fmt.Sprintf("malformed semver %q", ver))
	}
}

func TestList_PrereleaseOrdersBelowRelease(t *testing.T) {
	src := buildCatalogSource(map[string]string{"recommended": "rel_rel"}, 1, "2026-04-18T00:00:00Z",
		[]relSpec{
			{ref: "rc.json", releaseID: "rel_rc", versionID: "1.0.0-rc.1", raw: manifestJSON("rel_rc", "1.0.0-rc.1", "normal", repo, digA)},
			{ref: "rel.json", releaseID: "rel_rel", versionID: "1.0.0", raw: manifestJSON("rel_rel", "1.0.0", "normal", repo, digB)},
		})
	c := mustLoad(t, src)
	views := c.List()
	if views[0].VersionID != "1.0.0" || views[1].VersionID != "1.0.0-rc.1" {
		t.Errorf("prerelease ordering = [%s, %s]; want [1.0.0, 1.0.0-rc.1] (release > prerelease)", views[0].VersionID, views[1].VersionID)
	}
}

func TestFailClosed_BadReleaseID(t *testing.T) {
	// Control char and over-length release_ids are rejected (§4.7).
	for _, id := range []string{"rel\na", "rel a", "rel\x00a", strings.Repeat("x", 129)} {
		src := buildCatalogSource(map[string]string{}, 1, "2026-04-18T00:00:00Z",
			[]relSpec{{ref: "a.json", releaseID: id, versionID: "1.0.0", raw: manifestJSON(id, "1.0.0", "normal", repo, digA)}})
		mustReject(t, src, fmt.Sprintf("release_id %q", id))
	}
}

func TestFailClosed_CrossMismatch(t *testing.T) {
	// Manifest's release_id/version_id disagree with the index entry.
	src := buildCatalogSource(map[string]string{"recommended": "rel_a"}, 1, "2026-04-18T00:00:00Z",
		[]relSpec{{ref: "a.json", releaseID: "rel_a", versionID: "1.0.0", raw: manifestJSON("rel_OTHER", "1.0.0", "normal", repo, digA)}})
	mustReject(t, src, "release_id cross-mismatch")
}

func TestFailClosed_BadManifestSHA256Shape(t *testing.T) {
	src := validSource().clone()
	// Corrupt the index's manifest_sha256 to a non-64-hex value.
	src.index = []byte(strings.Replace(string(src.index), `"manifest_sha256":"`, `"manifest_sha256":"NOTHEX`, 1))
	mustReject(t, src, "manifest_sha256 not 64 hex")
}

func TestFailClosed_ReadIndexError(t *testing.T) {
	mustReject(t, &memSource{indexErr: errors.New("boom")}, "index read error")
}

func TestFailClosed_BadIndexJSON(t *testing.T) {
	mustReject(t, &memSource{index: []byte("{not json")}, "malformed index json")
}

// ─── dir source: symlink refusal, traversal, bounded reads ───────────────────

func TestDirSource_HappyPath_Fixture(t *testing.T) {
	c := mustLoad(t, NewDirCatalogSource("testdata/release/valid"))
	if len(c.byReleaseID) != 2 {
		t.Fatalf("fixture load: byReleaseID=%d want 2", len(c.byReleaseID))
	}
	if r, err := c.Resolve(ChannelRecommended); err != nil || r.VersionID != "1.10.0" {
		t.Errorf("fixture Resolve(recommended) = %+v err=%v", r, err)
	}
	views := c.List()
	if views[0].VersionID != "1.10.0" {
		t.Errorf("fixture List order wrong: %+v", views)
	}
}

func TestDirSource_Refuses_Traversal(t *testing.T) {
	for _, ref := range []string{"../x.json", "a/b.json", "..", ".", "x\x00.json"} {
		if err := catalogValidateManifestRef(ref); err == nil {
			t.Errorf("manifest_ref %q should be rejected", ref)
		}
	}
	src := NewDirCatalogSource("testdata/release/valid")
	if _, err := src.ReadManifest("../index.json"); err == nil {
		t.Error("dir source must reject a traversal manifest_ref")
	}
}

func TestDirSource_RefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "manifests"), 0o750); err != nil {
		t.Fatal(err)
	}
	realPath := filepath.Join(dir, "real.json")
	if err := os.WriteFile(realPath, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "index.json")
	if err := os.Symlink(realPath, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := NewDirCatalogSource(dir).ReadIndex(); err == nil {
		t.Error("dir source must refuse a symlinked index.json")
	}
}

func TestDirSource_BoundedRead(t *testing.T) {
	dir := t.TempDir()
	big := make([]byte, catalogMaxReadBytes+1)
	for i := range big {
		big[i] = 'x'
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), big, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewDirCatalogSource(dir).ReadIndex(); err == nil {
		t.Error("dir source must reject an oversize index")
	}
}

// Integrity ≠ authenticity: a hash-valid but UNSIGNED catalog loads — proving
// no signature is required (or checked) in this slice.
func TestIntegrityNotAuthenticity_UnsignedCatalogLoads(t *testing.T) {
	mustLoad(t, validSource()) // no signature anywhere; load succeeds on hash alone
}
