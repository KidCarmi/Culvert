package urlcatfeed

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

// ─── Finding 6: pinned-SAN identity matrix ───────────────────────────────────

func TestIdentity_SANMatrix(t *testing.T) {
	vs, v := newFeedSigstore(t)
	payload := genManifestBytes(t)
	const wf = "https://github.com/KidCarmi/Culvert/.github/workflows/publish-feeds.yml"

	accept := []string{
		wf + "@refs/tags/feeds-v1.2.3",
		wf + "@refs/tags/feeds-v0.0.1",
		wf + "@refs/tags/feeds-v10.20.30",
	}
	reject := map[string]string{
		"bare feeds-v":      wf + "@refs/tags/feeds-v",
		"garbage tag":       wf + "@refs/tags/feeds-vgarbage",
		"incomplete semver": wf + "@refs/tags/feeds-v1.2",
		"branch ref":        wf + "@refs/heads/main",
		"pull ref":          wf + "@refs/pull/1/merge",
		"wrong workflow":    "https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/tags/feeds-v1.2.3",
		"wrong repo":        "https://github.com/attacker/evil/.github/workflows/publish-feeds.yml@refs/tags/feeds-v1.2.3",
	}

	for _, san := range accept {
		entity, err := vs.Sign(san, OfficialIssuer, payload)
		if err != nil {
			t.Fatalf("Sign(%s): %v", san, err)
		}
		if _, err := v.verifyManifest(payload, entity); err != nil {
			t.Errorf("SAN %q should be ACCEPTED; got %v", san, err)
		}
	}
	for name, san := range reject {
		entity, err := vs.Sign(san, OfficialIssuer, payload)
		if err != nil {
			t.Fatalf("Sign(%s): %v", san, err)
		}
		if _, err := v.verifyManifest(payload, entity); !errors.Is(err, ErrVerify) {
			t.Errorf("%s (%q) should be REJECTED; got %v", name, san, err)
		}
	}
}

// ─── Finding 2: timestamp canonicalization ───────────────────────────────────

func TestGenerate_ZeroTimestampsRejected(t *testing.T) {
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	if _, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: time.Time{}, ExpiresAt: gen}); !errors.Is(err, ErrZeroTime) {
		t.Errorf("zero generated: err = %v; want ErrZeroTime", err)
	}
	if _, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: gen, ExpiresAt: time.Time{}}); !errors.Is(err, ErrZeroTime) {
		t.Errorf("zero expires: err = %v; want ErrZeroTime", err)
	}
}

// Sub-second-only gap that would collapse to a single RFC3339 second must be
// rejected by Generate rather than emitting a self-invalid manifest.
func TestGenerate_NanosecondCollapseRejected(t *testing.T) {
	gen := time.Date(2026, 7, 31, 0, 0, 0, int(100*time.Millisecond), time.UTC)
	exp := time.Date(2026, 7, 31, 0, 0, 0, int(900*time.Millisecond), time.UTC)
	if !exp.After(gen) {
		t.Fatal("test setup: raw exp should be after raw gen")
	}
	if _, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: gen, ExpiresAt: exp}); !errors.Is(err, ErrExpiry) {
		t.Errorf("nanosecond collapse: err = %v; want ErrExpiry", err)
	}
}

func TestGenerate_TimezoneEquivalentIdentical(t *testing.T) {
	genUTC := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	expUTC := genUTC.Add(14 * 24 * time.Hour)
	loc := time.FixedZone("UTC+2", 2*3600)
	a, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: genUTC, ExpiresAt: expUTC})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: genUTC.In(loc), ExpiresAt: expUTC.In(loc)})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a.ManifestBytes, b.ManifestBytes) || !bytes.Equal(a.ArtifactBytes, b.ArtifactBytes) {
		t.Error("equivalent instants in different zones produced different bytes")
	}
}

// ─── Finding 3: producer + structural max-validity ceiling ───────────────────

func genWithWindow(t *testing.T, d time.Duration) *GenerateResult {
	t.Helper()
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	r, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: gen, ExpiresAt: gen.Add(d)})
	if err != nil {
		t.Fatalf("Generate(window=%s): %v", d, err)
	}
	return r
}

func TestGenerate_MaxValidity(t *testing.T) {
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	_ = genWithWindow(t, MaxValidity)     // exactly 30d accepted
	_ = genWithWindow(t, 14*24*time.Hour) // 14d accepted
	if _, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: gen, ExpiresAt: gen.Add(MaxValidity + time.Second)}); !errors.Is(err, ErrMaxValidity) {
		t.Errorf(">30d: err = %v; want ErrMaxValidity", err)
	}
}

func TestManifest_RejectsWindowOver30d(t *testing.T) {
	r := genWithWindow(t, MaxValidity) // 30d, expires 2026-08-30
	// Hand-widen the signed window to 40d (2026-09-09) — structurally rejected.
	over := strings.Replace(string(r.ManifestBytes), `"expires_at":"2026-08-30T00:00:00Z"`, `"expires_at":"2026-09-09T00:00:00Z"`, 1)
	if over == string(r.ManifestBytes) {
		t.Fatal("test setup: expires_at not replaced")
	}
	if _, err := parseManifestPayload([]byte(over)); !errors.Is(err, ErrPayload) {
		t.Errorf("40d window: err = %v; want ErrPayload", err)
	}
}

// ─── Finding 1/2: non-canonical timestamp in a signed manifest ───────────────

func TestManifest_RejectsNonCanonicalTimestamp(t *testing.T) {
	nc := strings.Replace(goldenManifest, `"generated_at":"2026-07-31T00:00:00Z"`, `"generated_at":"2026-07-31T00:00:00+00:00"`, 1)
	if _, err := parseManifestPayload([]byte(nc)); !errors.Is(err, ErrPayload) {
		t.Errorf("non-canonical offset: err = %v; want ErrPayload", err)
	}
}

// ─── Finding 5: manifest cross-field + artifact binding ──────────────────────

func TestManifest_RejectsSigPathMismatch(t *testing.T) {
	bad := strings.Replace(goldenManifest,
		`"artifact_sig_path":"saas-00000007-20260731.json.sigstore"`,
		`"artifact_sig_path":"saas-00000007-20260731.json.sig"`, 1)
	if _, err := parseManifestPayload([]byte(bad)); !errors.Is(err, ErrPayload) {
		t.Errorf("sig-path mismatch: err = %v; want ErrPayload", err)
	}
}

func TestManifest_RejectsArtifactPathShape(t *testing.T) {
	// Wrong date in artifact_path (and matching sig_path) vs generated_at.
	bad := goldenManifest
	bad = strings.Replace(bad, `"artifact_path":"saas-00000007-20260731.json"`, `"artifact_path":"saas-00000007-20260101.json"`, 1)
	bad = strings.Replace(bad, `"artifact_sig_path":"saas-00000007-20260731.json.sigstore"`, `"artifact_sig_path":"saas-00000007-20260101.json.sigstore"`, 1)
	if _, err := parseManifestPayload([]byte(bad)); !errors.Is(err, ErrPayload) {
		t.Errorf("artifact-path shape: err = %v; want ErrPayload", err)
	}
}

func TestVerifyArtifact_GeneratedAtBinding(t *testing.T) {
	art, man, entity, _, v := signedArtifact(t)
	bad := *man
	bad.GeneratedAt = "2026-01-01T00:00:00Z" // canonical but different instant
	if _, err := v.verifyArtifactWithEntity(art, entity, &bad); !errors.Is(err, ErrBinding) {
		t.Fatalf("generated_at mismatch: err = %v; want ErrBinding", err)
	}
}

// ─── Additional hardening: AssembleEnvelope validates payload + bundle ────────

func TestAssembleEnvelope_RejectsNonCanonicalManifest(t *testing.T) {
	// A non-manifest payload must not be wrappable.
	if _, err := AssembleEnvelope([]byte(`{"not":"a manifest"}`), []byte(`{"a":1}`)); !errors.Is(err, ErrEnvelope) {
		t.Errorf("bad payload: err = %v; want ErrEnvelope", err)
	}
	// A valid manifest but a non-bundle blob must be rejected.
	if _, err := AssembleEnvelope([]byte(goldenManifest), []byte(`{"not":"a real bundle"}`)); !errors.Is(err, ErrEnvelope) {
		t.Errorf("bad bundle: err = %v; want ErrEnvelope", err)
	}
}
