package urlcatfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// A SAN that satisfies OfficialSANRegex: a tagged release run of the feed's
// dedicated signing workflow.
const feedMatchingIdentity = "https://github.com/KidCarmi/Culvert/.github/workflows/publish-feeds.yml@refs/tags/feeds-v1.0.0"

// A tagged release of THIS repo but the CATALOG workflow (ci.yml) — must be
// REJECTED by the feed verifier (separate identity).
const catalogWorkflowIdentity = "https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/tags/v1.2.3"

func newFeedSigstore(t *testing.T) (*ca.VirtualSigstore, *Verifier) {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("NewVirtualSigstore: %v", err)
	}
	v, err := NewVerifierFromMaterial(vs, OfficialIdentity())
	if err != nil {
		t.Fatalf("NewVerifierFromMaterial: %v", err)
	}
	return vs, v
}

func genManifestBytes(t *testing.T) []byte {
	t.Helper()
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	r, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 42, GeneratedAt: gen, ExpiresAt: gen.Add(14 * 24 * time.Hour)})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return r.ManifestBytes
}

// ─── crypto core (verify-before-parse) ───────────────────────────────────────

func TestVerify_AcceptsPinnedIdentity(t *testing.T) {
	vs, v := newFeedSigstore(t)
	payload := genManifestBytes(t)
	entity, err := vs.Sign(feedMatchingIdentity, OfficialIssuer, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	m, err := v.verifyManifest(payload, entity)
	if err != nil {
		t.Fatalf("verifyManifest: %v", err)
	}
	if m == nil || m.Feed != FeedID || m.FeedVersion != 42 {
		t.Fatalf("unexpected manifest: %+v", m)
	}
}

func TestVerify_RejectsTamperedPayload_NoObject(t *testing.T) {
	vs, v := newFeedSigstore(t)
	payload := genManifestBytes(t)
	entity, err := vs.Sign(feedMatchingIdentity, OfficialIssuer, payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	tampered := append(append([]byte(nil), payload...), ' ')
	m, err := v.verifyManifest(tampered, entity)
	if !errors.Is(err, ErrVerify) {
		t.Fatalf("err = %v; want ErrVerify", err)
	}
	if m != nil {
		t.Fatalf("verify-before-parse violated: manifest returned on failed verify")
	}
}

func TestVerify_RejectsWrongSAN(t *testing.T) {
	vs, v := newFeedSigstore(t)
	payload := genManifestBytes(t)
	entity, _ := vs.Sign("https://github.com/attacker/evil/.github/workflows/publish-feeds.yml@refs/tags/feeds-v9.9.9", OfficialIssuer, payload)
	if _, err := v.verifyManifest(payload, entity); !errors.Is(err, ErrVerify) {
		t.Fatalf("wrong SAN: err = %v; want ErrVerify", err)
	}
}

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	vs, v := newFeedSigstore(t)
	payload := genManifestBytes(t)
	entity, _ := vs.Sign(feedMatchingIdentity, "https://accounts.google.com", payload)
	if _, err := v.verifyManifest(payload, entity); !errors.Is(err, ErrVerify) {
		t.Fatalf("wrong issuer: err = %v; want ErrVerify", err)
	}
}

func TestVerify_RejectsCatalogWorkflow(t *testing.T) {
	vs, v := newFeedSigstore(t)
	payload := genManifestBytes(t)
	entity, _ := vs.Sign(catalogWorkflowIdentity, OfficialIssuer, payload)
	if _, err := v.verifyManifest(payload, entity); !errors.Is(err, ErrVerify) {
		t.Fatalf("catalog workflow identity: err = %v; want ErrVerify", err)
	}
}

// A validly-SIGNED payload whose feed id is wrong verifies cryptographically but
// is rejected at parse (cross-feed binding). The signature is real, so this
// proves the feed-id check, not the crypto.
func TestVerify_RejectsCrossFeedPayload(t *testing.T) {
	vs, v := newFeedSigstore(t)
	payload := []byte(`{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/other","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z","artifact_path":"saas-1.json","artifact_sha256":"` + strings.Repeat("a", 64) + `","artifact_size":10,"artifact_sig_path":"saas-1.json.sigstore","category_count":1,"host_count":1}`)
	entity, _ := vs.Sign(feedMatchingIdentity, OfficialIssuer, payload)
	m, err := v.verifyManifest(payload, entity)
	if !errors.Is(err, ErrPayload) {
		t.Fatalf("cross-feed: err = %v; want ErrPayload", err)
	}
	if m != nil {
		t.Fatalf("returned manifest for wrong feed")
	}
}

// ─── envelope wrapper (unwrap → verify) ──────────────────────────────────────

func TestVerifyEnvelope_RejectsMalformed(t *testing.T) {
	_, v := newFeedSigstore(t)
	cases := map[string][]byte{
		"not json":      []byte("nope"),
		"unknown field": []byte(`{"payload_b64":"AA==","bundle":{},"x":1}`),
		"bad base64":    []byte(`{"payload_b64":"!!!!","bundle":{"a":1}}`),
		"empty payload": []byte(`{"payload_b64":"","bundle":{"a":1}}`),
		"empty bundle":  []byte(`{"payload_b64":"AA==","bundle":null}`),
		"bad bundle":    []byte(`{"payload_b64":"AA==","bundle":{"not":"a-real-bundle"}}`),
	}
	for name, env := range cases {
		if _, err := v.VerifyEnvelope(env); err == nil {
			t.Errorf("%s: expected rejection, got nil", name)
		}
	}
}

func TestVerifyEnvelope_Oversize(t *testing.T) {
	_, v := newFeedSigstore(t)
	big := make([]byte, maxEnvelopeBytes+1)
	if _, err := v.VerifyEnvelope(big); !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize: err = %v; want ErrOversize", err)
	}
}

// ─── verifier construction config errors ─────────────────────────────────────

func TestNewVerifier_ConfigErrors(t *testing.T) {
	if _, err := NewVerifierFromJSON(nil, OfficialIdentity()); !errors.Is(err, ErrConfig) {
		t.Errorf("empty root: err = %v; want ErrConfig", err)
	}
	if _, err := NewVerifierFromJSON([]byte("   "), OfficialIdentity()); !errors.Is(err, ErrConfig) {
		t.Errorf("blank root: err = %v; want ErrConfig", err)
	}
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatalf("vs: %v", err)
	}
	if _, err := NewVerifierFromMaterial(vs, Identity{Issuer: "", SANRegex: "x"}); !errors.Is(err, ErrConfig) {
		t.Errorf("empty issuer: err = %v; want ErrConfig", err)
	}
	if _, err := NewVerifierFromMaterial(vs, Identity{Issuer: "x", SANRegex: ""}); !errors.Is(err, ErrConfig) {
		t.Errorf("empty san: err = %v; want ErrConfig", err)
	}
}

// ─── artifact verification + manifest binding ────────────────────────────────

func signedArtifact(t *testing.T) (artifactBytes []byte, manifest *ManifestPayload, entity *ca.TestEntity, vs *ca.VirtualSigstore, v *Verifier) {
	t.Helper()
	vs, v = newFeedSigstore(t)
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	r, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 42, GeneratedAt: gen, ExpiresAt: gen.Add(14 * 24 * time.Hour)})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	e, err := vs.Sign(feedMatchingIdentity, OfficialIssuer, r.ArtifactBytes)
	if err != nil {
		t.Fatalf("Sign artifact: %v", err)
	}
	m := r.Manifest
	return r.ArtifactBytes, &m, e, vs, v
}

func TestVerifyArtifact_Accepts(t *testing.T) {
	art, man, entity, _, v := signedArtifact(t)
	a, err := v.verifyArtifactWithEntity(art, entity, man)
	if err != nil {
		t.Fatalf("verifyArtifactWithEntity: %v", err)
	}
	if a == nil || a.FeedVersion != man.FeedVersion {
		t.Fatalf("unexpected artifact: %+v", a)
	}
}

func TestVerifyArtifact_BindingMismatches(t *testing.T) {
	art, man, entity, _, v := signedArtifact(t)

	t.Run("size", func(t *testing.T) {
		bad := *man
		bad.ArtifactSize++
		if _, err := v.verifyArtifactWithEntity(art, entity, &bad); !errors.Is(err, ErrBinding) {
			t.Fatalf("err = %v; want ErrBinding", err)
		}
	})
	t.Run("digest", func(t *testing.T) {
		bad := *man
		bad.ArtifactSHA256 = strings.Repeat("b", 64)
		if _, err := v.verifyArtifactWithEntity(art, entity, &bad); !errors.Is(err, ErrBinding) {
			t.Fatalf("err = %v; want ErrBinding", err)
		}
	})
	t.Run("version", func(t *testing.T) {
		bad := *man
		bad.FeedVersion = 999
		if _, err := v.verifyArtifactWithEntity(art, entity, &bad); !errors.Is(err, ErrBinding) {
			t.Fatalf("err = %v; want ErrBinding", err)
		}
	})
	t.Run("counts", func(t *testing.T) {
		bad := *man
		bad.HostCount = 999
		if _, err := v.verifyArtifactWithEntity(art, entity, &bad); !errors.Is(err, ErrBinding) {
			t.Fatalf("err = %v; want ErrBinding", err)
		}
	})
	t.Run("nil-manifest", func(t *testing.T) {
		if _, err := v.verifyArtifactWithEntity(art, entity, nil); !errors.Is(err, ErrBinding) {
			t.Fatalf("err = %v; want ErrBinding", err)
		}
	})
}

func TestVerifyArtifact_TamperedSignatureRejected(t *testing.T) {
	art, man, entity, _, v := signedArtifact(t)
	// Corrupt the artifact so the signature (over the original) no longer matches,
	// but keep the manifest binding consistent with the corrupted bytes so we
	// reach the signature check.
	tampered := append(append([]byte(nil), art...), ' ')
	bad := *man
	bad.ArtifactSize = int64(len(tampered))
	// Recompute the digest so size+digest binding passes and the SIGNATURE is the
	// gate that fails.
	sum := sha256Hex(tampered)
	bad.ArtifactSHA256 = sum
	if _, err := v.verifyArtifactWithEntity(tampered, entity, &bad); !errors.Is(err, ErrVerify) {
		t.Fatalf("err = %v; want ErrVerify", err)
	}
}

// ─── independent client-side integrity rejection (parse layer) ───────────────

func TestParseArtifact_RejectsIntegrityViolations(t *testing.T) {
	// Multi-category.
	multi := []byte(`{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","categories":[{"name":"A","hosts":["example.com"]},{"name":"B","hosts":["example.com"]}]}`)
	if _, _, _, err := parseArtifactPayload(multi); !errors.Is(err, ErrPayload) {
		t.Errorf("multi-category: err = %v; want ErrPayload", err)
	}
	// Ancestor/descendant across categories.
	suffix := []byte(`{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","categories":[{"name":"A","hosts":["example.com"]},{"name":"B","hosts":["sub.example.com"]}]}`)
	if _, _, _, err := parseArtifactPayload(suffix); !errors.Is(err, ErrPayload) {
		t.Errorf("suffix conflict: err = %v; want ErrPayload", err)
	}
	// Non-canonical host (uppercase) — the producer would have lowercased it.
	noncanon := []byte(`{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","categories":[{"name":"A","hosts":["Example.com"]}]}`)
	if _, _, _, err := parseArtifactPayload(noncanon); !errors.Is(err, ErrPayload) {
		t.Errorf("non-canonical: err = %v; want ErrPayload", err)
	}
	// Wrong protocol.
	wrongProto := []byte(`{"schema_version":1,"protocol":"legacy_raw_json_v0","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","categories":[{"name":"A","hosts":["example.com"]}]}`)
	if _, _, _, err := parseArtifactPayload(wrongProto); !errors.Is(err, ErrPayload) {
		t.Errorf("wrong protocol: err = %v; want ErrPayload", err)
	}
	// Unknown field.
	unknown := []byte(`{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","categories":[{"name":"A","hosts":["example.com"]}],"evil":true}`)
	if _, _, _, err := parseArtifactPayload(unknown); !errors.Is(err, ErrPayload) {
		t.Errorf("unknown field: err = %v; want ErrPayload", err)
	}
}

func TestParseManifest_RejectsBadStructure(t *testing.T) {
	good := genManifestBytes(t)
	if _, err := parseManifestPayload(good); err != nil {
		t.Fatalf("good manifest rejected: %v", err)
	}
	bad := map[string]string{
		"bad sha":       `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z","artifact_path":"a.json","artifact_sha256":"xyz","artifact_size":1,"artifact_sig_path":"a.json.sigstore","category_count":1,"host_count":1}`,
		"traversal":     `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z","artifact_path":"../a.json","artifact_sha256":"` + strings.Repeat("a", 64) + `","artifact_size":1,"artifact_sig_path":"a.json.sigstore","category_count":1,"host_count":1}`,
		"unknown field": `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z","artifact_path":"a.json","artifact_sha256":"` + strings.Repeat("a", 64) + `","artifact_size":1,"artifact_sig_path":"a.json.sigstore","category_count":1,"host_count":1,"evil":1}`,
		"expiry order":  `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-08-14T00:00:00Z","expires_at":"2026-07-31T00:00:00Z","artifact_path":"a.json","artifact_sha256":"` + strings.Repeat("a", 64) + `","artifact_size":1,"artifact_sig_path":"a.json.sigstore","category_count":1,"host_count":1}`,
	}
	for name, b := range bad {
		if _, err := parseManifestPayload([]byte(b)); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: err = %v; want ErrPayload", name, err)
		}
	}
}

func TestSafeRelKey(t *testing.T) {
	good := []string{"saas-00000042-20260731.json", "a.json.sigstore", "x-1_2.json"}
	for _, k := range good {
		if !safeRelKey(k) {
			t.Errorf("safeRelKey(%q) = false; want true", k)
		}
	}
	bad := []string{"", "../a", "a/b", "a\\b", "..", "a b", "évil.json"}
	for _, k := range bad {
		if safeRelKey(k) {
			t.Errorf("safeRelKey(%q) = true; want false", k)
		}
	}
}

// sha256Hex is a tiny test helper mirroring the production digest.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
