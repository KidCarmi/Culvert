package releaseproof

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const testRepo = "ghcr.io/kidcarmi/culvert"

func signedFixture(t *testing.T) (*Verifier, Evidence, string, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(Policy{CatalogRepository: testRepo, ProxyRepository: testRepo, Ed25519Keys: map[string][]byte{"test": pub}})
	if err != nil {
		t.Fatal(err)
	}
	digest := "sha256:" + strings.Repeat("a", 64)
	m, _ := json.Marshal(map[string]any{"schema_version": 1, "release_id": "r1", "version_id": "v1.2.3", "image": map[string]string{"repo": testRepo, "list_digest": digest}})
	h := sha256.Sum256(m)
	idx, _ := json.Marshal(indexFile{SchemaVersion: 1, CatalogVersion: 2, GeneratedAt: time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339), Releases: []indexEntry{{ReleaseID: "r1", VersionID: "v1.2.3", ManifestRef: "releases/r1.json", ManifestSHA256: hex.EncodeToString(h[:])}}})
	p := Evidence{ReleaseID: "r1", Index: idx, Manifest: m}
	signProof(&p, priv)
	return v, p, testRepo + "@" + digest, priv
}

func signProof(p *Evidence, key ed25519.PrivateKey) {
	p.Signature, _ = json.Marshal(map[string]any{"schema_version": 1, "alg": "ed25519", "key_id": "test", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(key, p.Index))})
}

func TestEvidenceBindsExactBytesAndPolicy(t *testing.T) {
	v, p, ref, key := signedFixture(t)
	if _, err := v.Verify(p, ref, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Evidence)
		ref    string
	}{
		{"unsigned", func(p *Evidence) { p.Signature = nil }, ref},
		{"index tampering", func(p *Evidence) { p.Index = append(p.Index, ' ') }, ref},
		{"manifest tampering", func(p *Evidence) { p.Manifest = append(p.Manifest, ' ') }, ref},
		{"unknown release", func(p *Evidence) { p.ReleaseID = "other" }, ref},
		{"foreign repo", func(*Evidence) {}, "attacker/repo@" + strings.Split(ref, "@")[1]},
		{"wrong digest", func(*Evidence) {}, testRepo + "@sha256:" + strings.Repeat("b", 64)},
		{"tag", func(*Evidence) {}, testRepo + ":latest"},
		{"oversize", func(p *Evidence) { p.Manifest = make([]byte, MaxDocumentBytes+1) }, ref},
		{"duplicate signed release", func(p *Evidence) {
			var idx indexFile
			_ = json.Unmarshal(p.Index, &idx)
			idx.Releases = append(idx.Releases, idx.Releases[0])
			p.Index, _ = json.Marshal(idx)
			signProof(p, key)
		}, ref},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := p
			tc.mutate(&q)
			if _, err := v.Verify(q, tc.ref, time.Now()); err == nil {
				t.Fatal("invalid proof accepted")
			}
		})
	}
}

func TestEvidenceFreshnessAndRecoveryAuthenticity(t *testing.T) {
	v, p, ref, key := signedFixture(t)
	var idx indexFile
	_ = json.Unmarshal(p.Index, &idx)
	idx.GeneratedAt = time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339)
	idx.ExpiresAt = time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	p.Index, _ = json.Marshal(idx)
	signProof(&p, key)
	if _, err := v.Verify(p, ref, time.Now()); err == nil {
		t.Fatal("expired new authorization accepted")
	}
	if _, err := v.VerifyAuthenticity(p, ref); err != nil {
		t.Fatal(err)
	}
	idx.GeneratedAt = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	idx.ExpiresAt = time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
	p.Index, _ = json.Marshal(idx)
	signProof(&p, key)
	if _, err := v.Verify(p, ref, time.Now()); err == nil {
		t.Fatal("future authorization accepted")
	}
}

func TestSigstoreIdentityAndArtifact(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	sv, err := verify.NewVerifier(vs, verify.WithTransparencyLog(1), verify.WithIntegratedTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}
	id, err := verify.NewShortCertificateIdentity(OfficialIssuer, "", "", OfficialSANRegex)
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{sigstore: sv, identity: id}
	good := "https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/tags/v1.2.3"
	for _, tc := range []struct {
		name, identity, issuer string
		tamper, wantError      bool
	}{
		{"valid", good, OfficialIssuer, false, false},
		{"wrong workflow", strings.Replace(good, "ci.yml", "other.yml", 1), OfficialIssuer, false, true},
		{"branch", strings.Replace(good, "tags/v1.2.3", "heads/main", 1), OfficialIssuer, false, true},
		{"issuer", good, "https://accounts.google.com", false, true},
		{"tamper", good, OfficialIssuer, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := []byte("signed catalog")
			e, err := vs.Sign(tc.identity, tc.issuer, b)
			if err != nil {
				t.Fatal(err)
			}
			if tc.tamper {
				b = append(b, ' ')
			}
			err = v.verifyEntity(b, e)
			if (err != nil) != tc.wantError {
				t.Fatalf("verification error=%v", err)
			}
		})
	}
}

func TestEmbeddedPolicyMatchesRepository(t *testing.T) {
	for _, name := range []string{"trusted_root.json", "LICENSE"} {
		b, err := os.ReadFile("../../" + name)
		if err != nil {
			t.Fatal(err)
		}
		local, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, local) {
			t.Fatalf("%s drifted", name)
		}
	}
	v, err := NewVerifier(DefaultPolicy(testRepo, testRepo))
	if err != nil {
		t.Fatal(err)
	}
	_, p, ref, _ := signedFixture(t)
	p.SigstoreBundle = []byte(`{}`)
	if _, err = v.Verify(p, ref, time.Now()); err == nil {
		t.Fatal("invalid Sigstore bundle accepted")
	}
}
