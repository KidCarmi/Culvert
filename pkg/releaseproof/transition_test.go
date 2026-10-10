package releaseproof

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

func proofWithFloor(t *testing.T, p Evidence, key ed25519.PrivateKey, floor string) Evidence {
	t.Helper()
	var m manifestFile
	if err := json.Unmarshal(p.Manifest, &m); err != nil {
		t.Fatal(err)
	}
	m.VersionID = "1.0.260"
	m.MinUpgradeFrom = floor
	p.Manifest, _ = json.Marshal(m)
	h := sha256.Sum256(p.Manifest)
	var idx indexFile
	if err := json.Unmarshal(p.Index, &idx); err != nil {
		t.Fatal(err)
	}
	idx.Releases[0].VersionID = m.VersionID
	idx.Releases[0].ManifestSHA256 = hex.EncodeToString(h[:])
	p.Index, _ = json.Marshal(idx)
	signProof(&p, key)
	return p
}

func TestSignedUpgradeFloor(t *testing.T) {
	v, p, ref, key := signedFixture(t)
	p = proofWithFloor(t, p, key, "1.0.250")
	a, err := v.Verify(p, ref, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		version string
		allowed bool
	}{
		{"1.0.249", false}, {"1.0.250", true}, {"1.0.251", true},
		{"1.0.250-rc.1", false}, {"1.0.250+build.8", true}, {"opaque", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			if err := a.CheckUpgradeFrom(Authorization{VersionID: tc.version}); (err == nil) != tc.allowed {
				t.Fatalf("allowed=%v error=%v", tc.allowed, err)
			}
		})
	}
}

func TestMalformedSignedUpgradeFloorRejected(t *testing.T) {
	v, p, ref, key := signedFixture(t)
	for _, floor := range []string{"1", "1.0", "v1.0.250", "01.0.250", "1.0.250-", "1.0.250-01", "1.0.250+", " 1.0.250", "not-a-version"} {
		t.Run(floor, func(t *testing.T) {
			q := proofWithFloor(t, p, key, floor)
			if _, err := v.Verify(q, ref, time.Now()); err == nil {
				t.Fatal("malformed signed floor accepted")
			}
		})
	}
	if err := (Authorization{VersionID: "legacy-target"}).CheckUpgradeFrom(Authorization{VersionID: "legacy-current"}); err != nil {
		t.Fatalf("empty legacy floor constrained opaque versions: %v", err)
	}
}
