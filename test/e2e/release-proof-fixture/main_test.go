package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/releaseproof"
)

func TestFixtureVerifiesActualRefsAndAliases(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	repo := "127.0.0.1:5000/culvert"
	prior, current := repo+"@sha256:"+strings.Repeat("a", 64), repo+"@sha256:"+strings.Repeat("b", 64)
	labels, err := parseRefs([]string{"prior=" + prior, "current=" + current, "alias=" + prior})
	if err != nil {
		t.Fatal(err)
	}
	files, err := fixture(labels, now)
	if err != nil {
		t.Fatal(err)
	}
	var keyring map[string][]byte
	if err := json.Unmarshal(files["keyring.json"], &keyring); err != nil {
		t.Fatal(err)
	}
	verifier, err := releaseproof.NewVerifier(releaseproof.Policy{CatalogRepository: repo, ProxyRepository: repo, Ed25519Keys: keyring})
	if err != nil {
		t.Fatal(err)
	}
	var proofs map[string]releaseproof.Evidence
	if err := json.Unmarshal(files["proofs.json"], &proofs); err != nil {
		t.Fatal(err)
	}
	if len(proofs) != 2 || !bytes.Equal(files["proof-prior.json"], files["proof-alias.json"]) {
		t.Fatal("duplicate reference aliases must share evidence")
	}
	for ref, proof := range proofs {
		if _, err := verifier.Verify(proof, ref, now); err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.Verify(proof, ref, now.Add(25*time.Hour)); err == nil {
			t.Fatal("expired fixture accepted")
		}
		proof.Index = append([]byte(nil), proof.Index...)
		proof.Index[0] ^= 1
		if _, err := verifier.Verify(proof, ref, now); err == nil {
			t.Fatal("tampered index accepted")
		}
	}
	// A fresh generator run must not reuse the signing identity.
	again, err := fixture(labels, now)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(files["keyring.json"], again["keyring.json"]) {
		t.Fatal("key reused")
	}
	for _, key := range keyring {
		if len(key) != 32 {
			t.Fatal("keyring is not public-key-only")
		}
	}
	if len(files) != 5 {
		t.Fatal("unexpected files (signing key must never be persisted)")
	}
	for _, raw := range files {
		if bytes.Contains(raw, []byte("PRIVATE KEY")) {
			t.Fatal("private-key output")
		}
	}
}

func TestFixtureRejectsUnpinnedAmbiguousAndUnsafeInput(t *testing.T) {
	ref := "127.0.0.1:5000/culvert@sha256:" + strings.Repeat("a", 64)
	cases := [][]string{nil, {"../escape=" + ref}, {"current=" + ref, "current=" + ref}, {"current=example.com/proxy:latest"},
		{"current=" + ref, "prior=other/repo@sha256:" + strings.Repeat("a", 64)}, {"current=repo:tag@sha256:" + strings.Repeat("a", 64)},
		{"current=repo@sha256:" + strings.Repeat("A", 64)}}
	for _, args := range cases {
		if _, err := parseRefs(args); err == nil {
			t.Fatal("invalid fixture refs accepted")
		}
	}
}

func TestFixtureDoesNotOverwriteExistingTrust(t *testing.T) {
	output := filepath.Join(t.TempDir(), "fixture")
	files := map[string][]byte{"keyring.json": []byte(base64.StdEncoding.EncodeToString(make([]byte, 32)))}
	if err := writeFixture(output, files); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(output, "keyring.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := writeFixture(output, map[string][]byte{"keyring.json": []byte("different")}); err == nil {
		t.Fatal("existing trust replaced")
	}
	after, err := os.ReadFile(filepath.Join(output, "keyring.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed generation changed trust")
	}
}
