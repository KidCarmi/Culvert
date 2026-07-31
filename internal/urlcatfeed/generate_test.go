package urlcatfeed

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func fixedTimes() (gen, exp time.Time) {
	gen = time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	exp = gen.Add(14 * 24 * time.Hour)
	return
}

func sampleDataset() SourceDataset {
	return SourceDataset{Categories: []SourceCategory{
		{Name: "AI", Hosts: []string{"anthropic.com", "claude.ai", "openai.com"}},
		{Name: "Messaging", Hosts: []string{"slack.com", "discord.com"}},
		{Name: "Dev Tools", Hosts: []string{"github.com", "gitlab.com"}},
	}}
}

func TestGenerate_Deterministic_RepeatedAndShuffled(t *testing.T) {
	gen, exp := fixedTimes()
	base := GenerateInput{Source: sampleDataset(), FeedVersion: 42, GeneratedAt: gen, ExpiresAt: exp}

	// Repeated execution (map iteration order is randomized per range) must be
	// byte-identical.
	var art, man []byte
	for i := 0; i < 6; i++ {
		r, err := Generate(base)
		if err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if i == 0 {
			art, man = r.ArtifactBytes, r.ManifestBytes
			continue
		}
		if !bytes.Equal(r.ArtifactBytes, art) {
			t.Fatalf("artifact bytes not deterministic across runs")
		}
		if !bytes.Equal(r.ManifestBytes, man) {
			t.Fatalf("manifest bytes not deterministic across runs")
		}
	}

	// Shuffled input ordering (categories + hosts reversed) must yield identical
	// output.
	shuf := SourceDataset{Categories: []SourceCategory{
		{Name: "Dev Tools", Hosts: []string{"gitlab.com", "github.com"}},
		{Name: "Messaging", Hosts: []string{"discord.com", "slack.com"}},
		{Name: "AI", Hosts: []string{"openai.com", "claude.ai", "anthropic.com"}},
	}}
	r2, err := Generate(GenerateInput{Source: shuf, FeedVersion: 42, GeneratedAt: gen, ExpiresAt: exp})
	if err != nil {
		t.Fatalf("Generate(shuffled): %v", err)
	}
	if !bytes.Equal(r2.ArtifactBytes, art) {
		t.Fatalf("artifact bytes differ under shuffled input")
	}
	if !bytes.Equal(r2.ManifestBytes, man) {
		t.Fatalf("manifest bytes differ under shuffled input")
	}
}

func TestGenerate_CountsAndDigestBinding(t *testing.T) {
	gen, exp := fixedTimes()
	r, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 42, GeneratedAt: gen, ExpiresAt: exp})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if r.HostCount != 7 {
		t.Errorf("HostCount = %d; want 7", r.HostCount)
	}
	if r.CategoryCount != 3 {
		t.Errorf("CategoryCount = %d; want 3", r.CategoryCount)
	}
	sum := sha256.Sum256(r.ArtifactBytes)
	if hex.EncodeToString(sum[:]) != r.ArtifactSHA256 {
		t.Errorf("ArtifactSHA256 not bound to ArtifactBytes")
	}
	if r.Manifest.ArtifactSHA256 != r.ArtifactSHA256 {
		t.Errorf("manifest digest != artifact digest")
	}
	if r.Manifest.ArtifactSize != int64(len(r.ArtifactBytes)) {
		t.Errorf("manifest ArtifactSize = %d; want %d", r.Manifest.ArtifactSize, len(r.ArtifactBytes))
	}
	if r.Manifest.HostCount != 7 || r.Manifest.CategoryCount != 3 {
		t.Errorf("manifest counts = (%d,%d); want (7,3)", r.Manifest.HostCount, r.Manifest.CategoryCount)
	}
	if r.ArtifactPath != "saas-00000042-20260731.json" {
		t.Errorf("ArtifactPath = %q; want saas-00000042-20260731.json", r.ArtifactPath)
	}
	if r.ArtifactSigPath != r.ArtifactPath+".sigstore" {
		t.Errorf("ArtifactSigPath = %q; want %q", r.ArtifactSigPath, r.ArtifactPath+".sigstore")
	}
	// Manifest binds constants.
	if r.Manifest.Protocol != Protocol || r.Manifest.Feed != FeedID || r.Manifest.SchemaVersion != SchemaVersion {
		t.Errorf("manifest constants not bound: %+v", r.Manifest)
	}
}

func TestGenerate_SortedOutput(t *testing.T) {
	gen, exp := fixedTimes()
	r, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: gen, ExpiresAt: exp})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var art ArtifactPayload
	if err := json.Unmarshal(r.ArtifactBytes, &art); err != nil {
		t.Fatalf("unmarshal artifact: %v", err)
	}
	// Categories sorted by name; hosts sorted within.
	for i := 1; i < len(art.Categories); i++ {
		if art.Categories[i-1].Name > art.Categories[i].Name {
			t.Errorf("categories not sorted: %q > %q", art.Categories[i-1].Name, art.Categories[i].Name)
		}
	}
	for _, c := range art.Categories {
		for i := 1; i < len(c.Hosts); i++ {
			if c.Hosts[i-1] > c.Hosts[i] {
				t.Errorf("hosts not sorted in %q", c.Name)
			}
		}
	}
}

func TestGenerate_VersionValidation(t *testing.T) {
	gen, exp := fixedTimes()
	ds := sampleDataset()
	if _, err := Generate(GenerateInput{Source: ds, FeedVersion: 0, GeneratedAt: gen, ExpiresAt: exp}); !errors.Is(err, ErrVersion) {
		t.Errorf("version 0: err = %v; want ErrVersion", err)
	}
	if _, err := Generate(GenerateInput{Source: ds, FeedVersion: 5, PrevFeedVersion: 5, GeneratedAt: gen, ExpiresAt: exp}); !errors.Is(err, ErrVersion) {
		t.Errorf("non-increasing version: err = %v; want ErrVersion", err)
	}
	if _, err := Generate(GenerateInput{Source: ds, FeedVersion: 4, PrevFeedVersion: 5, GeneratedAt: gen, ExpiresAt: exp}); !errors.Is(err, ErrVersion) {
		t.Errorf("decreasing version: err = %v; want ErrVersion", err)
	}
}

func TestGenerate_ExpiryValidation(t *testing.T) {
	gen, _ := fixedTimes()
	if _, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: gen, ExpiresAt: gen}); !errors.Is(err, ErrExpiry) {
		t.Errorf("equal expiry: err = %v; want ErrExpiry", err)
	}
	if _, err := Generate(GenerateInput{Source: sampleDataset(), FeedVersion: 1, GeneratedAt: gen, ExpiresAt: gen.Add(-time.Hour)}); !errors.Is(err, ErrExpiry) {
		t.Errorf("past expiry: err = %v; want ErrExpiry", err)
	}
}

func TestGenerate_IntegrityRejectionPropagates(t *testing.T) {
	gen, exp := fixedTimes()
	// Multi-category.
	_, err := Generate(GenerateInput{Source: SourceDataset{Categories: []SourceCategory{
		{Name: "A", Hosts: []string{"example.com"}},
		{Name: "B", Hosts: []string{"example.com"}},
	}}, FeedVersion: 1, GeneratedAt: gen, ExpiresAt: exp})
	if !errors.Is(err, ErrMultiCategory) {
		t.Errorf("multi-category: err = %v; want ErrMultiCategory", err)
	}
	// Ancestor/descendant.
	_, err = Generate(GenerateInput{Source: SourceDataset{Categories: []SourceCategory{
		{Name: "A", Hosts: []string{"example.com"}},
		{Name: "B", Hosts: []string{"sub.example.com"}},
	}}, FeedVersion: 1, GeneratedAt: gen, ExpiresAt: exp})
	if !errors.Is(err, ErrSuffixConflict) {
		t.Errorf("suffix conflict: err = %v; want ErrSuffixConflict", err)
	}
	// Bad host.
	_, err = Generate(GenerateInput{Source: SourceDataset{Categories: []SourceCategory{
		{Name: "A", Hosts: []string{"1.2.3.4"}},
	}}, FeedVersion: 1, GeneratedAt: gen, ExpiresAt: exp})
	if !errors.Is(err, ErrIPLiteral) {
		t.Errorf("ip literal: err = %v; want ErrIPLiteral", err)
	}
}

func TestGenerate_EmptyDatasetRejected(t *testing.T) {
	gen, exp := fixedTimes()
	if _, err := Generate(GenerateInput{Source: SourceDataset{}, FeedVersion: 1, GeneratedAt: gen, ExpiresAt: exp}); !errors.Is(err, ErrNoCats) {
		t.Errorf("empty dataset: err = %v; want ErrNoCats", err)
	}
}

func TestAssembleEnvelope(t *testing.T) {
	man := []byte(`{"schema_version":1}`)
	bundle := []byte(`{"mediaType":"x"}`)
	env, err := AssembleEnvelope(man, bundle)
	if err != nil {
		t.Fatalf("AssembleEnvelope: %v", err)
	}
	var e Envelope
	if err := json.Unmarshal(env, &e); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	if e.PayloadB64 == "" || len(e.Bundle) == 0 {
		t.Fatalf("envelope missing parts")
	}
	if _, err := AssembleEnvelope(nil, bundle); !errors.Is(err, ErrEnvelope) {
		t.Errorf("empty payload: err = %v; want ErrEnvelope", err)
	}
	if _, err := AssembleEnvelope(man, []byte("not json")); !errors.Is(err, ErrEnvelope) {
		t.Errorf("bad bundle: err = %v; want ErrEnvelope", err)
	}
}
