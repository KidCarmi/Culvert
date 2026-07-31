package urlcatfeed

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// Golden canonical bytes (Finding 1): pinned so the canonical format cannot drift
// silently. Feed version 7, generated_at 2026-07-31, expires +14d.
const (
	goldenArtifact = `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":7,"generated_at":"2026-07-31T00:00:00Z","categories":[{"name":"AI","hosts":["anthropic.com","claude.ai"]},{"name":"Dev Tools","hosts":["github.com"]}]}`
	goldenManifest = `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":7,"generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z","artifact_path":"saas-00000007-20260731.json","artifact_sha256":"0c0b97221b5f9fee7308c8187af223821324ec27fa6d1a518fddd8daaabe8a02","artifact_size":247,"artifact_sig_path":"saas-00000007-20260731.json.sigstore","category_count":2,"host_count":3}`
)

func goldenInput() GenerateInput {
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	return GenerateInput{Source: SourceDataset{Categories: []SourceCategory{
		{Name: "AI", Hosts: []string{"anthropic.com", "claude.ai"}},
		{Name: "Dev Tools", Hosts: []string{"github.com"}},
	}}, FeedVersion: 7, GeneratedAt: gen, ExpiresAt: gen.Add(14 * 24 * time.Hour)}
}

func TestCanonical_Golden(t *testing.T) {
	r, err := Generate(goldenInput())
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if string(r.ArtifactBytes) != goldenArtifact {
		t.Errorf("artifact golden drift:\n got %s\nwant %s", r.ArtifactBytes, goldenArtifact)
	}
	if string(r.ManifestBytes) != goldenManifest {
		t.Errorf("manifest golden drift:\n got %s\nwant %s", r.ManifestBytes, goldenManifest)
	}
	// Golden round-trips through the verifier's parsers.
	if _, err := parseManifestPayload([]byte(goldenManifest)); err != nil {
		t.Errorf("golden manifest rejected: %v", err)
	}
	if _, _, _, err := parseArtifactPayload([]byte(goldenArtifact)); err != nil {
		t.Errorf("golden artifact rejected: %v", err)
	}
}

// The canonical encoder disables HTML escaping: a category name with '&' is
// emitted literally, and an escaped variant is rejected as non-canonical.
func TestCanonical_EscapeFree(t *testing.T) {
	gen := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	r, err := Generate(GenerateInput{Source: SourceDataset{Categories: []SourceCategory{
		{Name: "Automation & Integration", Hosts: []string{"zapier.com"}},
	}}, FeedVersion: 1, GeneratedAt: gen, ExpiresAt: gen.Add(24 * time.Hour)})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(string(r.ArtifactBytes), "Automation & Integration") {
		t.Errorf("expected literal '&' in canonical bytes; got %s", r.ArtifactBytes)
	}
	jsonUnicodeAmp := "\\u0026" // backslash-u-0026 as it would appear in JSON bytes
	if strings.Contains(string(r.ArtifactBytes), jsonUnicodeAmp) {
		t.Errorf("canonical bytes must not HTML-escape '&' as %s: %s", jsonUnicodeAmp, r.ArtifactBytes)
	}
	// An escaped-'&' variant decodes to the same struct but is NOT canonical.
	escaped := strings.Replace(string(r.ArtifactBytes), "&", jsonUnicodeAmp, 1)
	if _, _, _, err := parseArtifactPayload([]byte(escaped)); !errors.Is(err, ErrPayload) {
		t.Errorf("escaped variant: err = %v; want ErrPayload (non-canonical)", err)
	}
}

func TestStrict_TrailingAndDuplicateRejected(t *testing.T) {
	// Trailing object / scalar after a valid manifest.
	for _, suffix := range []string{"{}", "true", " "} {
		var m ManifestPayload
		if err := strictUnmarshal([]byte(goldenManifest+suffix), &m); err == nil && suffix != " " {
			t.Errorf("trailing %q: expected rejection", suffix)
		}
	}
	// Duplicate top-level key.
	dupTop := `{"feed":"a","feed":"url-categories/saas"}`
	var v map[string]any
	if err := strictUnmarshal([]byte(dupTop), &v); !errors.Is(err, ErrJSONDuplicateKey) {
		t.Errorf("dup top-level key: err = %v; want ErrJSONDuplicateKey", err)
	}
	// Duplicate nested key.
	dupNested := `{"a":{"x":1,"x":2}}`
	if err := strictUnmarshal([]byte(dupNested), &v); !errors.Is(err, ErrJSONDuplicateKey) {
		t.Errorf("dup nested key: err = %v; want ErrJSONDuplicateKey", err)
	}
}

func TestParseManifest_RejectsNoncanonical(t *testing.T) {
	// Extra whitespace after a colon.
	ws := strings.Replace(goldenManifest, `"schema_version":1`, `"schema_version": 1`, 1)
	if _, err := parseManifestPayload([]byte(ws)); !errors.Is(err, ErrPayload) {
		t.Errorf("whitespace: err = %v; want ErrPayload", err)
	}
	// Reordered top-level fields (protocol before schema_version).
	reordered := `{"protocol":"signed_manifest_v1","schema_version":1,"feed":"url-categories/saas","feed_version":7,"generated_at":"2026-07-31T00:00:00Z","expires_at":"2026-08-14T00:00:00Z","artifact_path":"saas-00000007-20260731.json","artifact_sha256":"0c0b97221b5f9fee7308c8187af223821324ec27fa6d1a518fddd8daaabe8a02","artifact_size":247,"artifact_sig_path":"saas-00000007-20260731.json.sigstore","category_count":2,"host_count":3}`
	if _, err := parseManifestPayload([]byte(reordered)); !errors.Is(err, ErrPayload) {
		t.Errorf("reordered: err = %v; want ErrPayload", err)
	}
	// Trailing data.
	if _, err := parseManifestPayload([]byte(goldenManifest + "{}")); !errors.Is(err, ErrPayload) {
		t.Errorf("trailing: err = %v; want ErrPayload", err)
	}
}

func TestParseArtifact_RejectsStructuralNoncanonical(t *testing.T) {
	base := `{"schema_version":1,"protocol":"signed_manifest_v1","feed":"url-categories/saas","feed_version":1,"generated_at":"2026-07-31T00:00:00Z","categories":`
	cases := map[string]string{
		"unsorted rows":  base + `[{"name":"Zeta","hosts":["a.example.com"]},{"name":"Alpha","hosts":["b.example.com"]}]}`,
		"duplicate row":  base + `[{"name":"AI","hosts":["a.example.com"]},{"name":"AI","hosts":["b.example.com"]}]}`,
		"empty hosts":    base + `[{"name":"AI","hosts":[]}]}`,
		"unsorted hosts": base + `[{"name":"AI","hosts":["z.example.com","a.example.com"]}]}`,
		"duplicate host": base + `[{"name":"AI","hosts":["a.example.com","a.example.com"]}]}`,
		"untrimmed name": base + `[{"name":" AI ","hosts":["a.example.com"]}]}`,
	}
	for name, body := range cases {
		if _, _, _, err := parseArtifactPayload([]byte(body)); !errors.Is(err, ErrPayload) {
			t.Errorf("%s: err = %v; want ErrPayload", name, err)
		}
	}
}
