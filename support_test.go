package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/support"
)

// buildRealBundle assembles a bundle over the process-registered collectors
// (product + diagnostics) with no disk dependency.
func buildRealBundle(t *testing.T) *support.BuildResult {
	t.Helper()
	res, err := support.NewRunner().Build(context.Background(), support.BuildOptions{
		Version: version, GoVersion: runtime.Version(),
		Runtime: support.RuntimeInfo{NodeID: "test-node", Role: "standalone", Runtime: "compose"},
		Level:   support.L1, Nonce: "test-nonce", Clock: time.Now,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return res
}

func extractTarGz(t *testing.T, tgz []byte) map[string][]byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	out := map[string][]byte{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar: %v", err)
		}
		b, _ := io.ReadAll(tr)
		out[h.Name] = b
	}
	return out
}

func TestSupportBundle_MandatorySectionsPresent(t *testing.T) {
	res := buildRealBundle(t)
	if res.Manifest.Format != support.BundleFormat {
		t.Fatalf("format=%s want %s", res.Manifest.Format, support.BundleFormat)
	}
	ids := map[string]support.SectionEntry{}
	for _, s := range res.Manifest.Sections {
		ids[s.ID] = s
	}
	for _, want := range []string{"product", "health", "readiness", "diagnostics"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("manifest missing mandatory section %q", want)
		}
	}
	// readiness is declared PUBLIC; health is INTERNAL. Confirm the engine
	// records the actual post-redaction class per section.
	if c := ids["readiness"].ClassMax; c != "PUBLIC" {
		t.Fatalf("readiness class_max=%q want PUBLIC", c)
	}
	if c := ids["health"].ClassMax; c != "INTERNAL" {
		t.Fatalf("health class_max=%q want INTERNAL", c)
	}
	files := extractTarGz(t, res.TarGz)
	if _, ok := files[support.ManifestName]; !ok {
		t.Fatal("bundle missing manifest.json")
	}
	// product is L0/PUBLIC and must always succeed → its section file is present.
	if _, ok := files["sections/product.json"]; !ok {
		t.Fatal("bundle missing sections/product.json")
	}
	if !bytes.Contains(files["sections/product.json"], []byte(version)) {
		t.Fatal("product section does not report the version")
	}
}

// TestNoSecretInBundle is the seeded secret-leak wall for the Slice-1 sections.
// It decompresses the bundle and asserts no secret SHAPES appear in any section,
// and that the fail-closed redaction posture is recorded.
func TestNoSecretInBundle(t *testing.T) {
	res := buildRealBundle(t)
	files := extractTarGz(t, res.TarGz)

	// Concatenate every SECTION payload (not the manifest, which legitimately
	// contains hashes) and assert no credential shapes survived.
	var sections []byte
	for name, body := range files {
		if strings.HasPrefix(name, "sections/") {
			sections = append(sections, body...)
		}
	}
	// Match actual credential MATERIAL shapes, not English prose: a diagnostic
	// message may legitimately mention "private key" while carrying no key bytes.
	lower := bytes.ToLower(sections)
	for _, marker := range []string{"-----begin", "$2a$", "$2b$", "$2y$", "aws_secret", "hmac_key="} {
		if bytes.Contains(lower, []byte(marker)) {
			t.Fatalf("secret-shaped material %q found in a bundle section", marker)
		}
	}

	if !res.Manifest.Redaction.FailClosed {
		t.Fatal("manifest must record fail_closed=true")
	}
	for _, s := range res.Manifest.Sections {
		switch s.ClassMax {
		case "PUBLIC", "INTERNAL":
			// shareable
		default:
			t.Fatalf("section %s has class_max %q (must be <= INTERNAL for a shareable bundle)", s.ID, s.ClassMax)
		}
	}
}
