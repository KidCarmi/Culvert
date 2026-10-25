package main

// build-ova.sh refuses to bake an application archive that does not carry the
// pinned digest the first boot will verify (Codex P1, PR #1528): a classic
// image store saves a re-created manifest, and the OVA would abort its own
// first boot. Driven through bash against hand-built archives of both shapes.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func writeImageArchive(t *testing.T, path, indexDigest string, blobs ...string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	add := func(name string, body []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	add("index.json", []byte(`{"schemaVersion":2,"manifests":[{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"`+indexDigest+`","size":856}]}`))
	for _, b := range blobs {
		add("blobs/sha256/"+strings.TrimPrefix(b, "sha256:"), []byte("{}"))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runArchiveNamesDigest(t *testing.T, archive, digest string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	lib := filepath.Join(pkgSourceDir(), "appliance", "build", "archive-identity.sh")
	cmd := exec.CommandContext(t.Context(), "bash", "-c", `. "$1"; archive_names_digest "$2" "$3"`, "x", lib, archive, digest) //nolint:gosec // test-owned paths and constant digests
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestArchiveIdentity_AcceptsTheArchiveThatCarriesThePin(t *testing.T) {
	pin := "sha256:" + strings.Repeat("a", 64)
	p := filepath.Join(t.TempDir(), "ok.tar.gz")
	writeImageArchive(t, p, pin, pin)
	if out, err := runArchiveNamesDigest(t, p, pin); err != nil {
		t.Fatalf("an archive naming and carrying the pin must pass: %v\n%s", err, out)
	}
}

func TestArchiveIdentity_RefusesAClassicStoreArchive(t *testing.T) {
	pin := "sha256:" + strings.Repeat("a", 64)
	recreated := "sha256:" + strings.Repeat("b", 64)
	dir := t.TempDir()
	classic := filepath.Join(dir, "classic.tar.gz")
	writeImageArchive(t, classic, recreated, recreated)
	if out, err := runArchiveNamesDigest(t, classic, pin); err == nil || !strings.Contains(out, "not the pinned") {
		t.Fatalf("a re-created manifest must be refused: %v\n%s", err, out)
	}
	missingBlob := filepath.Join(dir, "noblob.tar.gz")
	writeImageArchive(t, missingBlob, pin)
	if out, err := runArchiveNamesDigest(t, missingBlob, pin); err == nil || !strings.Contains(out, "lacks blob") {
		t.Fatalf("an index naming a blob the archive does not carry must be refused: %v\n%s", err, out)
	}
}

func TestBuildOVA_VerifiesTheAppArchiveIdentityBeforeBaking(t *testing.T) {
	b, err := os.ReadFile(buildOVAScript)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	check := `archive_names_digest "$OV/var/lib/culvert-appliance/images/culvert.tar.gz" "$APP_IMAGE_INDEX_DIGEST"`
	i, j := strings.Index(src, check), strings.Index(src, `APP_TAR_SHA="$(sha256sum`)
	if i < 0 || j < 0 || i > j {
		t.Fatal("build-ova.sh must verify the saved app archive's identity before recording and baking it")
	}
}
