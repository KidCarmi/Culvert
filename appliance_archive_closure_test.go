package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// F-OVA-CLAMAV-1 (LOCAL-ESXI, PR #1528): runner-built OVAs baked a 69,562-byte
// ClamAV archive whose amd64 manifest referenced a config and seven layers
// the archive did not carry. `docker load` reported success; first boot then
// failed to create the container. archive_platform_closure must refuse it.

type closureBlob struct {
	digest string
	data   []byte
}

func newClosureBlob(data []byte) closureBlob {
	sum := sha256.Sum256(data)
	return closureBlob{digest: "sha256:" + hex.EncodeToString(sum[:]), data: data}
}

func (b closureBlob) desc(mediaType string, platform map[string]string) map[string]any {
	d := map[string]any{"mediaType": mediaType, "digest": b.digest, "size": len(b.data)}
	if platform != nil {
		d["platform"] = platform
	}
	return d
}

const (
	closureIndexMT    = "application/vnd.oci.image.index.v1+json"
	closureManifestMT = "application/vnd.oci.image.manifest.v1+json"
)

// platformImage returns the blobs of one single-platform image and its
// manifest blob.
func platformImage(t *testing.T, osName, arch string, nLayers int, salt ...string) (manifest closureBlob, config closureBlob, layers []closureBlob) {
	t.Helper()
	cfg, _ := json.Marshal(map[string]any{"os": osName, "architecture": arch, "salt": strings.Join(salt, "")})
	config = newClosureBlob(cfg)
	ld := make([]map[string]any, 0, nLayers)
	for i := 0; i < nLayers; i++ {
		l := newClosureBlob([]byte(strings.Join(salt, "") + strings.Repeat(arch, 10+i)))
		layers = append(layers, l)
		ld = append(ld, l.desc("application/vnd.oci.image.layer.v1.tar+gzip", nil))
	}
	m, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": closureManifestMT,
		"config": config.desc("application/vnd.oci.image.config.v1+json", nil), "layers": ld})
	return newClosureBlob(m), config, layers
}

func writeClosureArchive(t *testing.T, path string, index []map[string]any, blobs []closureBlob) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	put := func(name string, data []byte) {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": closureIndexMT, "manifests": index})
	put("index.json", idx)
	put("oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`))
	for _, b := range blobs {
		put("blobs/sha256/"+strings.TrimPrefix(b.digest, "sha256:"), b.data)
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

func runArchiveClosure(t *testing.T, archive string, pins ...string) (string, error) {
	t.Helper()
	for _, tool := range []string{"bash", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skip(tool + " not available")
		}
	}
	lib := filepath.Join(pkgSourceDir(), "appliance", "build", "archive-identity.sh")
	pin, plat := "", ""
	if len(pins) > 0 {
		pin = pins[0]
	}
	if len(pins) > 1 {
		plat = pins[1]
	}
	cmd := exec.CommandContext(t.Context(), "bash", "-c", `. "$1"; archive_platform_closure "$2" linux/amd64 "$3" "$4"`, "x", lib, archive, pin, plat) //nolint:gosec // test-owned paths
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// multiPlatform builds an index (amd64 + arm64 + an attestation) the way a
// containerd-store `docker save` of a registry image does, and returns the
// pieces so a case can drop or corrupt one.
type multiPlatform struct {
	index                      closureBlob
	amd64M, amd64C, armM, attM closureBlob
	amd64L                     []closureBlob
}

func newMultiPlatform(t *testing.T, salt ...string) multiPlatform {
	t.Helper()
	var mp multiPlatform
	mp.amd64M, mp.amd64C, mp.amd64L = platformImage(t, "linux", "amd64", 7, salt...)
	mp.armM, _, _ = platformImage(t, "linux", "arm64", 2, salt...) // arm64 content absent: not needed
	mp.attM = newClosureBlob([]byte(`{"schemaVersion":2,"layers":[]}`))
	idx, _ := json.Marshal(map[string]any{"schemaVersion": 2, "mediaType": closureIndexMT, "manifests": []map[string]any{
		mp.amd64M.desc(closureManifestMT, map[string]string{"os": "linux", "architecture": "amd64"}),
		mp.armM.desc(closureManifestMT, map[string]string{"os": "linux", "architecture": "arm64"}),
		mp.attM.desc(closureManifestMT, map[string]string{"os": "unknown", "architecture": "unknown"}),
	}})
	mp.index = newClosureBlob(idx)
	return mp
}

func (mp multiPlatform) write(t *testing.T, path string, blobs ...closureBlob) {
	t.Helper()
	writeClosureArchive(t, path, []map[string]any{mp.index.desc(closureIndexMT, nil)}, blobs)
}

func TestArchiveClosure_AcceptsACompleteMultiPlatformArchive(t *testing.T) {
	mp := newMultiPlatform(t)
	p := filepath.Join(t.TempDir(), "ok.tar.gz")
	mp.write(t, p, append([]closureBlob{mp.index, mp.amd64M, mp.amd64C}, mp.amd64L...)...)
	if out, err := runArchiveClosure(t, p, mp.index.digest, mp.amd64M.digest); err != nil || !strings.Contains(out, "closure ok") {
		t.Fatalf("a complete amd64 image must pass: %v\n%s", err, out)
	}
}

func TestArchiveClosure_AcceptsASingleManifestArchive(t *testing.T) {
	// The candidate application image is saved as one manifest with no
	// platform annotation; the config's os/architecture decides.
	m, c, ls := platformImage(t, "linux", "amd64", 3)
	p := filepath.Join(t.TempDir(), "app.tar.gz")
	writeClosureArchive(t, p, []map[string]any{m.desc(closureManifestMT, nil)}, append([]closureBlob{m, c}, ls...))
	if out, err := runArchiveClosure(t, p, m.digest, m.digest); err != nil {
		t.Fatalf("a complete single-manifest image must pass: %v\n%s", err, out)
	}
}

func TestArchiveClosure_RefusesTheF_OVA_CLAMAV_1Shape(t *testing.T) {
	// Index and manifests present, config and every layer absent.
	mp := newMultiPlatform(t)
	p := filepath.Join(t.TempDir(), "hollow.tar.gz")
	mp.write(t, p, mp.index, mp.amd64M, mp.armM, mp.attM)
	if out, err := runArchiveClosure(t, p, mp.index.digest, mp.amd64M.digest); err == nil || !strings.Contains(out, "lacks config "+mp.amd64C.digest) {
		t.Fatalf("an archive naming an image it does not carry must be refused: %v\n%s", err, out)
	}
}

func TestArchiveClosure_RefusesAMissingOrDamagedBlob(t *testing.T) {
	mp := newMultiPlatform(t)
	dir := t.TempDir()
	all := append([]closureBlob{mp.index, mp.amd64M, mp.amd64C}, mp.amd64L...)

	missing := filepath.Join(dir, "missing-layer.tar.gz")
	mp.write(t, missing, all[:len(all)-1]...)
	if out, err := runArchiveClosure(t, missing, mp.index.digest, mp.amd64M.digest); err == nil || !strings.Contains(out, "lacks layer 6") {
		t.Fatalf("a missing layer must be refused: %v\n%s", err, out)
	}

	damaged := filepath.Join(dir, "damaged-layer.tar.gz")
	bad := append([]closureBlob(nil), all...)
	last := bad[len(bad)-1]
	flipped := append([]byte(nil), last.data...)
	flipped[0] ^= 0xff
	bad[len(bad)-1] = closureBlob{digest: last.digest, data: flipped}
	mp.write(t, damaged, bad...)
	if out, err := runArchiveClosure(t, damaged, mp.index.digest, mp.amd64M.digest); err == nil || !strings.Contains(out, "does not hash to its digest") {
		t.Fatalf("a layer whose bytes do not match its digest must be refused: %v\n%s", err, out)
	}

	short := filepath.Join(dir, "short-layer.tar.gz")
	trunc := append([]closureBlob(nil), all...)
	trunc[len(trunc)-1] = closureBlob{digest: last.digest, data: last.data[:len(last.data)-1]}
	mp.write(t, short, trunc...)
	if out, err := runArchiveClosure(t, short, mp.index.digest, mp.amd64M.digest); err == nil || !strings.Contains(out, "descriptor says") {
		t.Fatalf("a layer of the wrong size must be refused: %v\n%s", err, out)
	}
}

func TestArchiveClosure_RefusesAnArchiveWithNoAmd64Image(t *testing.T) {
	m, c, ls := platformImage(t, "linux", "arm64", 2)
	p := filepath.Join(t.TempDir(), "arm.tar.gz")
	writeClosureArchive(t, p, []map[string]any{m.desc(closureManifestMT, nil)}, append([]closureBlob{m, c}, ls...))
	if out, err := runArchiveClosure(t, p, m.digest); err == nil || !strings.Contains(out, "no complete linux/amd64 image") {
		t.Fatalf("an archive without an amd64 image must be refused: %v\n%s", err, out)
	}
}

func TestBuildOVA_ChecksBothArchivesCarryTheirImageBeforeBaking(t *testing.T) {
	b, err := os.ReadFile(buildOVAScript)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	j := strings.Index(src, `APP_TAR_SHA="$(sha256sum`)
	for _, check := range []string{
		`archive_platform_closure "$OV/var/lib/culvert-appliance/images/culvert.tar.gz" linux/amd64 "$APP_IMAGE_INDEX_DIGEST" "$APP_IMAGE_AMD64_DIGEST"`,
		`archive_platform_closure "$OV/var/lib/culvert-appliance/images/clamav.tar.gz" linux/amd64 "$CLAMAV_IMAGE_INDEX_DIGEST" "$CLAMAV_IMAGE_AMD64_DIGEST"`,
	} {
		if i := strings.Index(src, check); i < 0 || j < 0 || i > j {
			t.Errorf("build-ova.sh must run %s before recording and baking the archives", check)
		}
	}
}

func TestArchiveClosure_ACompleteButDifferentImageDoesNotSatisfyThePin(t *testing.T) {
	// The archive carries a complete amd64 image, but not the pinned one.
	other := newMultiPlatform(t, "other")
	pinned := newMultiPlatform(t, "pinned")
	if other.index.digest == pinned.index.digest {
		t.Fatal("fixture: two distinct images expected")
	}
	p := filepath.Join(t.TempDir(), "other.tar.gz")
	other.write(t, p, append([]closureBlob{other.index, other.amd64M, other.amd64C}, other.amd64L...)...)
	if out, err := runArchiveClosure(t, p, pinned.index.digest, pinned.amd64M.digest); err == nil || !strings.Contains(out, "does not list the pinned") {
		t.Fatalf("a complete image that is not the pinned one must be refused: %v\n%s", err, out)
	}
	// Pinned index present, but it resolves amd64 to a manifest other than the
	// pinned platform digest.
	if out, err := runArchiveClosure(t, p, other.index.digest, pinned.amd64M.digest); err == nil || !strings.Contains(out, "not the pinned") {
		t.Fatalf("an amd64 manifest other than the pinned one must be refused: %v\n%s", err, out)
	}
}

func TestArchiveClosure_WalksOnlyFromThePin(t *testing.T) {
	// A complete unrelated image beside a hollow pinned one must not rescue it.
	hollow := newMultiPlatform(t, "hollow")
	full := newMultiPlatform(t, "full")
	p := filepath.Join(t.TempDir(), "mixed.tar.gz")
	blobs := append([]closureBlob{hollow.index, hollow.amd64M, full.index, full.amd64M, full.amd64C}, full.amd64L...)
	writeClosureArchive(t, p, []map[string]any{hollow.index.desc(closureIndexMT, nil), full.index.desc(closureIndexMT, nil)}, blobs)
	if out, err := runArchiveClosure(t, p, hollow.index.digest, hollow.amd64M.digest); err == nil || !strings.Contains(out, "lacks config") {
		t.Fatalf("the pinned image must be complete on its own: %v\n%s", err, out)
	}
	if out, err := runArchiveClosure(t, p, full.index.digest, full.amd64M.digest); err != nil {
		t.Fatalf("control: the complete image in the same archive passes: %v\n%s", err, out)
	}
}

func TestBuildOVA_ColdLoadsBothArchivesBeforeBaking(t *testing.T) {
	b, err := os.ReadFile(buildOVAScript)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	j := strings.Index(src, `APP_TAR_SHA="$(sha256sum`)
	for _, want := range []string{
		`--archive "$OV/var/lib/culvert-appliance/images/culvert.tar.gz" --ref "${APP_IMAGE_REPO}:${APP_IMAGE_TAG}"`,
		`--archive "$OV/var/lib/culvert-appliance/images/clamav.tar.gz" --ref "${CLAMAV_IMAGE_REPO#docker.io/}:${CLAMAV_IMAGE_TAG}"`,
	} {
		i := strings.Index(src, want)
		if i < 0 || j < 0 || i > j {
			t.Errorf("build-ova.sh must cold-load %s before recording and baking the archives", want)
			continue
		}
		if !strings.Contains(src[max(0, i-200):i], `"$HERE/cold-load-check.sh" --dind "$COLDLOAD_DIND_IMAGE"`) {
			t.Errorf("the cold-load of %s must use the pinned disposable daemon", want)
		}
	}
	m, err := os.ReadFile(filepath.Join(pkgSourceDir(), "appliance", "build", "manifest.env"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^COLDLOAD_DIND_IMAGE=docker\.io/library/docker@sha256:[0-9a-f]{64}$`).Match(m) {
		t.Error("manifest.env must pin COLDLOAD_DIND_IMAGE by digest")
	}
	c, err := os.ReadFile(filepath.Join(pkgSourceDir(), "appliance", "build", "cold-load-check.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"--pull=never", "registry fallback is reachable", "io.containerd.snapshotter.v1", "disposable store is not empty", "docker create --pull=never"} {
		if !strings.Contains(string(c), want) {
			t.Errorf("cold-load-check.sh lost %q", want)
		}
	}
}
