package main

// Real-Docker regression for candidate qualification (CI-REDESIGN §21.7.1).
//
// The first main push after build-once promotion (CI run 36111817278) failed
// qualification with "cannot overwrite digest": the scripts pulled
// <image>@<index digest> once per platform, and Docker's classic image store —
// the runners' default — keeps ONE image per digest reference. The mocked
// cases (.github/scripts/test/candidate-promotion-cases.sh) passed because the
// mock did not model the store, so this test drives the REAL daemon: it serves
// a two-platform candidate index from an in-process registry (stdlib only, no
// network, nothing published) and runs the qualification scripts in the order
// qualify-candidate runs them.
//
// It skips when no Docker daemon is reachable. Where one is (the CI runners),
// it also proves the environment reproduces the original failure on the
// classic store, so a pass cannot mean "this daemon never had the problem".

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// candidateRegistry serves pre-built blobs and manifests read-only — exactly
// the calls `docker pull` and `docker buildx imagetools inspect` make.
type candidateRegistry struct {
	blobs     map[string][]byte
	manifests map[string]ociBlob // by digest and by tag
}

type ociBlob struct {
	mediaType string
	body      []byte
}

func (r *candidateRegistry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	p := req.URL.Path
	if p == "/v2/" || p == "/v2" {
		w.WriteHeader(http.StatusOK)
		return
	}
	var (
		body      []byte
		mediaType = "application/octet-stream"
		ok        bool
	)
	switch {
	case strings.Contains(p, "/manifests/"):
		var m ociBlob
		m, ok = r.manifests[p[strings.LastIndex(p, "/manifests/")+len("/manifests/"):]]
		body, mediaType = m.body, m.mediaType
	case strings.Contains(p, "/blobs/"):
		body, ok = r.blobs[p[strings.LastIndex(p, "/blobs/")+len("/blobs/"):]]
	}
	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", mediaType)
	w.Header().Set("Docker-Content-Digest", ociDigest(body))
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	if req.Method == http.MethodHead {
		return
	}
	_, _ = w.Write(body)
}

func ociDigest(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func (r *candidateRegistry) addBlob(b []byte) string {
	d := ociDigest(b)
	r.blobs[d] = b
	return d
}

func (r *candidateRegistry) addManifest(mediaType string, v any, tag string) (digest string, size int) {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	d := ociDigest(b)
	r.manifests[d] = ociBlob{mediaType, b}
	if tag != "" {
		r.manifests[tag] = ociBlob{mediaType, b}
	}
	return d, len(b)
}

// tarLayer packs files (name → contents, all executable) into a gzipped layer
// and returns the compressed blob plus its uncompressed diff id.
func tarLayer(t *testing.T, files map[string][]byte) (gz []byte, diffID string) {
	t.Helper()
	var raw bytes.Buffer
	tw := tar.NewWriter(&raw)
	for _, d := range []string{"app/", "app/deploy/", "app/deploy/bin/", "tmp/", "data/"} {
		if err := tw.WriteHeader(&tar.Header{Name: d, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"app/culvert", "app/VERSION", "app/deploy/bin/culvert-maint", "app/.nonce"} {
		b := files[name]
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(b)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	zw := gzip.NewWriter(&out)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), ociDigest(raw.Bytes())
}

// fakeCulvertSource answers the two things qualification executes: the
// agent's -version, and the proxy's /health (status + version).
const fakeCulvertSource = `package main

import (
	"fmt"
	"net/http"
	"os"
)

var version = "dev"

func main() {
	for _, a := range os.Args[1:] {
		if a == "-version" {
			fmt.Println(version)
			return
		}
	}
	http.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, "{\"status\":\"ok\",\"version\":%q}", version)
	})
	_ = http.ListenAndServe(":8080", nil)
}
`

func buildFakeCulvert(t *testing.T, dir, goarch, version string) []byte {
	t.Helper()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fakeculvert\n\ngo 1.26\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(fakeCulvertSource), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "culvert-"+goarch)
	// #nosec G204 -- fixed go build of this test's own temp source.
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-ldflags", "-X main.version="+version, "-o", out, ".")
	cmd.Dir = src
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+goarch, "GOFLAGS=", "GOTOOLCHAIN=local")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fake culvert for %s: %v\n%s", goarch, err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func dockerOut(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// #nosec G204 -- docker with this test's own arguments.
	b, err := exec.CommandContext(t.Context(), "docker", args...).CombinedOutput()
	return strings.TrimSpace(string(b)), err
}

func TestCandidateQualification_RealDockerImageStore(t *testing.T) {
	for _, bin := range []string{"docker", "bash", "jq", "curl", "go"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not on PATH", bin)
		}
	}
	if out, err := dockerOut(t, "info", "--format", "{{.ServerVersion}}"); err != nil {
		t.Skipf("no reachable Docker daemon: %s", out)
	}
	if out, err := dockerOut(t, "buildx", "version"); err != nil {
		t.Skipf("docker buildx unavailable: %s", out)
	}
	goVersion, err := exec.CommandContext(t.Context(), "go", "env", "GOVERSION").Output()
	if err != nil {
		t.Fatal(err)
	}
	toolchain := strings.TrimSpace(string(goVersion))

	const version = "v9.9.9"
	sha := strings.Repeat("ab", 20)
	nonce := make([]byte, 8)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	// A fresh nonce per run gives fresh digests, so a leftover image from an
	// earlier run can never already hold one of them.
	reg := &candidateRegistry{blobs: map[string][]byte{}, manifests: map[string]ociBlob{}}
	type platformRef struct{ platform, digest string }
	var platforms []platformRef
	var entries []map[string]any
	dir := t.TempDir()
	for _, arch := range []string{"amd64", "arm64"} {
		bin := buildFakeCulvert(t, filepath.Join(dir, arch), arch, version)
		layer, diffID := tarLayer(t, map[string][]byte{
			"app/culvert": bin, "app/deploy/bin/culvert-maint": bin,
			"app/VERSION": []byte(version + "\n"), "app/.nonce": []byte(hex.EncodeToString(nonce) + arch),
		})
		cfg, _ := json.Marshal(map[string]any{
			"architecture": arch, "os": "linux",
			"config": map[string]any{
				"Entrypoint": []string{"/app/culvert"},
				"Labels":     map[string]string{"org.opencontainers.image.revision": sha},
			},
			"rootfs":  map[string]any{"type": "layers", "diff_ids": []string{diffID}},
			"history": []map[string]string{{"created_by": "candidate qualification test"}},
		})
		manifest := map[string]any{
			"schemaVersion": 2,
			"mediaType":     "application/vnd.oci.image.manifest.v1+json",
			"config":        map[string]any{"mediaType": "application/vnd.oci.image.config.v1+json", "digest": reg.addBlob(cfg), "size": len(cfg)},
			"layers":        []map[string]any{{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": reg.addBlob(layer), "size": len(layer)}},
		}
		d, n := reg.addManifest("application/vnd.oci.image.manifest.v1+json", manifest, "")
		platforms = append(platforms, platformRef{"linux/" + arch, d})
		entries = append(entries, map[string]any{
			"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": d, "size": n,
			"platform": map[string]string{"os": "linux", "architecture": arch},
		})
	}
	index, _ := reg.addManifest("application/vnd.oci.image.index.v1+json", map[string]any{
		"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": entries,
	}, "candidate")

	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: reg, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	image := fmt.Sprintf("%s/culvert-qualification-test", l.Addr().String())
	smokeTag := "culvert-qualification-test:" + hex.EncodeToString(nonce)
	t.Cleanup(func() {
		refs := []string{image + "@" + index, smokeTag}
		for _, p := range platforms {
			refs = append(refs, image+"@"+p.digest)
		}
		// t.Context() is already cancelled when cleanups run, so removal
		// gets its own bounded context; otherwise the images are left behind.
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		for _, r := range refs {
			// #nosec G204 -- docker with this test's own arguments.
			_ = exec.CommandContext(ctx, "docker", "image", "rm", "-f", r).Run()
		}
	})

	store, _ := dockerOut(t, "info", "--format", "{{json .DriverStatus}}")
	classic := !strings.Contains(store, "io.containerd.snapshotter")
	t.Logf("docker image store: %s (classic=%v)", store, classic)

	// 1. The original failure, reproduced: one index digest, pulled for a
	// second platform. On the classic store this MUST fail — if it does not,
	// the daemon cannot show the defect and the checks below prove less.
	if classic {
		if out, err := dockerOut(t, "pull", "--quiet", "--platform", "linux/amd64", image+"@"+index); err != nil {
			t.Fatalf("pull amd64 by index digest: %v\n%s", err, out)
		}
		out, err := dockerOut(t, "pull", "--quiet", "--platform", "linux/arm64", image+"@"+index)
		if err == nil || !strings.Contains(out, "cannot overwrite digest") {
			t.Fatalf("the classic store accepted a second platform under one index digest (err=%v): %s — this daemon no longer reproduces run 36111817278", err, out)
		}
		_, _ = dockerOut(t, "image", "rm", "-f", image+"@"+index)
	} else {
		t.Log("containerd image store: the original failure cannot occur here; checking the fixed sequence only")
	}

	// 2. The qualification sequence, in qualify-candidate's order, on ONE store.
	env := append(os.Environ(), "DOCKER_BIN=docker")
	script := func(name string, args ...string) (string, error) {
		// #nosec G204 -- this repository's own scripts with test arguments.
		cmd := exec.CommandContext(t.Context(), "bash", append([]string{".github/scripts/" + name}, args...)...)
		cmd.Env = env
		b, err := cmd.CombinedOutput()
		return string(b), err
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := script(name, args...)
		if err != nil {
			t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
		}
		return out
	}
	out := run("candidate-verify-contents.sh", image, index, sha, version, toolchain)
	if !strings.Contains(out, "candidate contents verified") {
		t.Fatalf("contents not verified:\n%s", out)
	}
	env = append(env, fmt.Sprintf("RUN_CHECK_PORT=%d", freePort(t)), "RUN_CHECK_TRIES=30", "RUN_CHECK_DELAY=1")
	run("candidate-run-check.sh", image, index, version, "linux/amd64")
	if _, err := os.Stat("/proc/sys/fs/binfmt_misc/qemu-aarch64"); err == nil {
		run("candidate-run-check.sh", image, index, version, "linux/arm64")
	} else {
		// No emulator: the arm64 binary cannot execute here, but the script's
		// PULL must still succeed on this store — that is where run 36111817278
		// broke. Any failure after the pull is the missing emulator.
		out, err := script("candidate-run-check.sh", image, index, version, "linux/arm64")
		if strings.Contains(out, "cannot overwrite digest") || strings.Contains(out, "no single manifest digest") {
			t.Fatalf("arm64 run check failed at the pull, not at execution: %v\n%s", err, out)
		}
		t.Logf("no qemu-aarch64 binfmt handler: arm64 pulled, execution not attempted to completion (err=%v); qualify-candidate sets up QEMU and runs it", err)
	}
	ref := strings.TrimSpace(run("candidate-platform-ref.sh", image, index, "linux/amd64"))
	if ref != image+"@"+platforms[0].digest {
		t.Fatalf("platform ref = %q, want the amd64 manifest %s", ref, platforms[0].digest)
	}
	if out, err := dockerOut(t, "pull", "--quiet", "--platform", "linux/amd64", ref); err != nil {
		t.Fatalf("compose-smoke pull of %s after both platforms: %v\n%s", ref, err, out)
	}
	if out, err := dockerOut(t, "tag", ref, smokeTag); err != nil {
		t.Fatalf("tag %s: %v\n%s", ref, err, out)
	}
}
