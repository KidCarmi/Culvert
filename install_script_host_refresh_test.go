package main

// install_script_host_refresh_test.go — re-running scripts/install.sh over an
// existing deployment adopts the pinned image's host components (§6b,
// refresh_deploy_bundle).
//
// Found by the appliance lab's sidecar-adoption scenario (run 37625917513,
// A3): after an application upgrade to an image whose bundle names a new
// ClamAV sidecar tag, the documented refresh (`culvert-firstboot
// --repair-agent`, i.e. install.sh) exited 0 and left the compose file and
// sidecar as first installed — §6b only extracted when docker-compose.yml was
// MISSING, while upgrade-runbook.md said a re-run "re-extracts the bundle".
// A package security fix in the sidecar therefore could not reach an
// installed appliance at all.
//
// These tests run the REAL functions from scripts/install.sh under a stub
// docker whose `cp` serves a fixture bundle.

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type hostRefreshHarness struct {
	t                    *testing.T
	root, install, image string
	calls                string
}

const hostRefreshOldCompose = "services:\n  clamav:\n    image: culvert/clamav:1.4.6-old\n    build:\n      context: ./appliance/clamav\n"
const hostRefreshNewCompose = "services:\n  clamav:\n    image: culvert/clamav:1.4.6-new  # local-only\n    build:\n      context: ./appliance/clamav\n"

func newHostRefreshHarness(t *testing.T) *hostRefreshHarness {
	t.Helper()
	root := t.TempDir()
	h := &hostRefreshHarness{t: t, root: root, install: filepath.Join(root, "srv"), image: filepath.Join(root, "image-deploy"), calls: filepath.Join(root, "calls")}
	// Installed deployment (as first install left it) and the image bundle.
	h.writeTree(h.install, hostRefreshOldCompose, "FROM base\nRUN apk add zlib=1.3.2-r0\n", "agent installer v1\n")
	h.writeTree(h.image, hostRefreshOldCompose, "FROM base\nRUN apk add zlib=1.3.2-r0\n", "agent installer v1\n")
	if err := os.WriteFile(filepath.Join(h.install, ".env"), []byte("CULVERT_SECRET=keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(h.image, "bin"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.image, "bin", "culvert-maint"), []byte("binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.present("culvert/clamav:1.4.6-old")
	return h
}

func (h *hostRefreshHarness) writeTree(dir, compose, dockerfile, installer string) {
	h.t.Helper()
	files := map[string]string{
		"docker-compose.yml":                  compose,
		"docker-compose.maint-agent.yml":      "services: {}\n",
		"appliance/clamav/Dockerfile":         dockerfile,
		"packaging/culvert-maint/install.sh":  installer,
		"packaging/culvert-maint/config.toml": "x = 1\n",
	}
	for rel, body := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			h.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			h.t.Fatal(err)
		}
	}
}

// present marks a sidecar tag as already in the local image store.
func (h *hostRefreshHarness) present(tag string) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.root, "img-"+strings.NewReplacer("/", "_", ":", "_").Replace(tag)), nil, 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *hostRefreshHarness) read(rel string) string {
	h.t.Helper()
	b, err := os.ReadFile(filepath.Join(h.install, rel))
	if err != nil {
		h.t.Fatal(err)
	}
	return string(b)
}

func (h *hostRefreshHarness) snapshot() map[string]string {
	h.t.Helper()
	out := map[string]string{}
	fsys := os.DirFS(h.install)
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := fs.ReadFile(fsys, p)
		out[p] = string(b)
		return rerr
	})
	if err != nil {
		h.t.Fatal(err)
	}
	return out
}

func (h *hostRefreshHarness) run(env ...string) (out string, rc int) {
	h.t.Helper()
	var fns []string
	for _, name := range []string{"copy_bundle_file", "stage_deploy_bundle", "install_staged_bundle",
		"sidecar_image_of", "staged_bundle_differs", "refresh_deploy_bundle"} {
		fns = append(fns, extractShellFunction(h.t, "scripts/install.sh", name))
	}
	script := `set -uo pipefail
info() { echo "INFO $*"; }
warn() { echo "WARN $*"; }
sudo() { "$@"; }
install() {
  [[ -n "${FAIL_INSTALL_OF:-}" && "${@: -1}" == *"$FAIL_INSTALL_OF" ]] && return 1
  command install "$@"
}
docker() {
  echo "docker $*" >> "$CALLS"
  case "$1 $2" in
    "create culvert/proxy:pinned") echo cid1 ;;
    "cp cid1:/app/deploy/.") cp -a "$IMAGE_DEPLOY/." "$3" ;;
    "rm -f") ;;
    "image inspect") [[ -e "$ROOT/img-$(printf '%s' "$3" | tr '/:' '__')" ]] ;;
    "build -t")
      [[ -z "${FAIL_BUILD:-}" ]] || return 1
      cp "$4/Dockerfile" "$ROOT/built-dockerfile"
      : > "$ROOT/img-$(printf '%s' "$3" | tr '/:' '__')" ;;
    *) echo "unexpected docker $*" >&2; return 99 ;;
  esac
}
PINNED_TAG=culvert/proxy:pinned
` + strings.Join(fns, "\n") + `
refresh_deploy_bundle; echo "RC=$?"
`
	cmd := exec.CommandContext(h.t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script built from the repo's own install.sh
	cmd.Env = append(os.Environ(), append([]string{
		"INSTALL_DIR=" + h.install, "IMAGE_DEPLOY=" + h.image, "ROOT=" + h.root, "CALLS=" + h.calls,
	}, env...)...)
	raw, err := cmd.CombinedOutput()
	if err != nil {
		h.t.Fatalf("harness failed: %v\n%s", err, raw)
	}
	out = string(raw)
	i := strings.LastIndex(out, "RC=")
	if i < 0 {
		h.t.Fatalf("no RC:\n%s", out)
	}
	switch code := strings.TrimSpace(out[i+3:]); code {
	case "0", "1", "3":
		rc = int(code[0] - '0')
	default:
		h.t.Fatalf("unexpected rc %q:\n%s", code, out)
	}
	return out, rc
}

func (h *hostRefreshHarness) built() bool {
	_, err := os.Stat(filepath.Join(h.root, "built-dockerfile"))
	return err == nil
}

func (h *hostRefreshHarness) newRelease() {
	h.writeTree(h.image, hostRefreshNewCompose, "FROM base\nRUN apk add zlib=1.3.2-r1\n", "agent installer v2\n")
}

func TestInstallScript_HostRefresh_CurrentBundleChangesNothing(t *testing.T) {
	h := newHostRefreshHarness(t)
	before := h.snapshot()
	out, rc := h.run()
	if rc != 0 || !strings.Contains(out, "already match") {
		t.Fatalf("an unchanged bundle must report current (rc %d):\n%s", rc, out)
	}
	if h.built() {
		t.Fatal("nothing to build for an unchanged bundle")
	}
	if after := h.snapshot(); !mapsEqual(before, after) {
		t.Fatalf("an unchanged bundle must not touch the deployment:\n%v\n%v", before, after)
	}
}

// The lab's A3 case: the image now names a new sidecar tag that this host does
// not have. It is built from the NEW context first; only then are the files
// replaced, compose last.
func TestInstallScript_HostRefresh_AdoptsANewSidecar(t *testing.T) {
	h := newHostRefreshHarness(t)
	h.newRelease()
	out, rc := h.run()
	if rc != 0 {
		t.Fatalf("refresh failed (rc %d):\n%s", rc, out)
	}
	b, _ := os.ReadFile(filepath.Join(h.root, "built-dockerfile"))
	if !strings.Contains(string(b), "zlib=1.3.2-r1") {
		t.Fatalf("the sidecar must be built from the NEW bundle's context, got %q", b)
	}
	if !strings.Contains(h.read("docker-compose.yml"), "culvert/clamav:1.4.6-new") ||
		!strings.Contains(h.read("appliance/clamav/Dockerfile"), "zlib=1.3.2-r1") ||
		h.read("packaging/culvert-maint/install.sh") != "agent installer v2\n" {
		t.Fatal("compose, sidecar context and agent packaging must all be refreshed")
	}
	if h.read("docker-compose.yml.pre-refresh") != hostRefreshOldCompose {
		t.Fatal("the previous compose file must be kept as docker-compose.yml.pre-refresh")
	}
	if h.read(".env") != "CULVERT_SECRET=keep\n" {
		t.Fatal(".env must never be touched by a refresh")
	}
	if _, err := os.Stat(filepath.Join(h.install, "bin", "culvert-maint")); err == nil {
		t.Fatal("the bundle's agent binary is install_maint_agent's, never a stack file")
	}
}

// Offline (Docker Hub / Alpine CDN unreachable): the build fails, and NOTHING
// is replaced — the compose file keeps naming an image this host has, so the
// next `compose up` still works (lab A2).
func TestInstallScript_HostRefresh_FailedBuildReplacesNothing(t *testing.T) {
	h := newHostRefreshHarness(t)
	h.newRelease()
	before := h.snapshot()
	out, rc := h.run("FAIL_BUILD=1")
	if rc != 3 || !strings.Contains(out, "were NOT refreshed") {
		t.Fatalf("a failed sidecar build must return 3 with a warning (rc %d):\n%s", rc, out)
	}
	if after := h.snapshot(); !mapsEqual(before, after) {
		t.Fatalf("a failed build must leave every host component as it was:\n%v\n%v", before, after)
	}
}

func TestInstallScript_HostRefresh_PresentTagIsNotRebuilt(t *testing.T) {
	h := newHostRefreshHarness(t)
	h.newRelease()
	h.present("culvert/clamav:1.4.6-new")
	if out, rc := h.run(); rc != 0 {
		t.Fatalf("refresh failed (rc %d):\n%s", rc, out)
	}
	if h.built() {
		t.Fatal("a tag already in the local store must be reused, not rebuilt (Compose would reuse it too)")
	}
	if !strings.Contains(h.read("docker-compose.yml"), "culvert/clamav:1.4.6-new") {
		t.Fatal("compose must be refreshed")
	}
}

// A write failure after a successful build must not leave the deployment
// without a compose file (extract_deploy_bundle's fresh-install rule deletes
// the sentinel; a refresh must put the previous one back instead).
func TestInstallScript_HostRefresh_WriteFailureRestoresTheCompose(t *testing.T) {
	h := newHostRefreshHarness(t)
	h.newRelease()
	out, rc := h.run("FAIL_INSTALL_OF=/docker-compose.yml")
	if rc != 3 {
		t.Fatalf("a failed write must return 3 (rc %d):\n%s", rc, out)
	}
	if h.read("docker-compose.yml") != hostRefreshOldCompose {
		t.Fatalf("the previous compose file must be restored, got:\n%s", h.read("docker-compose.yml"))
	}
}

// The call site: a source checkout is never overwritten, a failed refresh is
// carried to the end of the run, and the run then exits non-zero.
func TestInstallScript_HostRefresh_CallSiteContract(t *testing.T) {
	raw, err := os.ReadFile("scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`elif [[ -e "$INSTALL_DIR/.git" || -f "$INSTALL_DIR/go.mod" ]]; then`,
		"refresh_deploy_bundle || refresh_rc=$?",
		"*) HOST_REFRESH_FAILED=1 ;;",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("install.sh §6b lost %q", want)
		}
	}
	tail := s[strings.LastIndex(s, `if [[ "${HOST_REFRESH_FAILED:-0}" == "1" ]]; then`):]
	if !strings.Contains(tail, "exit 3") || strings.Count(s[strings.LastIndex(s, "exit 3"):], "\n") > 3 {
		t.Fatal("a failed refresh must end the run with exit 3, after everything else ran")
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
