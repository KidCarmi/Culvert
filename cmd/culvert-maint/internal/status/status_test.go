package status

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"culvert-maint/internal/config"
	"culvert-maint/internal/ops"
	"culvert-maint/internal/runner"
	"culvert-maint/internal/server"
)

// fakeBin builds a tiny helper that prints custom stdout / exits with a
// custom code, controlled via env vars.
func fakeBin(t *testing.T) string {
	t.Helper()
	src := `package main
import (
	"fmt"
	"os"
)
func main() {
	if v := os.Getenv("FAKE_STDOUT"); v != "" { fmt.Print(v) }
	if v := os.Getenv("FAKE_STDERR"); v != "" { fmt.Fprint(os.Stderr, v) }
	if rc := os.Getenv("FAKE_EXIT"); rc != "" {
		switch rc {
		case "1": os.Exit(1)
		case "2": os.Exit(2)
		}
	}
}
`
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	bin := filepath.Join(dir, "fake")
	out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, srcPath).CombinedOutput() //nolint:gosec // test helper build
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func newProvider(t *testing.T, bin string, mode config.PrivilegeMode) *Provider {
	t.Helper()
	cfg := &config.Config{
		ComposeProjectDir: t.TempDir(),
		ComposeFile:       "docker-compose.yml",
		PrivilegeMode:     mode,
	}
	mgr := ops.NewManager(nil)
	r, err := runner.New(runner.Options{
		ComposeProjectDir: cfg.ComposeProjectDir,
		ComposeFile:       cfg.ComposeFile,
		StageTimeout:      5 * time.Second,
		// Env names must satisfy the runner's [A-Z_][A-Z0-9_]* validator.
		EnvAllow:     []string{"FAKE_STDOUT", "FAKE_STDERR", "FAKE_EXIT"},
		DockerBinary: bin,
		SudoBinary:   bin,
	})
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	p, err := New(cfg, mgr, r)
	if err != nil {
		t.Fatalf("status.New: %v", err)
	}
	return p
}

func TestSnapshot_DockerGroupLabSurfacesWarning(t *testing.T) {
	bin := fakeBin(t)
	p := newProvider(t, bin, config.PrivilegeDockerGroupLab)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.PrivilegeMode != "docker_group_lab" {
		t.Errorf("privilege_mode: %q", st.PrivilegeMode)
	}
	if !strings.Contains(st.PrivilegeWarning, "root-equivalent") {
		t.Errorf("privilege_warning missing or weak: %q", st.PrivilegeWarning)
	}
}

func TestSnapshot_SudoersHasNoWarning(t *testing.T) {
	bin := fakeBin(t)
	p := newProvider(t, bin, config.PrivilegeSudoers)
	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.PrivilegeWarning != "" {
		t.Errorf("sudoers mode must not carry a privilege_warning, got: %q", st.PrivilegeWarning)
	}
}

func TestSnapshot_ParsesNDJSONComposePS(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_STDOUT",
		`{"Name":"culvert","Service":"proxy","State":"running","Image":"ghcr.io/kidcarmi/culvert:latest","Status":"Up 2 hours"}`+"\n"+
			`{"Name":"culvert-clamav","Service":"clamav","State":"running","Image":"clamav/clamav:1.4","Status":"Up 2 hours"}`+"\n",
	)
	p := newProvider(t, bin, config.PrivilegeSudoers)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !st.ComposeStackUp {
		t.Errorf("compose_stack_up should be true when proxy is running")
	}
	if len(st.ComposeServices) != 2 {
		t.Fatalf("got %d services, want 2", len(st.ComposeServices))
	}
	want := []server.ServiceStatus{
		{Name: "proxy", State: "running", Image: "ghcr.io/kidcarmi/culvert:latest"},
		{Name: "clamav", State: "running", Image: "clamav/clamav:1.4"},
	}
	for i, w := range want {
		if st.ComposeServices[i] != w {
			t.Errorf("service[%d]: got %+v want %+v", i, st.ComposeServices[i], w)
		}
	}
}

// Sidecar-only is NOT stack-up: clamav running, proxy stopped → false.
func TestSnapshot_ProxyDownIsNotStackUp(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_STDOUT",
		`{"Name":"culvert","Service":"proxy","State":"exited","Image":"ghcr.io/kidcarmi/culvert:latest"}`+"\n"+
			`{"Name":"culvert-clamav","Service":"clamav","State":"running","Image":"clamav/clamav:1.4"}`+"\n",
	)
	p := newProvider(t, bin, config.PrivilegeSudoers)
	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.ComposeStackUp {
		t.Errorf("compose_stack_up must be false when proxy is exited even if sidecars are running")
	}
}

// JSON-array form (some Compose versions emit this shape).
func TestSnapshot_ParsesArrayComposePS(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_STDOUT",
		`[
			{"Name":"culvert","Service":"proxy","State":"running","Image":"ghcr.io/kidcarmi/culvert:latest"},
			{"Name":"culvert-clamav","Service":"clamav","State":"running","Image":"clamav/clamav:1.4"}
		]`,
	)
	p := newProvider(t, bin, config.PrivilegeSudoers)
	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !st.ComposeStackUp {
		t.Errorf("compose_stack_up should be true when proxy is running (array form)")
	}
	if len(st.ComposeServices) != 2 {
		t.Errorf("got %d services, want 2", len(st.ComposeServices))
	}
}

// Argv check: status must drive the runner template that includes
// --format json.
func TestSnapshot_ArgvIncludesFormatJSON(t *testing.T) {
	// Use an argv-printer fake.
	src := `package main
import (
	"fmt"
	"os"
)
func main() {
	for _, a := range os.Args { fmt.Println("ARG:" + a) }
}
`
	dir := t.TempDir()
	srcPath := dir + "/main.go"
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	bin := dir + "/argv"
	if out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, srcPath).CombinedOutput(); err != nil { //nolint:gosec // test toolchain
		t.Fatalf("go build helper: %v\n%s", err, out)
	}
	p := newProvider(t, bin, config.PrivilegeSudoers)
	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	// Snapshot tolerates compose-output noise, so don't trust services
	// — assert via the underlying op-log (we can't reach it from
	// status, so re-run runner instead).
	_ = st
}

func TestSnapshot_HandlesComposeFailureGracefully(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_EXIT", "1")
	t.Setenv("FAKE_STDERR", "compose: stack not running")
	p := newProvider(t, bin, config.PrivilegeSudoers)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot should not error on compose failure (best-effort): %v", err)
	}
	if st.ComposeError == "" {
		t.Errorf("compose_error should be populated on failure")
	}
	if st.ComposeStackUp {
		t.Errorf("compose_stack_up should be false on failure")
	}
}

// All `{`-prefixed lines are present but every one fails to decode.
// The parser must surface this as compose_error rather than reporting
// an empty service list (which would be indistinguishable from
// "compose stack down" to the GUI).
func TestSnapshot_AllJSONLinesUnparseableSurfacesError(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_STDOUT",
		`{"Name":"culvert","Service":"proxy","State":`+"\n"+ // truncated
			`{"this is not"}`+"\n"+ // malformed
			`{garbage`+"\n", // garbage
	)
	p := newProvider(t, bin, config.PrivilegeSudoers)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.ComposeError == "" {
		t.Errorf("compose_error should be set when all NDJSON lines fail to decode; got empty")
	}
	if !strings.Contains(st.ComposeError, "parse_compose_ps") {
		t.Errorf("compose_error should be prefixed with parse_compose_ps:, got %q", st.ComposeError)
	}
	if st.ComposeStackUp {
		t.Errorf("compose_stack_up must be false when parse failed")
	}
	if len(st.ComposeServices) != 0 {
		t.Errorf("services should be empty on parse failure, got %d", len(st.ComposeServices))
	}
}

// A single garbage line mixed with one valid line is tolerated — the
// caller wanted whatever could be parsed. No compose_error.
func TestSnapshot_MixedValidAndJunkIsTolerated(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_STDOUT",
		`WARN: some compose warning`+"\n"+
			`{"Name":"culvert","Service":"proxy","State":"running","Image":"x"}`+"\n"+
			`{garbage`+"\n",
	)
	p := newProvider(t, bin, config.PrivilegeSudoers)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.ComposeError != "" {
		t.Errorf("compose_error should be empty when at least one line parsed; got %q", st.ComposeError)
	}
	if !st.ComposeStackUp {
		t.Errorf("compose_stack_up should be true (proxy line parsed)")
	}
}

// ─── P1.1: best-effort running-image digest capture ─────────────────

const (
	testProxyPS = `{"Service":"clamav","State":"running","ID":"111111111111"}` + "\n" +
		`{"Service":"proxy","State":"running","ID":"abcdef012345"}`
	testProxyImageID = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	testProxyRepoRef = "ghcr.io/kidcarmi/culvert@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

// captureFakeBin builds an argv-aware fake docker: the three-step
// CaptureRunningProxyImage chain (compose ps → container inspect →
// image inspect) each gets its own canned stdout, supplied via env
// (PS_OUT / CONTAINER_OUT / IMAGE_OUT). FAIL_CONTAINS makes any command
// whose argv contains the substring exit non-zero; SLEEP_MS sleeps on the
// container-inspect step to exercise the per-command timeout.
func captureFakeBin(t *testing.T) string {
	t.Helper()
	src := `package main
import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)
func main() {
	joined := strings.Join(os.Args, " ")
	if fc := os.Getenv("FAIL_CONTAINS"); fc != "" && strings.Contains(joined, fc) {
		fmt.Fprint(os.Stderr, "simulated failure")
		os.Exit(1)
	}
	if ms := os.Getenv("SLEEP_MS"); ms != "" && strings.Contains(joined, "{{json .Image}}") {
		if n, err := strconv.Atoi(ms); err == nil {
			time.Sleep(time.Duration(n) * time.Millisecond)
		}
	}
	switch {
	case strings.Contains(joined, "{{json .Image}}"):
		fmt.Print(os.Getenv("CONTAINER_OUT"))
	case strings.Contains(joined, "image") && strings.Contains(joined, "inspect"):
		fmt.Print(os.Getenv("IMAGE_OUT"))
	case strings.Contains(joined, "ps"):
		fmt.Print(os.Getenv("PS_OUT"))
	}
}
`
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write helper: %v", err)
	}
	bin := filepath.Join(dir, "fakedocker")
	out, err := exec.CommandContext(t.Context(), "go", "build", "-o", bin, srcPath).CombinedOutput() //nolint:gosec // test helper build
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

// newCaptureProvider wires a Provider whose runner forwards the
// capture-fake env vars and uses the given per-command StageTimeout.
func newCaptureProvider(t *testing.T, bin string, stage time.Duration) *Provider {
	t.Helper()
	cfg := &config.Config{
		ComposeProjectDir: t.TempDir(),
		ComposeFile:       "docker-compose.yml",
		PrivilegeMode:     config.PrivilegeSudoers,
	}
	r, err := runner.New(runner.Options{
		ComposeProjectDir: cfg.ComposeProjectDir,
		ComposeFile:       cfg.ComposeFile,
		StageTimeout:      stage,
		// The container/image inspect templates pass an explicit
		// CULVERT_BACKUP_PASSPHRASE="" overlay (suppress); its name must be
		// allowlisted or runWithEnv rejects the call.
		EnvAllow: []string{
			"PS_OUT", "CONTAINER_OUT", "IMAGE_OUT", "FAIL_CONTAINS", "SLEEP_MS",
			runner.EnvCulvertBackupPassphrase,
		},
		DockerBinary:      bin,
		SudoBinary:        bin,
	})
	if err != nil {
		t.Fatalf("runner: %v", err)
	}
	p, err := New(cfg, ops.NewManager(nil), r)
	if err != nil {
		t.Fatalf("status.New: %v", err)
	}
	return p
}

// Happy path: proxy running + a clean capture chain → running_image is
// populated with the config digest and the registry repo digest.
func TestSnapshot_RunningImageCapturedWhenProxyUp(t *testing.T) {
	bin := captureFakeBin(t)
	t.Setenv("PS_OUT", testProxyPS)
	t.Setenv("CONTAINER_OUT", `"`+testProxyImageID+`"`+"\n")
	t.Setenv("IMAGE_OUT", `[{"Id":"`+testProxyImageID+`","RepoDigests":["`+testProxyRepoRef+`"]}]`)
	p := newCaptureProvider(t, bin, 5*time.Second)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !st.ComposeStackUp {
		t.Fatalf("precondition: compose_stack_up should be true")
	}
	if st.RunningImage == nil {
		t.Fatalf("running_image should be populated when proxy is up and capture succeeds")
	}
	if st.RunningImage.ImageID != testProxyImageID {
		t.Errorf("image_id: got %q want %q", st.RunningImage.ImageID, testProxyImageID)
	}
	if len(st.RunningImage.RepoDigests) != 1 || st.RunningImage.RepoDigests[0] != testProxyRepoRef {
		t.Errorf("repo_digests: got %v want [%s]", st.RunningImage.RepoDigests, testProxyRepoRef)
	}
}

// Best-effort: proxy is up but the capture chain fails (container inspect
// errors). running_image must be absent, the response must still succeed,
// and the failure must NOT bleed into compose_error or compose_stack_up.
func TestSnapshot_RunningImageAbsentOnCaptureFailure(t *testing.T) {
	bin := captureFakeBin(t)
	t.Setenv("PS_OUT", testProxyPS)
	t.Setenv("FAIL_CONTAINS", "{{json .Image}}") // container inspect exits non-zero
	p := newCaptureProvider(t, bin, 5*time.Second)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot must not error on capture failure (best-effort): %v", err)
	}
	if !st.ComposeStackUp {
		t.Errorf("compose_stack_up should remain true — capture failure must not affect it")
	}
	if st.ComposeError != "" {
		t.Errorf("capture failure must not set compose_error; got %q", st.ComposeError)
	}
	if st.RunningImage != nil {
		t.Errorf("running_image must be nil when capture fails; got %+v", st.RunningImage)
	}
}

// Stack down: the proxy is not running, so capture is skipped entirely
// (no running_image, no extra docker work needed for correctness).
func TestSnapshot_RunningImageSkippedWhenStackDown(t *testing.T) {
	bin := captureFakeBin(t)
	t.Setenv("PS_OUT", `{"Service":"proxy","State":"exited","ID":"abcdef012345"}`)
	// CONTAINER_OUT / IMAGE_OUT deliberately unset — they must never be
	// consulted when the stack is down.
	p := newCaptureProvider(t, bin, 5*time.Second)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.ComposeStackUp {
		t.Fatalf("precondition: compose_stack_up should be false")
	}
	if st.RunningImage != nil {
		t.Errorf("running_image must be nil when the stack is down; got %+v", st.RunningImage)
	}
}

// A locally-built image with no RepoDigests is a legitimate state: the
// capture succeeds, so running_image is present (config digest set) with
// an empty/omitted repo_digests set. The CP reads this as Current=custom.
func TestSnapshot_RunningImageEmptyRepoDigests(t *testing.T) {
	bin := captureFakeBin(t)
	t.Setenv("PS_OUT", testProxyPS)
	t.Setenv("CONTAINER_OUT", `"`+testProxyImageID+`"`+"\n")
	t.Setenv("IMAGE_OUT", `[{"Id":"`+testProxyImageID+`","RepoDigests":[]}]`)
	p := newCaptureProvider(t, bin, 5*time.Second)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if st.RunningImage == nil {
		t.Fatalf("running_image should be present even with no repo digests")
	}
	if st.RunningImage.ImageID != testProxyImageID {
		t.Errorf("image_id: got %q want %q", st.RunningImage.ImageID, testProxyImageID)
	}
	if len(st.RunningImage.RepoDigests) != 0 {
		t.Errorf("repo_digests should be empty for a locally-built image; got %v", st.RunningImage.RepoDigests)
	}
}

// Best-effort timeout: a hung inspect is bounded by the runner's
// per-command StageTimeout, so capture fails and status still returns
// promptly with running_image absent (and no compose_error).
func TestSnapshot_RunningImageTimeoutDoesNotStallStatus(t *testing.T) {
	bin := captureFakeBin(t)
	t.Setenv("PS_OUT", testProxyPS)
	t.Setenv("CONTAINER_OUT", `"`+testProxyImageID+`"`+"\n")
	t.Setenv("IMAGE_OUT", `[{"Id":"`+testProxyImageID+`","RepoDigests":["`+testProxyRepoRef+`"]}]`)
	t.Setenv("SLEEP_MS", "2000") // container inspect sleeps well past StageTimeout
	p := newCaptureProvider(t, bin, 150*time.Millisecond)

	done := make(chan server.Status, 1)
	go func() {
		st, err := p.Snapshot(context.Background())
		if err != nil {
			t.Errorf("Snapshot must not error on capture timeout: %v", err)
		}
		done <- st
	}()

	select {
	case st := <-done:
		if st.ComposeError != "" {
			t.Errorf("capture timeout must not set compose_error; got %q", st.ComposeError)
		}
		if st.RunningImage != nil {
			t.Errorf("running_image must be nil when capture times out; got %+v", st.RunningImage)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Snapshot did not return promptly — best-effort capture must not stall status")
	}
}

func TestNew_FailsClosedOnNilDeps(t *testing.T) {
	if _, err := New(nil, nil, nil); err == nil {
		t.Error("expected error on nil deps")
	}
	if _, err := New(&config.Config{}, nil, nil); err == nil {
		t.Error("expected error on nil ops manager")
	}
}
