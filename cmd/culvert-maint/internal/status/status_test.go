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
		EnvAllow:          []string{"FAKE_STDOUT", "FAKE_STDERR", "FAKE_EXIT"},
		DockerBinary:      bin,
		SudoBinary:        bin,
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
		`{"Name":"culvert","Service":"proxy","State":"running","Image":"ghcr.io/kidcarmi/culvert:latest"}`+"\n"+
			`{"Name":"culvert-clamav","Service":"clamav","State":"running","Image":"clamav/clamav:1.4"}`+"\n",
	)
	p := newProvider(t, bin, config.PrivilegeSudoers)

	st, err := p.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if !st.ComposeStackUp {
		t.Errorf("compose_stack_up should be true when a service is running")
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

func TestNew_FailsClosedOnNilDeps(t *testing.T) {
	if _, err := New(nil, nil, nil); err == nil {
		t.Error("expected error on nil deps")
	}
	if _, err := New(&config.Config{}, nil, nil); err == nil {
		t.Error("expected error on nil ops manager")
	}
}
