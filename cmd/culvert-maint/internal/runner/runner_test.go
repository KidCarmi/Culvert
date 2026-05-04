package runner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeBin builds a tiny helper that prints its argv and env, then exits.
// Used by tests to inspect what the runner actually exec's. Built once
// per test binary and cached via testing.T's parallel tree.
func fakeBin(t *testing.T) string {
	t.Helper()
	src := `package main
import (
	"fmt"
	"os"
)
func main() {
	for _, a := range os.Args { fmt.Println("ARG:" + a) }
	for _, e := range os.Environ() { fmt.Println("ENV:" + e) }
	if v := os.Getenv("FAKE_STDOUT"); v != "" { fmt.Print(v) }
	if v := os.Getenv("FAKE_STDERR"); v != "" { fmt.Fprint(os.Stderr, v) }
	if rc := os.Getenv("FAKE_EXIT"); rc != "" {
		switch rc {
		case "1": os.Exit(1)
		case "2": os.Exit(2)
		}
	}
	if os.Getenv("FAKE_SLEEP") == "yes" {
		select {} // block forever; runner timeout must fire
	}
}
`
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "main.go")
	if err := os.WriteFile(srcPath, []byte(src), 0o600); err != nil {
		t.Fatalf("write helper main.go: %v", err)
	}
	binPath := filepath.Join(dir, "argvprint")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-o", binPath, srcPath) //nolint:gosec // fixed argv to go toolchain in test temp dir
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build helper: %v\n%s", err, string(out))
	}
	return binPath
}

func TestRun_ArgvAndCwdPropagated(t *testing.T) {
	bin := fakeBin(t)
	dir := t.TempDir()
	r, err := New(Options{
		ComposeProjectDir: dir,
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      10 * time.Second,
		DockerBinary:      bin,
		SudoBinary:        bin,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := r.ComposeStatus(context.Background())
	if err != nil {
		t.Fatalf("ComposeStatus: %v", err)
	}
	out := string(res.Stdout)
	expectedComposePath := dir + "/docker-compose.yml"
	for _, want := range []string{
		"ARG:" + bin,
		"ARG:compose",
		"ARG:-f",
		"ARG:" + expectedComposePath, // full path, not bare filename
		"ARG:ps",
		"ARG:--format",
		"ARG:json",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in argv output:\n%s", want, out)
		}
	}
	// Sudoers is path-bound: the bare filename must NOT appear by itself
	// as an argv entry. (`docker-compose.yml` would match a path-loose
	// sudoers rule; the full path must.)
	if strings.Contains(out, "ARG:docker-compose.yml\n") {
		t.Errorf("argv contains bare compose filename — sudoers rule would not be path-bound:\n%s", out)
	}
	for _, banned := range []string{"ARG:sh", "ARG:bash", "ARG:-c"} {
		if strings.Contains(out, banned) {
			t.Errorf("argv should not contain shell artifact %q:\n%s", banned, out)
		}
	}
	if !strings.Contains(out, "ENV:PATH=") {
		t.Errorf("env should include PATH default")
	}
}

func TestRun_EnvAllowlistOnly(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("CULVERT_BACKUP_PASSPHRASE", "should-be-forwarded")
	t.Setenv("UNSAFE_OPERATOR_VAR", "should-NOT-be-forwarded")

	r, _ := New(Options{
		ComposeProjectDir: t.TempDir(),
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      10 * time.Second,
		EnvAllow:          []string{"CULVERT_BACKUP_PASSPHRASE"},
		DockerBinary:      bin,
		SudoBinary:        bin,
	})
	res, err := r.ComposeStatus(context.Background())
	if err != nil {
		t.Fatalf("ComposeStatus: %v", err)
	}
	out := string(res.Stdout)
	if !strings.Contains(out, "ENV:CULVERT_BACKUP_PASSPHRASE=should-be-forwarded") {
		t.Errorf("allowlisted env not forwarded: %s", out)
	}
	if strings.Contains(out, "ENV:UNSAFE_OPERATOR_VAR=") {
		t.Errorf("non-allowlisted env leaked: %s", out)
	}
}

func TestRun_BoundedOutput(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_STDOUT", strings.Repeat("X", 5_000))
	r, _ := New(Options{
		ComposeProjectDir: t.TempDir(),
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      10 * time.Second,
		EnvAllow:          []string{"FAKE_STDOUT"},
		CaptureMax:        1024,
		DockerBinary:      bin,
		SudoBinary:        bin,
	})
	res, err := r.ComposeStatus(context.Background())
	if err != nil {
		t.Fatalf("ComposeStatus: %v", err)
	}
	if !res.Truncated {
		t.Errorf("expected Truncated=true when stdout exceeds CaptureMax")
	}
	if len(res.Stdout) > 1024 {
		t.Errorf("captured stdout exceeds cap: %d", len(res.Stdout))
	}
}

func TestRun_TimeoutKillsCommand(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_SLEEP", "yes")
	r, _ := New(Options{
		ComposeProjectDir: t.TempDir(),
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      200 * time.Millisecond,
		EnvAllow:          []string{"FAKE_SLEEP"},
		DockerBinary:      bin,
		SudoBinary:        bin,
	})
	start := time.Now()
	_, err := r.ComposeStatus(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	// Either runner-detected timeout or wait-error from kernel signal — both acceptable.
	if elapsed > 10*time.Second {
		t.Errorf("timeout took too long: %s", elapsed)
	}
}

func TestRun_NonZeroExit(t *testing.T) {
	bin := fakeBin(t)
	t.Setenv("FAKE_EXIT", "2")
	r, _ := New(Options{
		ComposeProjectDir: t.TempDir(),
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      10 * time.Second,
		EnvAllow:          []string{"FAKE_EXIT"},
		DockerBinary:      bin,
		SudoBinary:        bin,
	})
	res, err := r.ComposeStatus(context.Background())
	if err == nil {
		t.Fatal("expected error for non-zero exit")
	}
	if res.ExitCode != 2 {
		t.Errorf("ExitCode: got %d want 2", res.ExitCode)
	}
}

func TestRun_SudoPrependedWhenUseSudo(t *testing.T) {
	bin := fakeBin(t)
	r, _ := New(Options{
		ComposeProjectDir: t.TempDir(),
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      10 * time.Second,
		UseSudo:           true,
		DockerBinary:      bin,
		SudoBinary:        bin,
	})
	res, err := r.ComposeStatus(context.Background())
	if err != nil {
		t.Fatalf("ComposeStatus: %v", err)
	}
	out := string(res.Stdout)
	if !strings.Contains(out, "ARG:-n") {
		t.Errorf("expected -n flag for sudo non-interactive, got:\n%s", out)
	}
}

func TestNew_FailsClosedOnInvalidOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
	}{
		{"empty ComposeProjectDir", Options{ComposeProjectDir: "", ComposeFile: "x", StageTimeout: time.Second}},
		{"relative ComposeProjectDir", Options{ComposeProjectDir: "relative/path", ComposeFile: "y", StageTimeout: time.Second}},
		{"empty ComposeFile", Options{ComposeProjectDir: "/x", ComposeFile: "", StageTimeout: time.Second}},
		{"ComposeFile with slash", Options{ComposeProjectDir: "/x", ComposeFile: "sub/compose.yml", StageTimeout: time.Second}},
		{"ComposeFile with backslash", Options{ComposeProjectDir: "/x", ComposeFile: `sub\compose.yml`, StageTimeout: time.Second}},
		{"ComposeFile traversal", Options{ComposeProjectDir: "/x", ComposeFile: "../etc/passwd", StageTimeout: time.Second}},
		{"zero StageTimeout", Options{ComposeProjectDir: "/x", ComposeFile: "y", StageTimeout: 0}},
		{"negative CaptureMax", Options{ComposeProjectDir: "/x", ComposeFile: "y", StageTimeout: time.Second, CaptureMax: -1}},
		{"env name with =", Options{ComposeProjectDir: "/x", ComposeFile: "y", StageTimeout: time.Second, EnvAllow: []string{"BAD=NAME"}}},
		{"env name lowercase", Options{ComposeProjectDir: "/x", ComposeFile: "y", StageTimeout: time.Second, EnvAllow: []string{"bad_name"}}},
		{"env name with newline", Options{ComposeProjectDir: "/x", ComposeFile: "y", StageTimeout: time.Second, EnvAllow: []string{"BAD\nNAME"}}},
		{"env name leading digit", Options{ComposeProjectDir: "/x", ComposeFile: "y", StageTimeout: time.Second, EnvAllow: []string{"1BAD"}}},
	}
	for _, c := range cases {
		_, err := New(c.opts)
		if err == nil {
			t.Errorf("%s: expected error, got nil", c.name)
		}
	}
}

func TestBuildEnv_DeterministicOrder(t *testing.T) {
	t.Setenv("ZZ_TAIL", "z")
	t.Setenv("AA_HEAD", "a")
	t.Setenv("MM_MID", "m")
	r, err := New(Options{
		ComposeProjectDir: "/srv/x",
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      time.Second,
		EnvAllow:          []string{"MM_MID", "AA_HEAD", "ZZ_TAIL"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := r.buildEnv()
	if len(got) < 7 {
		t.Fatalf("got %d entries, want >=7", len(got))
	}
	// Defaults always first in fixed order.
	wantPrefix := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=/var/lib/culvert-maint",
		"LANG=C.UTF-8",
		"TZ=UTC",
	}
	for i, want := range wantPrefix {
		if got[i] != want {
			t.Errorf("env[%d]: got %q want %q", i, got[i], want)
		}
	}
	// EnvAllow alphabetised after defaults.
	wantTail := []string{"AA_HEAD=a", "MM_MID=m", "ZZ_TAIL=z"}
	for i, want := range wantTail {
		idx := len(wantPrefix) + i
		if got[idx] != want {
			t.Errorf("env[%d]: got %q want %q", idx, got[idx], want)
		}
	}
}

func TestRegistry_ContainsComposeStatusD16a(t *testing.T) {
	// D1.6b registry must still include compose.status (read-only,
	// drives /v1/status). The closed-set assertion across all D1.6b
	// templates lives in TestParity_D16bRegistryShape.
	var found *Template
	for _, tmpl := range Registry() {
		if tmpl.ID == TemplateComposeStatus {
			t := tmpl
			found = &t
			break
		}
	}
	if found == nil {
		t.Fatalf("Registry must include %q", TemplateComposeStatus)
	}
	if found.StateChanging {
		t.Errorf("compose.status must not be state-changing")
	}
	if len(found.SudoersLines) != 1 {
		t.Errorf("compose.status must have exactly one sudoers line; got %d", len(found.SudoersLines))
	}
}

func TestBoundedBuffer_Truncates(t *testing.T) {
	b := newBoundedBuffer(8)
	n, _ := b.Write([]byte("hello"))
	if n != 5 || b.Truncated() {
		t.Errorf("first write under cap should not truncate; n=%d truncated=%v", n, b.Truncated())
	}
	n2, _ := b.Write([]byte("world!!!"))
	if n2 != 8 || !b.Truncated() {
		t.Errorf("second write should mark truncated; n2=%d truncated=%v", n2, b.Truncated())
	}
	if got := b.String(); got != "hellowor" {
		t.Errorf("buffer body: got %q want %q", got, "hellowor")
	}
}

func TestFormatStringForFlow_StripsControl(t *testing.T) {
	got := FormatStringForFlow("hello\nworld\rsneaky\x00")
	if got != "helloworldsneaky" {
		t.Errorf("got %q", got)
	}
}
