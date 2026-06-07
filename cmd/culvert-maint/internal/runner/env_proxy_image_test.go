package runner

import (
	"context"
	"os/exec"
	"testing"
	"time"
)

// P1.4 removed CULVERT_PROXY_IMAGE: the proxy image is no longer selected by
// an env var (it is bound at the sudo boundary via a repo-bound docker
// pull + retag, see templates_apply_test.go). The tests that remain here
// cover the still-live overlay-only env mechanism via the one remaining
// overlay-only var, CULVERT_BACKUP_PASSPHRASE (encrypted backup/restore).

// captureRunner builds a Runner with a fake exec layer that records the
// child argv + env, wired with the given EnvAllow / EnvOverlayOnly sets.
func captureRunner(t *testing.T, capE *capturedExec, envAllow, overlayOnly []string) *Runner {
	t.Helper()
	r, err := New(Options{
		ComposeProjectDir: "/srv/culvert",
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      5 * time.Second,
		EnvAllow:          envAllow,
		EnvOverlayOnly:    overlayOnly,
		DockerBinary:      "/usr/bin/docker",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	r.execStartFn = func(cmd *exec.Cmd) error {
		capE.Argv = append([]string(nil), cmd.Args...)
		capE.Env = append([]string(nil), cmd.Env...)
		return nil
	}
	r.execWaitFn = func(_ *exec.Cmd) error { return nil }
	return r
}

// prodEnvRunner mirrors main's wiring after P1.4: CULVERT_BACKUP_PASSPHRASE
// is the only allowlisted env var, and it is overlay-only.
func prodEnvRunner(t *testing.T, capE *capturedExec) *Runner {
	return captureRunner(t, capE,
		[]string{EnvCulvertBackupPassphrase},
		[]string{EnvCulvertBackupPassphrase})
}

// Overlay-only (production wiring): an ambient CULVERT_BACKUP_PASSPHRASE in
// the AGENT's own process env must NEVER leak onto a command that did not
// explicitly overlay it (e.g. pull/tag/up/ps/inspect). This is the
// runner-side complement to the command-scoped sudoers env_keep.
func TestEnvCulvertBackupPassphrase_AmbientValueNeverLeaks_WhenOverlayOnly(t *testing.T) {
	t.Setenv(EnvCulvertBackupPassphrase, "super-secret-ambient")
	capE := &capturedExec{}
	r := prodEnvRunner(t, capE)
	// A plain compose `up -d` (the apply/rollback restart) carries NO
	// overlay — the ambient passphrase must not ride along.
	if _, err := r.runWithEnv(context.Background(),
		[]string{"/usr/bin/docker", "compose", "up", "-d"}, nil); err != nil {
		t.Fatalf("runWithEnv: %v", err)
	}
	if capE.HasEnvName(EnvCulvertBackupPassphrase) {
		t.Errorf("overlay-only passphrase must NEVER be sourced from the agent's ambient env; child env=%v", capE.Env)
	}
}

// The encrypted backup/restore path still works under overlay-only: an
// explicit passphrase overlay is forwarded to the child.
func TestEnvCulvertBackupPassphrase_ForwardedViaOverlay_WhenOverlayOnly(t *testing.T) {
	t.Setenv(EnvCulvertBackupPassphrase, "ambient-should-be-ignored")
	capE := &capturedExec{}
	r := prodEnvRunner(t, capE)
	if _, err := r.runWithEnv(context.Background(),
		[]string{"/usr/bin/docker", "compose", "run", "--rm", "-e", EnvCulvertBackupPassphrase, "cli", "--encrypt", "--backup", "/backup/x"},
		map[string]string{EnvCulvertBackupPassphrase: "explicit-overlay-value"}); err != nil {
		t.Fatalf("runWithEnv: %v", err)
	}
	if !capE.HasEnv(EnvCulvertBackupPassphrase, "explicit-overlay-value") {
		t.Errorf("explicit passphrase overlay must be forwarded (encrypted backup/restore path); env=%v", capE.Env)
	}
}

// EnvOverlayOnly names must be a subset of EnvAllow — New rejects a stray
// overlay-only name.
func TestEnvOverlayOnly_MustBeSubsetOfEnvAllow(t *testing.T) {
	_, err := New(Options{
		ComposeProjectDir: "/srv/culvert",
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      5 * time.Second,
		EnvAllow:          []string{EnvCulvertBackupPassphrase},
		EnvOverlayOnly:    []string{"CULVERT_UNLISTED_VAR"}, // not in EnvAllow
		DockerBinary:      "/usr/bin/docker",
	})
	if err == nil {
		t.Fatal("New must reject an EnvOverlayOnly name that is not in EnvAllow")
	}
}

// Contrast: a NORMAL (non-overlay-only) allowlisted var still falls back to
// the ambient env — proving overlay-only is what suppresses the leak, not a
// blanket change to env forwarding.
func TestEnvOverlayOnly_NormalVarStillFallsBackToAmbient(t *testing.T) {
	t.Setenv(EnvCulvertBackupPassphrase, "ambient-value")
	capE := &capturedExec{}
	// Passphrase allowlisted but NOT overlay-only.
	r := captureRunner(t, capE, []string{EnvCulvertBackupPassphrase}, nil)
	if _, err := r.runWithEnv(context.Background(),
		[]string{"/usr/bin/docker", "compose", "ps"}, nil); err != nil {
		t.Fatalf("runWithEnv: %v", err)
	}
	if !capE.HasEnv(EnvCulvertBackupPassphrase, "ambient-value") {
		t.Errorf("a non-overlay-only allowlisted var should still fall back to ambient; env=%v", capE.Env)
	}
}

// Read-only inspect paths suppress the passphrase (no use for it) even
// though the var is allowlisted.
func TestEnvCulvertBackupPassphrase_ReadOnlyInspectSuppressed(t *testing.T) {
	t.Setenv(EnvCulvertBackupPassphrase, "ambient")
	capE := &capturedExec{}
	r := prodEnvRunner(t, capE)
	if _, err := r.ComposeImageInspect(context.Background(), "ghcr.io/kidcarmi/culvert:v1"); err != nil {
		t.Fatalf("ComposeImageInspect: %v", err)
	}
	if capE.HasEnvName(EnvCulvertBackupPassphrase) {
		t.Errorf("read-only image inspect must suppress %s; env=%v", EnvCulvertBackupPassphrase, capE.Env)
	}
}
