package runner

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// CULVERT_PROXY_IMAGE is the compose image-override precondition (D1.6c).
// These tests prove it is forwardable ONLY through an explicit env overlay
// (the path the future pull/up will use) and is gated by the closed env
// allowlist — it never leaks to a child process by default, and the
// read-only paths do not carry it.

// proxyEnvRunner builds a Runner with the given EnvAllow and a fake exec
// layer that captures the child argv + env.
func proxyEnvRunner(t *testing.T, capE *capturedExec, envAllow []string) *Runner {
	t.Helper()
	r, err := New(Options{
		ComposeProjectDir: "/srv/culvert",
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      5 * time.Second,
		EnvAllow:          envAllow,
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

func TestEnvCulvertProxyImage_IsValidEnvName(t *testing.T) {
	if !envNameRE.MatchString(EnvCulvertProxyImage) {
		t.Fatalf("EnvCulvertProxyImage %q must be a valid env-var name", EnvCulvertProxyImage)
	}
}

// Intended path: an explicit overlay (what the future pull/up will pass)
// forwards the pinned ref to the child process.
func TestEnvCulvertProxyImage_ForwardedViaOverlay(t *testing.T) {
	capE := &capturedExec{}
	r := proxyEnvRunner(t, capE, []string{EnvCulvertProxyImage})
	ref := "ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("a", 64)
	if _, err := r.runWithEnv(context.Background(),
		[]string{"/usr/bin/docker", "compose", "up", "-d"},
		map[string]string{EnvCulvertProxyImage: ref}); err != nil {
		t.Fatalf("runWithEnv: %v", err)
	}
	if !capE.HasEnv(EnvCulvertProxyImage, ref) {
		t.Errorf("intended overlay path must forward %s=%s; child env=%v", EnvCulvertProxyImage, ref, capE.Env)
	}
}

// Closed-allowlist gate: an overlay carrying the var is REJECTED before
// exec when the var is not in EnvAllow.
func TestEnvCulvertProxyImage_RejectedWhenNotAllowlisted(t *testing.T) {
	capE := &capturedExec{}
	// Only the passphrase is allowed; the proxy-image var is not.
	r := proxyEnvRunner(t, capE, []string{EnvCulvertBackupPassphrase})
	_, err := r.runWithEnv(context.Background(),
		[]string{"/usr/bin/docker", "compose", "up", "-d"},
		map[string]string{EnvCulvertProxyImage: "ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("a", 64)})
	if err == nil {
		t.Fatal("an overlay name outside EnvAllow must be rejected (closed allowlist)")
	}
	if len(capE.Argv) != 0 {
		t.Errorf("a rejected overlay must not reach exec; argv=%v", capE.Argv)
	}
}

// No ambient leak: with the var allowlisted but neither an overlay value
// nor a value in the agent's own process env, it must NOT reach a child.
func TestEnvCulvertProxyImage_NotForwardedWithoutOverlay(t *testing.T) {
	capE := &capturedExec{}
	r := proxyEnvRunner(t, capE, []string{EnvCulvertProxyImage})
	if _, err := r.runWithEnv(context.Background(),
		[]string{"/usr/bin/docker", "compose", "ps"}, nil); err != nil {
		t.Fatalf("runWithEnv: %v", err)
	}
	if capE.HasEnvName(EnvCulvertProxyImage) {
		t.Errorf("must not forward %s when neither overlay nor process env sets it; env=%v", EnvCulvertProxyImage, capE.Env)
	}
}

// A read-only inspect path must not carry the proxy-image override even
// when the var is allowlisted — only the future pull/up overlay should.
func TestEnvCulvertProxyImage_ReadOnlyPathsDoNotForward(t *testing.T) {
	capE := &capturedExec{}
	r := proxyEnvRunner(t, capE, []string{EnvCulvertProxyImage, EnvCulvertBackupPassphrase})
	if _, err := r.ComposeImageInspect(context.Background(), "ghcr.io/kidcarmi/culvert:v1"); err != nil {
		t.Fatalf("ComposeImageInspect: %v", err)
	}
	if capE.HasEnvName(EnvCulvertProxyImage) {
		t.Errorf("read-only image inspect must not forward %s; env=%v", EnvCulvertProxyImage, capE.Env)
	}
}
