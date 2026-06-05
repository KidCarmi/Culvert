package runner

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

const pinnedRef = "ghcr.io/kidcarmi/culvert@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

// ComposePull pulls ONLY the proxy service and forwards the pin via the
// CULVERT_PROXY_IMAGE overlay.
func TestComposePull_ArgvForwardsPin(t *testing.T) {
	capE := &capturedExec{}
	r := proxyEnvRunner(t, capE, []string{EnvCulvertProxyImage})
	if _, err := r.ComposePull(context.Background(), pinnedRef); err != nil {
		t.Fatalf("ComposePull: %v", err)
	}
	want := []string{"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml", "pull", "proxy"}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	if !capE.HasEnv(EnvCulvertProxyImage, pinnedRef) {
		t.Errorf("pull must forward %s=%s; child env=%v", EnvCulvertProxyImage, pinnedRef, capE.Env)
	}
}

// ComposeUpWithImage recreates the stack with the same pinned override.
func TestComposeUpWithImage_ArgvForwardsPin(t *testing.T) {
	capE := &capturedExec{}
	r := proxyEnvRunner(t, capE, []string{EnvCulvertProxyImage})
	if _, err := r.ComposeUpWithImage(context.Background(), pinnedRef); err != nil {
		t.Fatalf("ComposeUpWithImage: %v", err)
	}
	want := []string{"/usr/bin/docker", "compose", "-f", "/srv/culvert/docker-compose.yml", "up", "-d"}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	if !capE.HasEnv(EnvCulvertProxyImage, pinnedRef) {
		t.Errorf("up must forward %s=%s; child env=%v", EnvCulvertProxyImage, pinnedRef, capE.Env)
	}
}

// Plain ComposeUp (used by restore) must NOT carry the proxy-image
// override — the pin is exclusive to the apply path.
func TestComposeUp_DoesNotForwardPin(t *testing.T) {
	capE := &capturedExec{}
	r := proxyEnvRunner(t, capE, []string{EnvCulvertProxyImage})
	if _, err := r.ComposeUp(context.Background()); err != nil {
		t.Fatalf("ComposeUp: %v", err)
	}
	if capE.HasEnvName(EnvCulvertProxyImage) {
		t.Errorf("plain ComposeUp must not forward %s; env=%v", EnvCulvertProxyImage, capE.Env)
	}
}

func TestComposePull_RejectsMalformedRefBeforeExec(t *testing.T) {
	capE := &capturedExec{}
	r := proxyEnvRunner(t, capE, []string{EnvCulvertProxyImage})
	for _, bad := range []string{"", "-rf", "has space", "x;rm -rf /", strings.Repeat("a", 513)} {
		if _, err := r.ComposePull(context.Background(), bad); err == nil {
			t.Errorf("ComposePull(%q) should have errored", bad)
		}
		if _, err := r.ComposeUpWithImage(context.Background(), bad); err == nil {
			t.Errorf("ComposeUpWithImage(%q) should have errored", bad)
		}
	}
	if len(capE.Argv) != 0 {
		t.Errorf("a rejected ref must NOT reach exec; argv=%v", capE.Argv)
	}
}

// The pull template is state-changing with exactly one path-bound,
// service-scoped sudoers line (no wildcard).
func TestComposePullTemplate_Shape(t *testing.T) {
	tmpl := templateByID(TemplateComposePull)
	if tmpl == nil {
		t.Fatal("TemplateComposePull missing from registry")
	}
	if !tmpl.StateChanging {
		t.Error("pull template must be state-changing")
	}
	if len(tmpl.SudoersLines) != 1 {
		t.Fatalf("pull must have exactly one sudoers line; got %d", len(tmpl.SudoersLines))
	}
	if strings.Contains(tmpl.SudoersLines[0], "*") {
		t.Errorf("pull sudoers line must not contain a wildcard (proxy is a fixed literal): %q", tmpl.SudoersLines[0])
	}
}
