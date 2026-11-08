package runner

import (
	"context"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

var pinnedRef = "ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("c", 64)

// ComposePullDigest pulls a repo-bound pinned digest as raw `docker pull`,
// carrying the ref in ARGV (not an env var).
func TestComposePullDigest_Argv(t *testing.T) {
	capE := &capturedExec{}
	r := captureRunner(t, capE, nil, nil)
	if _, err := r.ComposePullDigest(context.Background(), pinnedRef); err != nil {
		t.Fatalf("ComposePullDigest: %v", err)
	}
	want := []string{"/usr/bin/docker", "pull", pinnedRef}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	// No env-based image selection: the proxy-image var no longer exists.
	for _, e := range capE.Env {
		if strings.Contains(e, "PROXY_IMAGE") {
			t.Errorf("pull must not forward any *PROXY_IMAGE* env; got %q", e)
		}
	}
}

// ComposeTagPinned retags the pulled digest to the FIXED local tag.
func TestComposeTagPinned_Argv(t *testing.T) {
	capE := &capturedExec{}
	r := captureRunner(t, capE, nil, nil)
	if _, err := r.ComposeTagPinned(context.Background(), pinnedRef); err != nil {
		t.Fatalf("ComposeTagPinned: %v", err)
	}
	want := []string{"/usr/bin/docker", "tag", pinnedRef, "culvert/proxy:pinned"}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
}

// The pinned destination is a fixed literal: ComposeTagPinned never lets the
// caller choose the tag.
func TestComposeTagPinned_DestinationIsFixedLiteral(t *testing.T) {
	if pinnedProxyTag != "culvert/proxy:pinned" {
		t.Fatalf("pinnedProxyTag must be the fixed literal culvert/proxy:pinned; got %q", pinnedProxyTag)
	}
}

// Repo-bound + exact-digest validation: a foreign repo, a tag, a short/long
// digest, or a malformed ref is rejected BEFORE exec, for both methods.
func TestPinnedDigestRef_RejectedBeforeExec(t *testing.T) {
	capE := &capturedExec{}
	r := captureRunner(t, capE, nil, nil) // default proxyRepo ghcr.io/kidcarmi/culvert
	hex64 := strings.Repeat("a", 64)
	bad := []string{
		"",
		"-rf",
		"has space",
		"ghcr.io/kidcarmi/culvert:v1.2.3",      // tag, not a digest
		"ghcr.io/evil/culvert@sha256:" + hex64, // foreign repo
		"docker.io/library/nginx@sha256:" + hex64,                    // foreign repo
		"ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("a", 63), // 63 hex (short)
		"ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("a", 65), // 65 hex (long)
		"ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("A", 64), // uppercase hex
		"ghcr.io/kidcarmi/culvert:latest@sha256:" + hex64,            // tag+digest
	}
	for _, ref := range bad {
		if _, err := r.ComposePullDigest(context.Background(), ref); err == nil {
			t.Errorf("ComposePullDigest(%q) should have errored", ref)
		}
		if _, err := r.ComposeTagPinned(context.Background(), ref); err == nil {
			t.Errorf("ComposeTagPinned(%q) should have errored", ref)
		}
	}
	if len(capE.Argv) != 0 {
		t.Errorf("a rejected ref must NOT reach exec; argv=%v", capE.Argv)
	}
}

// A correctly repo-bound digest of the configured repo is accepted.
func TestPinnedDigestRef_AcceptsRepoBoundDigest(t *testing.T) {
	capE := &capturedExec{}
	r := captureRunner(t, capE, nil, nil)
	good := "ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("0", 64)
	if _, err := r.ComposePullDigest(context.Background(), good); err != nil {
		t.Errorf("ComposePullDigest(%q) should be accepted: %v", good, err)
	}
}

// Both P1.4 templates are state-changing and, in sudo mode, run through the
// compose-cli wrapper's `pull` / `tag` subcommands. Their only sudoers line is
// the bare wrapper rule: the old `{proxy_repo}@sha256\:[0-9a-f]…` patterns
// parse under sudo-rs but never match (it compares arguments literally), so
// the repo literal and 64-hex digest are enforced by the wrapper instead
// (TestWrapper_PinnedPullTag* in wrapper_test.go).
func TestPinTemplates_Shape(t *testing.T) {
	wantWrapper := map[TemplateID]string{TemplateImagePullDigest: "pull", TemplateImageTagPinned: "tag"}
	for id, sub := range wantWrapper {
		tmpl := templateByID(id)
		if tmpl == nil {
			t.Fatalf("template %q missing from registry", id)
		}
		if !tmpl.StateChanging {
			t.Errorf("template %q must be state-changing", id)
		}
		if len(tmpl.WrapperArgv) != 1 || tmpl.WrapperArgv[0] != sub {
			t.Errorf("template %q must route through the wrapper subcommand %q; got %q", id, sub, tmpl.WrapperArgv)
		}
		if len(tmpl.SudoersLines) != 1 || tmpl.SudoersLines[0] != ComposeCLIWrapperPath {
			t.Errorf("template %q must declare exactly the wrapper sudoers line %q; got %q", id, ComposeCLIWrapperPath, tmpl.SudoersLines)
		}
	}
}

// In sudo mode the pinned pull/tag argv is `sudo -n <wrapper> pull|tag …` with
// the SAME positional tail as the direct docker form; without sudo it is the
// raw docker command (docker_group_lab is unchanged).
func TestPinTemplates_SudoArgvUsesWrapper(t *testing.T) {
	ref := "ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("ab", 32)
	for _, useSudo := range []bool{true, false} {
		r, rec := recordingRunner(t, useSudo)
		if _, err := r.ComposePullDigest(context.Background(), ref); err != nil {
			t.Fatalf("ComposePullDigest: %v", err)
		}
		if _, err := r.ComposeTagPinned(context.Background(), ref); err != nil {
			t.Fatalf("ComposeTagPinned: %v", err)
		}
		var want [][]string
		if useSudo {
			want = [][]string{
				{"sudo", "-n", ComposeCLIWrapperPath, "pull", ref},
				{"sudo", "-n", ComposeCLIWrapperPath, "tag", ref, pinnedProxyTag},
			}
		} else {
			want = [][]string{
				{"/usr/bin/docker", "pull", ref},
				{"/usr/bin/docker", "tag", ref, pinnedProxyTag},
			}
		}
		if !reflect.DeepEqual(rec.argvs, want) {
			t.Errorf("useSudo=%v argv:\n got %q\nwant %q", useSudo, rec.argvs, want)
		}
	}
}

// argvRecorder captures every exec'd argv and env, in call order.
type argvRecorder struct {
	argvs [][]string
	envs  [][]string
}

// recordingRunner is a Runner whose exec layer only records, with sudo on or
// off. CULVERT_BACKUP_PASSPHRASE is allowlisted (not overlay-only), so an
// ambient value would reach the child unless the template suppresses it.
func recordingRunner(t *testing.T, useSudo bool) (*Runner, *argvRecorder) {
	t.Helper()
	r, err := New(Options{
		ComposeProjectDir: "/srv/culvert",
		ComposeFile:       "docker-compose.yml",
		StageTimeout:      5 * time.Second,
		EnvAllow:          []string{EnvCulvertBackupPassphrase},
		DockerBinary:      "/usr/bin/docker",
		UseSudo:           useSudo,
		SudoBinary:        "sudo",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	rec := &argvRecorder{}
	r.execStartFn = func(cmd *exec.Cmd) error {
		rec.argvs = append(rec.argvs, append([]string(nil), cmd.Args...))
		rec.envs = append(rec.envs, append([]string(nil), cmd.Env...))
		return nil
	}
	r.execWaitFn = func(_ *exec.Cmd) error { return nil }
	return r, rec
}
