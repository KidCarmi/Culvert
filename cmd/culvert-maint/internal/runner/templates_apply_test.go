package runner

import (
	"context"
	"reflect"
	"strings"
	"testing"
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

// Both P1.4 templates are state-changing with exactly one sudoers line each:
// a repo-LITERAL ({proxy_repo}) + a 64-class hex digest with NO wildcard,
// and the tag's destination is the fixed literal.
func TestPinTemplates_Shape(t *testing.T) {
	for _, id := range []TemplateID{TemplateImagePullDigest, TemplateImageTagPinned} {
		tmpl := templateByID(id)
		if tmpl == nil {
			t.Fatalf("template %q missing from registry", id)
		}
		if !tmpl.StateChanging {
			t.Errorf("template %q must be state-changing", id)
		}
		if len(tmpl.SudoersLines) != 1 {
			t.Fatalf("template %q must have exactly one sudoers line; got %d", id, len(tmpl.SudoersLines))
		}
		line := tmpl.SudoersLines[0]
		if strings.Contains(line, "*") {
			t.Errorf("template %q sudoers line must contain NO wildcard (repo is a literal, digest is enumerated): %q", id, line)
		}
		if !strings.Contains(line, "{proxy_repo}@sha256:") {
			t.Errorf("template %q sudoers line must bind the {proxy_repo} literal + @sha256: digest: %q", id, line)
		}
		if n := strings.Count(line, "[0-9a-f]"); n != pinnedDigestHexLen {
			t.Errorf("template %q digest must be exactly %d [0-9a-f] classes; got %d", id, pinnedDigestHexLen, n)
		}
	}
	tag := templateByID(TemplateImageTagPinned)
	if !strings.HasSuffix(tag.SudoersLines[0], " culvert/proxy:pinned") {
		t.Errorf("tag sudoers line must end with the fixed destination culvert/proxy:pinned: %q", tag.SudoersLines[0])
	}
}
