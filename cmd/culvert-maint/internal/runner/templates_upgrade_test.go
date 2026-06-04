package runner

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// ─── argv-shape tests (exact match per template) ────────────────────

func TestComposeImageInspect_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeImageInspect(context.Background(), "ghcr.io/kidcarmi/culvert:v1.2.3"); err != nil {
		t.Fatalf("ComposeImageInspect: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "image", "inspect",
		"ghcr.io/kidcarmi/culvert:v1.2.3",
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	if capE.HasEnvName(EnvCulvertBackupPassphrase) {
		t.Errorf("image inspect must not forward the backup passphrase; child env=%v", capE.Env)
	}
}

func TestComposeManifestInspect_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	if _, err := r.ComposeManifestInspect(context.Background(), "ghcr.io/kidcarmi/culvert:v1.2.3"); err != nil {
		t.Fatalf("ComposeManifestInspect: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "manifest", "inspect", "--verbose",
		"ghcr.io/kidcarmi/culvert:v1.2.3",
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	if capE.HasEnvName(EnvCulvertBackupPassphrase) {
		t.Errorf("manifest inspect must not forward the backup passphrase; child env=%v", capE.Env)
	}
}

// The image_ref is the single variable argv token. The runner rejects a
// malformed ref before building argv, so sudo is never invoked with a
// dangerous token even if a handler-level allowlist were misconfigured.
func TestImageInspect_RejectsMalformedRefBeforeExec(t *testing.T) {
	r, capE := d16bRunner(t)
	bad := []string{
		"",
		"-rf",                    // leading dash → flag injection
		"ghcr.io/x culvert:v1",   // space
		"ghcr.io/x;rm -rf /",     // shell meta
		"ghcr.io/x$(id)",         // shell expansion
		"ghcr.io/x`whoami`",      // backtick
		"ghcr.io/x\nculvert",     // newline
		"ghcr.io/x|cat",          // pipe
		"ghcr.io/x*",             // glob
		strings.Repeat("a", 513), // over length bound
	}
	for _, ref := range bad {
		if _, err := r.ComposeImageInspect(context.Background(), ref); err == nil {
			t.Errorf("ComposeImageInspect(%q) should have errored", ref)
		}
		if _, err := r.ComposeManifestInspect(context.Background(), ref); err == nil {
			t.Errorf("ComposeManifestInspect(%q) should have errored", ref)
		}
	}
	if len(capE.Argv) != 0 {
		t.Errorf("a rejected ref must NOT reach exec; captured argv=%v", capE.Argv)
	}
}

// ─── validator tests ────────────────────────────────────────────────

func TestValidateImageRefShape_Rejects(t *testing.T) {
	bad := []string{
		"",
		".leading-dot",
		"-leading-dash",
		"has space",
		"has\ttab",
		"has\nnewline",
		"semi;colon",
		"pipe|x",
		"amp&x",
		"glob*",
		"question?",
		"redir>x",
		"dollar$x",
		"back`tick`",
		"quote\"x",
		"squote'x",
		"back\\slash",
		strings.Repeat("a", 513),
	}
	for _, ref := range bad {
		if err := validateImageRefShape(ref); err == nil {
			t.Errorf("validateImageRefShape(%q) should have errored", ref)
		}
	}
}

func TestValidateImageRefShape_Accepts(t *testing.T) {
	good := []string{
		"ghcr.io/kidcarmi/culvert:v1.2.3",
		"ghcr.io/kidcarmi/culvert@sha256:" + strings.Repeat("a", 64),
		"ghcr.io/kidcarmi/culvert:latest",
		"registry.example.com:5000/team/app:1.0.0-rc.1",
		"alpine",
		strings.Repeat("a", 512),
	}
	for _, ref := range good {
		if err := validateImageRefShape(ref); err != nil {
			t.Errorf("validateImageRefShape(%q): want nil, got %v", ref, err)
		}
	}
}

// The exported wrapper must behave identically to the internal validator.
func TestValidateImageRef_ExportedWrapper(t *testing.T) {
	if err := ValidateImageRef("ghcr.io/kidcarmi/culvert:v1"); err != nil {
		t.Errorf("ValidateImageRef on a valid ref: %v", err)
	}
	if err := ValidateImageRef("-bad"); err == nil {
		t.Error("ValidateImageRef must reject a flag-like ref")
	}
}

// Both inspect templates must be read-only and carry exactly one
// sudoers line (one bounded image_ref wildcard). A template that flips
// to state-changing or grows extra allowlist surface is a review block.
func TestImageInspectTemplates_ReadOnlySingleLine(t *testing.T) {
	for _, id := range []TemplateID{TemplateComposeImageInspect, TemplateComposeManifestInspect} {
		tmpl := templateByID(id)
		if tmpl == nil {
			t.Fatalf("template %q missing from registry", id)
		}
		if tmpl.StateChanging {
			t.Errorf("template %q must be read-only", id)
		}
		if len(tmpl.SudoersLines) != 1 {
			t.Errorf("template %q must have exactly one sudoers line; got %d", id, len(tmpl.SudoersLines))
		}
	}
}
