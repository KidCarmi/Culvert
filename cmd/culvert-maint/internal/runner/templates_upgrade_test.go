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

// ─── container inspect (D1.6c capture primitive) ────────────────────

func TestComposeContainerInspect_Argv(t *testing.T) {
	r, capE := d16bRunner(t)
	const cid = "abcdef012345"
	if _, err := r.ComposeContainerInspect(context.Background(), cid); err != nil {
		t.Fatalf("ComposeContainerInspect: %v", err)
	}
	want := []string{
		"/usr/bin/docker", "inspect", "--format", "{{json .Image}}", cid,
	}
	if !reflect.DeepEqual(capE.Argv, want) {
		t.Errorf("argv mismatch.\n  got:  %v\n  want: %v", capE.Argv, want)
	}
	// The format spec must be ONE argv token (with its space intact), not
	// split — that is exactly why the sudoers line double-quotes it.
	if capE.Argv[3] != "{{json .Image}}" {
		t.Errorf("--format value must be a single argv token %q; got %q", "{{json .Image}}", capE.Argv[3])
	}
	if capE.HasEnvName(EnvCulvertBackupPassphrase) {
		t.Errorf("container inspect must not forward the backup passphrase; child env=%v", capE.Env)
	}
}

// A malformed container id must be rejected before any argv is built, so
// sudo/docker is never invoked with a dangerous token.
func TestComposeContainerInspect_RejectsMalformedIDBeforeExec(t *testing.T) {
	r, capE := d16bRunner(t)
	bad := []string{
		"",
		"abc",                   // too short (<12)
		"ABCDEF012345",          // uppercase
		"abcdef01234g",          // non-hex
		"abcdef 012345",         // space
		"-abcdef012345",         // leading dash
		"abcdef012345;rm",       // shell meta
		strings.Repeat("a", 65), // too long (>64)
		"sha256:abcdef012345",   // not a bare hex id
	}
	for _, id := range bad {
		if _, err := r.ComposeContainerInspect(context.Background(), id); err == nil {
			t.Errorf("ComposeContainerInspect(%q) should have errored", id)
		}
	}
	if len(capE.Argv) != 0 {
		t.Errorf("a rejected id must NOT reach exec; captured argv=%v", capE.Argv)
	}
}

func TestValidateContainerIDShape(t *testing.T) {
	good := []string{
		strings.Repeat("a", 12), // short id
		strings.Repeat("0", 64), // full id
		"abcdef0123456789",
		"0123456789ab",
	}
	for _, id := range good {
		if err := validateContainerIDShape(id); err != nil {
			t.Errorf("validateContainerIDShape(%q): want nil, got %v", id, err)
		}
	}
	bad := []string{
		"",
		strings.Repeat("a", 11), // 11 < 12
		strings.Repeat("a", 65), // 65 > 64
		"ABCDEF012345",          // uppercase not allowed
		"abcdefg01234",          // 'g' non-hex
		"abc def01234",          // space
		"abcdef01234-",          // dash
	}
	for _, id := range bad {
		if err := validateContainerIDShape(id); err == nil {
			t.Errorf("validateContainerIDShape(%q) should have errored", id)
		}
	}
}

// The exported wrapper must behave identically to the internal validator.
func TestValidateContainerID_ExportedWrapper(t *testing.T) {
	if err := ValidateContainerID(strings.Repeat("a", 12)); err != nil {
		t.Errorf("ValidateContainerID on a valid id: %v", err)
	}
	if err := ValidateContainerID("nope"); err == nil {
		t.Error("ValidateContainerID must reject a malformed id")
	}
}

// The container-inspect template must be read-only and enumerate one
// fixed-length hex pattern per legal id length (12–64) — never a single
// trailing `*` (which sudo would let match whitespace + extra args). It
// must also keep the format token double-quoted.
func TestContainerInspectTemplate_EnumeratedNoTrailingWildcard(t *testing.T) {
	tmpl := templateByID(TemplateComposeContainerInspect)
	if tmpl == nil {
		t.Fatal("TemplateComposeContainerInspect missing from registry")
	}
	if tmpl.StateChanging {
		t.Error("container inspect template must be read-only")
	}
	wantN := containerIDMaxLen - containerIDMinLen + 1
	if len(tmpl.SudoersLines) != wantN {
		t.Fatalf("container inspect must enumerate %d sudoers lines (lengths %d–%d); got %d",
			wantN, containerIDMinLen, containerIDMaxLen, len(tmpl.SudoersLines))
	}
	for _, line := range tmpl.SudoersLines {
		if strings.Contains(line, "*") {
			t.Errorf("sudoers line must NOT contain a trailing wildcard (sudo `*` matches whitespace): %q", line)
		}
		if !strings.Contains(line, `"{{json .Image}}"`) {
			t.Errorf("sudoers line must double-quote the format token: %q", line)
		}
	}
	// Shortest and longest patterns must carry exactly min/max hex classes.
	first, last := tmpl.SudoersLines[0], tmpl.SudoersLines[wantN-1]
	if got := strings.Count(first, "[0-9a-f]"); got != containerIDMinLen {
		t.Errorf("shortest line: got %d hex classes, want %d", got, containerIDMinLen)
	}
	if got := strings.Count(last, "[0-9a-f]"); got != containerIDMaxLen {
		t.Errorf("longest line: got %d hex classes, want %d", got, containerIDMaxLen)
	}
}
