package main

// install_script_compose_command_flags_scope_test.go — regression coverage
// for the compose_command_flags() helper in scripts/install.sh.
//
// preflight_compose_image_compat() (§6c, added in f5d827f "install: only
// deploy published images; fix latest-tag resolution; add compose↔image
// preflight") uses compose_command_flags() to collect the culvert flags
// baked into docker-compose.yml's proxy `command: [...]` array, then diffs
// them against the flags the seeded image's binary actually defines
// (image_supported_flags(), via `culvert -help`). Any flag present in
// compose but absent from the image is treated as a fatal compose↔binary
// mismatch: install.sh backs up docker-compose.yml to docker-compose.yml.bak
// and OVERWRITES it by re-extracting the compose file from the image's own
// /app/deploy bundle (scripts/install.sh, preflight_compose_image_compat).
//
// compose_command_flags()'s own doc comment says it collects flags "from the
// proxy service's `command:` array", specifically to keep other services'
// args from being misread as culvert flags. But its awk implementation only
// scopes to ANY flow-style `command: [ ... ]` block anywhere in the file —
// it never actually restricts matching to the `proxy:` service. A
// non-proxy service (e.g. the `cli` service, whose flags are normally
// supplied at `docker compose run --rm cli <flags>` time rather than baked
// into docker-compose.yml, but which docker-compose.yml's own comments show
// operators DO sometimes hand-edit for other services) with a populated
// flow-style command array would have ITS flags folded into the "culvert
// flags to verify" set. Since those flags are never defined by `culvert
// -help`, the preflight falsely concludes the compose/image are
// incompatible and silently overwrites the operator's hand-edited
// docker-compose.yml — a genuine "confirmed bug" data-loss/surprise path in
// the currently-shipped compose↔image preflight, even though it happens to
// be a no-op on the exact file this repo ships today (only the proxy
// service's command array is currently non-empty).
//
// This extracts the REAL compose_command_flags()/missing_compose_flags()
// function bodies out of scripts/install.sh (rather than duplicating them)
// so the test tracks the actual installer script instead of a copy that can
// drift.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureComposeWithNonProxyCommand is a two-service compose file: `proxy`
// carries the real culvert flags, and a second service (`cli`, mirroring
// the repo's own D1.5 operator-contract `cli` service) carries flags that
// are NOT culvert proxy flags at all.
const fixtureComposeWithNonProxyCommand = `services:
  proxy:
    image: culvert/proxy:pinned
    command: [
      "-port",           "8080",
      "-ui-port",        "9090"
    ]
  cli:
    image: culvert/proxy:pinned
    profiles: ["cli"]
    command: ["-confirm", "-backup-dir", "/backup/nightly"]
volumes:
  proxy-data:
`

// fixtureComposeWithAnchoredProxyHeader declares the proxy service header
// with a trailing YAML anchor ("proxy: &proxy"), a normal and valid way for
// an operator to reference the service's mapping elsewhere in the same file
// (or from an override file). Only the proxy service is present, so any
// scoping approach that fails to recognize this header as the start of the
// proxy block will report zero flags — silently defeating the §6c
// compose↔image preflight rather than just leaking a foreign flag into it.
const fixtureComposeWithAnchoredProxyHeader = `services:
  proxy: &proxy
    image: culvert/proxy:pinned
    command: [
      "-port",           "8080",
      "-ui-port",        "9090"
    ]
volumes:
  proxy-data:
`

// runComposeCommandFlags extracts compose_command_flags() from
// scripts/install.sh and runs it with INSTALL_DIR pointed at dir, exactly
// how scripts/install.sh invokes it during the §6c preflight.
func runComposeCommandFlags(t *testing.T, dir string) []string {
	t.Helper()
	fn := extractShellFunction(t, "scripts/install.sh", "compose_command_flags")
	script := fn + "\nINSTALL_DIR=\"$1\"\ncompose_command_flags\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "install_script_compose_command_flags_scope_test", dir) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("compose_command_flags failed: %v\n%s", err, out)
	}
	trimmed := strings.TrimSpace(string(out))
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

// runMissingComposeFlags extracts compose_command_flags()+missing_compose_flags()
// from scripts/install.sh (the latter depends on the former) and runs
// missing_compose_flags with the given "supported" flag list, exactly how
// preflight_compose_image_compat() invokes it.
func runMissingComposeFlags(t *testing.T, dir, supported string) string {
	t.Helper()
	ccf := extractShellFunction(t, "scripts/install.sh", "compose_command_flags")
	mcf := extractShellFunction(t, "scripts/install.sh", "missing_compose_flags")
	script := ccf + "\n" + mcf + "\n" +
		"INSTALL_DIR=\"$1\"\n" +
		`missing_compose_flags "$2"` + "\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "install_script_compose_command_flags_scope_test", dir, supported) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("missing_compose_flags failed: %v\n%s", err, out)
	}
	return string(out)
}

// TestInstallScript_ComposeCommandFlags_ScopedToProxyService proves that
// compose_command_flags() only collects flags from the `proxy:` service's
// command array, matching its own doc comment ("culvert flags from the
// proxy service's `command:` array"). A flow-style command array on any
// OTHER service must not leak into the result.
func TestInstallScript_ComposeCommandFlags_ScopedToProxyService(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(fixtureComposeWithNonProxyCommand), 0o644); err != nil { //nolint:gosec // test fixture, not sensitive
		t.Fatalf("write fixture compose file: %v", err)
	}

	got := runComposeCommandFlags(t, dir)
	gotSet := map[string]bool{}
	for _, f := range got {
		gotSet[f] = true
	}

	for _, want := range []string{"-port", "-ui-port"} {
		if !gotSet[want] {
			t.Errorf("compose_command_flags() = %v, missing real proxy flag %q", got, want)
		}
	}
	for _, unwanted := range []string{"-confirm", "-backup-dir"} {
		if gotSet[unwanted] {
			t.Errorf("compose_command_flags() = %v — leaked %q from the cli service's command array; "+
				"compose_command_flags must scope to the proxy service only (per its own doc comment), "+
				"or preflight_compose_image_compat() will treat unrelated services' flags as culvert "+
				"flags and falsely conclude the compose/image are incompatible", got, unwanted)
		}
	}
}

// TestInstallScript_MissingComposeFlags_IgnoresNonProxyServiceFlags proves
// the end-to-end consequence: preflight_compose_image_compat() calls
// missing_compose_flags(supported) to decide whether to overwrite
// docker-compose.yml. With an image that supports exactly the proxy
// service's real flags (-port, -ui-port) but knows nothing about the cli
// service's flags (-confirm, -backup-dir — never real culvert proxy flags),
// missing_compose_flags must report NO missing flags. Before the fix, the
// cli service's unrelated flags leaked in and were reported "missing",
// which would make install.sh silently back up and overwrite an operator's
// hand-edited docker-compose.yml over a false positive.
func TestInstallScript_MissingComposeFlags_IgnoresNonProxyServiceFlags(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(fixtureComposeWithNonProxyCommand), 0o644); err != nil { //nolint:gosec // test fixture, not sensitive
		t.Fatalf("write fixture compose file: %v", err)
	}

	supported := "-port\n-ui-port"
	got := runMissingComposeFlags(t, dir, supported)
	if strings.TrimSpace(got) != "" {
		t.Fatalf("missing_compose_flags(%q) = %q, want empty — the cli service's -confirm/-backup-dir "+
			"flags are not culvert proxy flags and must not trigger preflight_compose_image_compat() to "+
			"overwrite docker-compose.yml", supported, got)
	}
}

// TestInstallScript_ComposeCommandFlags_RecognizesAnchoredProxyHeader proves
// that scoping compose_command_flags() to the proxy service does not depend
// on the `proxy:` header line having nothing else on it: a YAML anchor
// ("proxy: &proxy") is valid compose syntax and must still be recognized as
// the start of the proxy block. An earlier fix for the cross-service leak
// (see TestInstallScript_ComposeCommandFlags_ScopedToProxyService) matched
// the header only when followed by end-of-line or a comment, which made an
// anchored header fall out of scope entirely — compose_command_flags()
// silently returned NO flags, which would make preflight_compose_image_compat()
// skip the compose/image compatibility check altogether (flagged in PR #763
// review).
func TestInstallScript_ComposeCommandFlags_RecognizesAnchoredProxyHeader(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte(fixtureComposeWithAnchoredProxyHeader), 0o644); err != nil { //nolint:gosec // test fixture, not sensitive
		t.Fatalf("write fixture compose file: %v", err)
	}

	got := runComposeCommandFlags(t, dir)
	gotSet := map[string]bool{}
	for _, f := range got {
		gotSet[f] = true
	}
	for _, want := range []string{"-port", "-ui-port"} {
		if !gotSet[want] {
			t.Errorf("compose_command_flags() = %v with an anchored \"proxy: &proxy\" header, missing real "+
				"proxy flag %q — an anchor on the proxy service header must not drop it out of scope", got, want)
		}
	}
}
