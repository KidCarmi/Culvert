package main

// install_script_maint_toml_string_test.go — regression coverage for the
// maint_toml_string() helper in scripts/install.sh, which
// wire_release_agent_for_compose uses to read compose_project_dir,
// socket_path, and proxy_repo out of /etc/culvert-maint/config.toml before
// deciding whether it is safe to auto-wire the Release Management UDS into
// the proxy container.
//
// maint_toml_string is a near-duplicate of extract_toml_string() in
// packaging/culvert-maint/install.sh, which had its own trailing-comment
// leak fixed in PR #? ("extract_toml_string leaks trailing comment into
// value"). That fix was never ported to this copy — this file proves the
// same defect still lives in scripts/install.sh.
//
// This extracts the REAL maint_toml_string() function body out of
// scripts/install.sh (rather than duplicating it here) and exercises it
// under bash, so the test tracks the actual installer script instead of a
// copy that can drift.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runMaintTomlString writes toml to a temp config file and returns the value
// maint_toml_string() prints for key, exactly as wire_release_agent_for_compose
// calls it: maint_toml_string <key> <file>.
func runMaintTomlString(t *testing.T, toml, key string) string {
	t.Helper()
	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "maint_toml_string")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	script := fn + "\n" + `maint_toml_string "` + key + `" "` + cfgPath + `"` + "\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}
	return strings.TrimRight(string(out), "\n")
}

// TestInstallScript_MaintTomlString_TrailingComment proves that a
// config.toml value with a normal trailing inline comment — ordinary,
// spec-legal TOML an operator is likely to write when hand-editing
// /etc/culvert-maint/config.toml — is read back clean, without the closing
// quote or comment text leaking into the value.
//
// Downstream, wire_release_agent_for_compose compares this value against
// $INSTALL_DIR with a plain string equality check:
//
//	if [[ "$cfg_project" != "$INSTALL_DIR" ]]; then
//	  warn "... does not match install dir ..."; return 0
//	fi
//
// A leaked trailing quote/comment makes that comparison fail even when the
// path genuinely matches, so Release Management auto-wiring silently skips
// itself on an otherwise correctly configured install — no error, only an
// easy-to-miss warning line.
func TestInstallScript_MaintTomlString_TrailingComment(t *testing.T) {
	toml := "compose_project_dir = \"/srv/culvert\"  # primary docker-compose dir\n" +
		"socket_path = \"/run/culvert-maint/culvert-maint.sock\"\n"

	got := runMaintTomlString(t, toml, "compose_project_dir")
	want := "/srv/culvert"
	if got != want {
		t.Fatalf("maint_toml_string(compose_project_dir) = %q, want %q — a trailing TOML comment must not leak "+
			"into the extracted value (this breaks wire_release_agent_for_compose's compose_project_dir match "+
			"against $INSTALL_DIR)", got, want)
	}
}

// TestInstallScript_MaintTomlString_NoComment is the baseline sanity check:
// a value with no trailing comment (the common case, and what
// config.example.toml itself uses) is read back correctly.
func TestInstallScript_MaintTomlString_NoComment(t *testing.T) {
	toml := "compose_project_dir = \"/srv/culvert\"\n" +
		"socket_path = \"/run/culvert-maint/culvert-maint.sock\"\n"

	got := runMaintTomlString(t, toml, "compose_project_dir")
	want := "/srv/culvert"
	if got != want {
		t.Fatalf("maint_toml_string(compose_project_dir) = %q, want %q", got, want)
	}
}
