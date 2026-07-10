package main

// install_script_maint_toml_string_test.go — regression coverage for the
// maint_toml_string() helper in scripts/install.sh, which
// wire_release_agent_for_compose uses to read compose_project_dir,
// socket_path, and proxy_repo out of /etc/culvert-maint/config.toml before
// deciding whether it is safe to auto-wire Release Management (mount the
// maintenance agent's UDS into the proxy container).
//
// This extracts the REAL maint_toml_string() function body out of
// scripts/install.sh (rather than duplicating it here) and exercises it
// under bash, so the test tracks the actual installer script instead of a
// copy that can drift.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// requireSudoForTest skips the test when passwordless sudo isn't available —
// maint_toml_string always shells out via `sudo awk` (scripts/install.sh runs
// as an unprivileged user with selective sudo escalation; the config file it
// reads is root-owned 0640).
func requireSudoForTest(t *testing.T) {
	t.Helper()
	if err := exec.CommandContext(t.Context(), "sudo", "-n", "true").Run(); err != nil {
		t.Skip("passwordless sudo not available in this environment — skipping")
	}
}

// runMaintTomlString extracts the real maint_toml_string() function body from
// scripts/install.sh and runs it against a temp config file.
func runMaintTomlString(t *testing.T, toml, key string) string {
	t.Helper()
	requireSudoForTest(t)
	// maint_toml_string's awk program opens a pattern-action brace that itself
	// closes on a standalone "}" line before the function's own closing brace
	// — the same shape called out in install_script_extract_toml_string_test.go
	// — so the brace-aware extractor is required here too.
	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "maint_toml_string")

	dir := t.TempDir()
	cfgPath := dir + "/config.toml"
	// 0644 is fine — the test doesn't rely on root ownership, only on
	// maint_toml_string's `sudo awk` being able to read it, which a
	// world-readable temp file satisfies.
	if err := os.WriteFile(cfgPath, []byte(toml), 0o644); err != nil { //nolint:gosec // test fixture, not sensitive
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
// spec-legal TOML that an operator is likely to write when hand-editing
// /etc/culvert-maint/config.toml — is read back clean, without the closing
// quote or comment text leaking into the value.
//
// maint_toml_string's trailing-quote strip, `sub(/"[[:space:]]*$/, "", v)`,
// only removes the quote when it is the last non-blank character on the
// line. A trailing "# comment" after the closing quote leaves that regex
// without a match, so the quote and comment survive in the extracted value.
//
// Unlike the sibling bug already fixed in
// packaging/culvert-maint/install.sh's extract_toml_string (which dies loudly
// via reject_unsafe on the resulting garbage), a leaked comment here is
// silent: wire_release_agent_for_compose compares the extracted
// compose_project_dir/socket_path/proxy_repo against expected values and,
// on any mismatch, just warns "Release Management auto-wiring skipped" and
// returns — so an operator who added an innocuous inline comment to their
// config.toml silently loses Release Management auto-wiring with a
// confusing "does not match" warning, even though the values are identical
// in substance.
func TestInstallScript_MaintTomlString_TrailingComment(t *testing.T) {
	toml := "compose_project_dir = \"/srv/culvert\"  # primary docker-compose dir\n" +
		"socket_path = \"/run/culvert-maint/culvert-maint.sock\"\n"

	got := runMaintTomlString(t, toml, "compose_project_dir")
	want := "/srv/culvert"
	if got != want {
		t.Fatalf("maint_toml_string(compose_project_dir) = %q, want %q — a trailing TOML comment must not leak "+
			"into the extracted value (this silently breaks Release Management auto-wiring's "+
			"compose_project_dir/socket_path/proxy_repo comparisons in wire_release_agent_for_compose)", got, want)
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
