package main

// install_script_extract_toml_string_test.go — regression coverage for the
// extract_toml_string() helper in packaging/culvert-maint/install.sh, which
// the maintenance-agent installer uses to read compose_project_dir,
// compose_file, proxy_repo, and image_allowlist out of
// /etc/culvert-maint/config.toml before rendering them into the sudoers
// allowlist (see install.sh §5, lines ~324-332).
//
// This extracts the REAL extract_toml_string() function body out of
// packaging/culvert-maint/install.sh (rather than duplicating it here) and
// exercises it under bash, so the test tracks the actual installer script
// instead of a copy that can drift.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// extractShellFunctionBraceAware pulls a shell function's source (from
// "name() {" to its true matching closing brace) out of a script file,
// tracking brace depth line by line. Unlike the flat extractShellFunction
// helper used elsewhere in this package (which stops at the first line that
// is exactly "}"), this handles functions whose body embeds a multi-line awk
// program with its own standalone closing braces — extract_toml_string's awk
// pattern-action block ("$0 ~ ... { ... }") closes on a line that is just
// "}", which would fool the flat extractor into truncating the function
// mid-body.
func extractShellFunctionBraceAware(t *testing.T, scriptPath, name string) string {
	t.Helper()
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == name+"() {" {
			start = i
			break
		}
	}
	if start == -1 {
		t.Fatalf("could not find %q function in %s", name, scriptPath)
	}
	depth := strings.Count(lines[start], "{") - strings.Count(lines[start], "}")
	for i := start + 1; i < len(lines); i++ {
		depth += strings.Count(lines[i], "{") - strings.Count(lines[i], "}")
		if depth <= 0 {
			return strings.Join(lines[start:i+1], "\n")
		}
	}
	t.Fatalf("could not find closing brace for %q in %s", name, scriptPath)
	return ""
}

// runExtractTomlString writes toml to a temp config file, points CONFIG_DEST
// at it (extract_toml_string reads the global $CONFIG_DEST, exactly as the
// real installer does), and returns the value it prints for key.
func runExtractTomlString(t *testing.T, toml, key string) string {
	t.Helper()
	fn := extractShellFunctionBraceAware(t, "packaging/culvert-maint/install.sh", "extract_toml_string")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(toml), 0o600); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	script := "CONFIG_DEST=" + cfgPath + "\n" + fn + "\n" + `extract_toml_string "` + key + `"` + "\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}
	return strings.TrimRight(string(out), "\n")
}

// TestCulvertMaintInstall_ExtractTomlString_TrailingComment proves that a
// config.toml value with a normal trailing inline comment — ordinary,
// spec-legal TOML that an operator is likely to write when hand-editing
// /etc/culvert-maint/config.toml — is read back clean, without the closing
// quote or comment text leaking into the value.
//
// extract_toml_string uses `awk 'BEGIN{FS="="} ... {v=$2; ...}'`: FS="=" means
// $2 is only the field between the FIRST and SECOND "=" in the line, and with
// no second "=" present $2 is simply everything after the first "=" — that
// part is fine. The bug is in the trailing-quote strip, `sub(/"[[:space:]]*$/,
// "", v)`, which only removes the quote when it is the last non-blank
// character on the line. A trailing "# comment" after the closing quote
// leaves that regex without a match, so the quote and comment survive in the
// extracted value.
//
// Downstream, install.sh's reject_unsafe() rejects any value containing a
// quote or space (line ~76-82), so this doesn't silently misconfigure the
// sudoers allowlist — it makes install.sh die with a confusing
// "contains whitespace/quotes/pipe/control chars" error for a config file
// that is perfectly valid TOML.
func TestCulvertMaintInstall_ExtractTomlString_TrailingComment(t *testing.T) {
	toml := "compose_project_dir = \"/srv/culvert\"  # primary docker-compose dir\n" +
		"allow_peers = [\"1000\"]\n"

	got := runExtractTomlString(t, toml, "compose_project_dir")
	want := "/srv/culvert"
	if got != want {
		t.Fatalf("extract_toml_string(compose_project_dir) = %q, want %q — a trailing TOML comment must not leak "+
			"into the extracted value", got, want)
	}
}

// TestCulvertMaintInstall_ExtractTomlString_NoComment is the baseline sanity
// check: a value with no trailing comment (the common case, and what
// config.example.toml itself uses) is read back correctly.
func TestCulvertMaintInstall_ExtractTomlString_NoComment(t *testing.T) {
	toml := "compose_project_dir = \"/srv/culvert\"\n" +
		"allow_peers = [\"1000\"]\n"

	got := runExtractTomlString(t, toml, "compose_project_dir")
	want := "/srv/culvert"
	if got != want {
		t.Fatalf("extract_toml_string(compose_project_dir) = %q, want %q", got, want)
	}
}

// TestCulvertMaintInstall_ExtractTomlString_SingleQuotedLiteral is a CI-caught
// regression: extract_toml_string only stripped DOUBLE-quote delimiters, so a
// TOML LITERAL string (single-quoted — required whenever the value contains a
// backslash, e.g. image_allowlist's regex '^ghcr\.io/...') came back with its
// surrounding single-quote characters still attached. That silently broke
// check_proxy_repo_matches_allowlist's anchored regex match against the
// DEFAULT config.example.toml (a stray leading/trailing quote defeats a
// ^...$-anchored pattern) — install-lifecycle-e2e caught it as a real CI
// failure on a plain default install ("Maintenance-agent installer lifecycle").
func TestCulvertMaintInstall_ExtractTomlString_SingleQuotedLiteral(t *testing.T) {
	toml := `image_allowlist = '^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$'` + "\n" +
		"allow_peers = [\"1000\"]\n"

	got := runExtractTomlString(t, toml, "image_allowlist")
	want := `^ghcr\.io/kidcarmi/culvert(:[A-Za-z0-9._-]+|@sha256:[a-f0-9]{64})$`
	if got != want {
		t.Fatalf("extract_toml_string(image_allowlist) = %q, want %q — a single-quoted TOML literal string "+
			"must have its delimiter quotes stripped just like a double-quoted basic string", got, want)
	}
}
