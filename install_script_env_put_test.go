package main

// install_script_env_put_test.go — regression coverage for the env_put()
// helper in scripts/install.sh, which scripts/install.sh uses to write
// secrets/config into the operator's .env file (e.g. CULVERT_LOG_PASSPHRASE,
// CULVERT_MAINT_GID, CULVERT_RELEASE_PROXY_REPO via wire_release_agent_for_compose).
//
// This extracts the REAL env_put() function body out of scripts/install.sh
// (rather than duplicating it here) and exercises it under bash, so the test
// tracks the actual installer script instead of a copy that can drift.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// extractShellFunction pulls a bash function's source (from "name() {" to the
// matching top-level "}") out of a script file. env_put's body is flat (no
// nested braces), so the first line that is exactly "}" closes it.
func extractShellFunction(t *testing.T, scriptPath, name string) string {
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
	for i := start + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "}" {
			return strings.Join(lines[start:i+1], "\n")
		}
	}
	t.Fatalf("could not find closing brace for %q in %s", name, scriptPath)
	return ""
}

// runShellScript runs a fixed, test-authored bash script (never external or
// user-supplied input) against envFile (passed in as $1) and fails the test
// if it exits non-zero.
func runShellScript(t *testing.T, script, envFile string) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "install_script_env_put_test", envFile) // #nosec G204 -- fixed test script content, not external/user input
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}
}

// TestInstallScript_EnvPut_ReplacesExistingValue proves that calling env_put
// twice for the same variable REPLACES the value rather than appending a
// second, duplicate "VAR=..." line. This is the documented contract ("set/
// replace VAR=VALUE in FILE") and matters in practice: install.sh's
// wire_release_agent_for_compose calls env_put CULVERT_MAINT_GID and
// env_put CULVERT_RELEASE_PROXY_REPO on every run (install.sh is designed to
// be safely re-run against an existing deployment — see its many "already
// exists/already present" idempotency checks), so a fresh .env whose only
// content is one of those two vars must not accumulate duplicate lines on a
// second install.sh run.
func TestInstallScript_EnvPut_ReplacesExistingValue(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "env_put")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")

	script := fn + "\n" +
		`env_put CULVERT_MAINT_GID "1000" "$1"` + "\n" +
		`env_put CULVERT_MAINT_GID "2000" "$1"` + "\n"

	runShellScript(t, script, envFile)

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read %s: %v", envFile, err)
	}
	content := string(got)

	if n := strings.Count(content, "CULVERT_MAINT_GID="); n != 1 {
		t.Fatalf("env_put left %d CULVERT_MAINT_GID= lines in .env, want 1 (value replaced, not duplicated); .env content:\n%s", n, content)
	}
	if !strings.Contains(content, "CULVERT_MAINT_GID=2000") {
		t.Errorf(".env does not contain the updated value CULVERT_MAINT_GID=2000; .env content:\n%s", content)
	}
	if strings.Contains(content, "CULVERT_MAINT_GID=1000") {
		t.Errorf(".env still contains the stale value CULVERT_MAINT_GID=1000 alongside the new one; .env content:\n%s", content)
	}
}

// TestInstallScript_EnvPut_PreservesFileOnRealGrepFailure proves that a real
// grep failure (exit code > 1 — e.g. an I/O error, not just "no lines
// survived the filter") does NOT clobber the existing file with an
// incomplete/empty temp file. Flagged in PR #530 review: treating every
// non-zero grep exit as benign (as the first fix in this file did) would let
// a genuine write error to $file.tmp silently promote an empty file over the
// operator's real .env content.
func TestInstallScript_EnvPut_PreservesFileOnRealGrepFailure(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "env_put")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")

	// 1) Seed the file normally (real grep). 2) Shadow `grep` with a shell
	// function that simulates a real error (exit 2), then call env_put again.
	script := fn + "\n" +
		`env_put EXISTING_VAR original_value "$1"` + "\n" +
		`grep() { return 2; }` + "\n" +
		`env_put CULVERT_MAINT_GID new_value "$1"` + "\n"

	runShellScript(t, script, envFile)

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read %s: %v", envFile, err)
	}
	content := string(got)

	if !strings.Contains(content, "EXISTING_VAR=original_value") {
		t.Errorf("a real grep failure while setting CULVERT_MAINT_GID lost the pre-existing EXISTING_VAR entry — the temp file must not be promoted over the original on a genuine error; .env content:\n%s", content)
	}
}
