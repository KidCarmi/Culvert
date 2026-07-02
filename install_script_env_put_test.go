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

	cmd := exec.Command("bash", "-c", script, "install_script_env_put_test", envFile)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("env_put script failed: %v\n%s", err, out)
	}

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
