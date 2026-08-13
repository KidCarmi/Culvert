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

// TestInstallScript_EnvPut_ConcurrentInvocationsDoNotLeaveStaleDuplicate
// proves that two env_put calls racing against the SAME .env file — e.g. an
// operator re-running install.sh (automation retry, or a second admin)
// against a shared /srv/culvert install while a still-running instance is
// mid-setup — do not corrupt it.
//
// env_put stages its edit through a FIXED path, "$file.tmp", shared by every
// invocation regardless of which process is running it. When a second,
// concurrent env_put finishes first, its "mv "$file.tmp" "$file"" replaces
// "$file" out from under the first invocation's still-open write handle to
// the OLD "$file.tmp" inode — which is now the SAME inode as the (just
// replaced) "$file". The first invocation's own `grep -vE "^VAR=" "$file" >
// "$file.tmp"` then has its output redirect alias its own input file, so GNU
// grep refuses with "input file is also the output" (exit 2) — a real,
// observable failure this test surfaces directly by capturing it, not just
// inferring it from the resulting content. env_put treats any exit other
// than 0/1 as a hard error and discards the (never-produced) filtered
// output via `rm -f "$file.tmp"` instead of promoting it — which means the
// "drop the old VAR= line" step never happens. The unconditional final
// `printf ... >> "$file"` still runs, so the NEW value is appended anyway —
// leaving BOTH the stale old line and the new line in the file, silently
// violating env_put's documented "set/replace VAR=VALUE" contract (compare
// TestInstallScript_EnvPut_ReplacesExistingValue above, which pins that same
// contract for the uncontended, sequential case).
//
// This reproduces the real race deterministically — via the same
// command-shadowing technique as TestInstallScript_EnvPut_PreservesFileOnRealGrepFailure
// above — rather than relying on real OS scheduling timing, which was tried
// first and confirmed to reproduce with real concurrent processes but was too
// flaky (timing-dependent) for a reliable regression test.
func TestInstallScript_EnvPut_ConcurrentInvocationsDoNotLeaveStaleDuplicate(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "env_put")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("EXISTING=original\nVARA=oldvalue\n"), 0o600); err != nil {
		t.Fatalf("seed %s: %v", envFile, err)
	}

	// The outer env_put call (VARA=newvalue, simulating this installer run)
	// is mid-flight when its `grep` step is reached. At exactly that point —
	// before the real grep runs — a second, concurrent env_put call
	// (VARB=valueB, simulating a second overlapping installer run) is
	// injected and runs to completion first, exactly as a genuinely
	// concurrent process finishing first would. The FIRST guard prevents the
	// injected call's own grep step from recursing into this same shadow.
	script := fn + "\n" +
		`envfile="$1"` + "\n" +
		`FIRST=1` + "\n" +
		`grep() {` + "\n" +
		`  if [[ "$FIRST" -eq 1 ]]; then` + "\n" +
		`    FIRST=0` + "\n" +
		`    env_put VARB valueB "$envfile"` + "\n" +
		`  fi` + "\n" +
		`  command grep "$@"` + "\n" +
		`}` + "\n" +
		`env_put VARA newvalue "$envfile"` + "\n"

	runShellScript(t, script, envFile)

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read %s: %v", envFile, err)
	}
	content := string(got)

	if n := strings.Count(content, "VARA="); n != 1 {
		t.Errorf("env_put left %d VARA= lines in .env after a concurrent env_put raced it, want 1 (value replaced, "+
			"not duplicated) — env_put's own doc comment promises \"set/replace VAR=VALUE in FILE\"; .env content:\n%s", n, content)
	}
	if strings.Contains(content, "VARA=oldvalue") {
		t.Errorf(".env still contains the stale VARA=oldvalue line after a concurrent env_put raced the update to "+
			"VARA=newvalue; .env content:\n%s", content)
	}
	if !strings.Contains(content, "VARA=newvalue") {
		t.Errorf(".env does not contain the updated VARA=newvalue; .env content:\n%s", content)
	}
	if !strings.Contains(content, "VARB=valueB") {
		t.Errorf("the concurrent env_put's own VARB=valueB write was lost; .env content:\n%s", content)
	}
	if !strings.Contains(content, "EXISTING=original") {
		t.Errorf("pre-existing EXISTING var lost to the concurrent env_put race; .env content:\n%s", content)
	}
}
