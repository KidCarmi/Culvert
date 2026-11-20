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
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

// runEnvPutProcess runs a single, real, independent `bash` process that
// sources the real env_put() body and calls it once. Used to build genuine
// concurrent-process tests below (as opposed to the single-process,
// same-shell shadowing technique used elsewhere in this file) — env_put's
// concurrency safety is specifically about separate OS processes (two
// overlapping install.sh runs), so the regression tests for it must use
// real, separate processes racing on a real lock file, not a simulation.
func runEnvPutProcess(t *testing.T, fn, envFile, varName, val string) error {
	t.Helper()
	_, err := runEnvPutProcessWith(t, "", "", fn, envFile, varName, val)
	return err
}

// runEnvPutProcessWith is runEnvPutProcess with fixed, test-authored shell
// text run in the same process before the env_put definition (prelude: e.g. a
// umask or a stub shadowing a command) and after the call (epilogue: e.g. a
// probe of the calling shell's state). It also returns the combined output.
func runEnvPutProcessWith(t *testing.T, prelude, epilogue, fn, envFile, varName, val string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	// warn is install.sh's own helper, which the extracted function calls on
	// every skip path. Define it so a skip is VISIBLE: in a writable temp dir
	// none of those paths may fire, and one that does is a skipped update that
	// would otherwise surface only as a missing var.
	script := `warn() { printf 'WARN: %s\n' "$*" >&2; }` + "\n" + prelude + "\n" + fn + "\n" + `env_put "$1" "$2" "$3"` + "\n" + epilogue
	cmd := exec.CommandContext(ctx, "bash", "-c", script, "env_put_concurrency_test", varName, val, envFile) // #nosec G204 -- fixed test script content, not external/user input
	raw, err := cmd.CombinedOutput()
	out := string(raw)
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("env_put %s=%s timed out (likely deadlocked): %s", varName, val, out)
	}
	if err != nil {
		return out, fmt.Errorf("env_put %s=%s failed: %w: %s", varName, val, err, out)
	}
	if strings.Contains(out, "WARN:") {
		return out, fmt.Errorf("env_put %s=%s skipped its update in a writable dir: %s", varName, val, out)
	}
	return out, nil
}

// TestInstallScript_EnvPut_ConcurrentDistinctVars_NoCorruptionOrDeadlock
// proves that many env_put calls, each setting a DIFFERENT var, racing as
// real concurrent processes against the SAME .env file — e.g. install.sh's
// wire_release_agent_for_compose (env_put CULVERT_MAINT_GID, env_put
// CULVERT_RELEASE_PROXY_REPO) overlapping a second, concurrent installer
// run touching other vars — neither deadlocks (env_put's internal locking
// must not be reentrant-unsafe in a way that hangs a genuinely concurrent,
// non-nested caller) nor corrupts the file (every var ends up present
// exactly once, and pre-existing content survives).
func TestInstallScript_EnvPut_ConcurrentDistinctVars_NoCorruptionOrDeadlock(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "env_put")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("EXISTING=original\n"), 0o600); err != nil {
		t.Fatalf("seed %s: %v", envFile, err)
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make(chan error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs <- runEnvPutProcess(t, fn, envFile, fmt.Sprintf("VAR%d", i), fmt.Sprintf("val%d", i))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read %s: %v", envFile, err)
	}
	content := string(got)

	if !strings.Contains(content, "EXISTING=original") {
		t.Errorf("pre-existing EXISTING var lost to the concurrent env_put race; .env content:\n%s", content)
	}
	for i := 0; i < n; i++ {
		want := fmt.Sprintf("VAR%d=val%d", i, i)
		if !strings.Contains(content, want) {
			t.Errorf("missing %q after %d concurrent env_put processes raced the same .env; .env content:\n%s", want, n, content)
		}
	}
}

// TestInstallScript_EnvPut_ConcurrentSameVar_NoLostUpdateOrDuplicate proves
// the specific race flagged in review of the unique-temp-file fix alone
// (PR #1130): two env_put calls as real concurrent processes both updating
// the SAME var. Giving each call its own staging file stops the two writes
// from colliding with EACH OTHER, but does not stop one call's `grep` (its
// READ of the pre-update file) from racing the other's `mv`+append (its
// WRITE) — so whichever `mv` lands last can still silently overwrite the
// other's already-applied update, either resurrecting a stale duplicate
// line or discarding the other's write outright (a lost-update race).
// env_put now serializes its full read/modify/write sequence behind a
// flock held on a dedicated lock file for the transaction's whole duration,
// so this proves BOTH invariants hold under real concurrent execution:
// no crash/deadlock, and — whichever of the two writers "wins" — exactly
// ONE VARA= line survives, holding one of the two written values (never
// both, never neither, never corrupted).
func TestInstallScript_EnvPut_ConcurrentSameVar_NoLostUpdateOrDuplicate(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "env_put")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("EXISTING=original\nVARA=oldvalue\n"), 0o600); err != nil {
		t.Fatalf("seed %s: %v", envFile, err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs <- runEnvPutProcess(t, fn, envFile, "VARA", "raceval1") }()
	go func() { defer wg.Done(); errs <- runEnvPutProcess(t, fn, envFile, "VARA", "raceval2") }()
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read %s: %v", envFile, err)
	}
	content := string(got)

	if n := strings.Count(content, "VARA="); n != 1 {
		t.Fatalf("env_put left %d VARA= lines in .env after two concurrent processes raced to update it, want "+
			"exactly 1 — env_put's own doc comment promises \"set/replace VAR=VALUE in FILE\"; .env content:\n%s", n, content)
	}
	if !strings.Contains(content, "VARA=raceval1") && !strings.Contains(content, "VARA=raceval2") {
		t.Errorf("the surviving VARA= line holds neither racing value (corrupted by the race); .env content:\n%s", content)
	}
	if !strings.Contains(content, "EXISTING=original") {
		t.Errorf("pre-existing EXISTING var lost to the concurrent env_put race; .env content:\n%s", content)
	}
}

// TestInstallScript_EnvPut_CreatesFilePrivateUnderLaxUmask is the regression
// test for SEC-INSTALL-ENVUMASK-1 (CWE-367). install.sh sets no umask, and
// env_put used to create a fresh .env with a plain `touch` (mode
// 0666 & ~umask) and narrow it with `chmod 600` only afterwards. Under a lax
// operator umask a local user could open the file read-only in that window,
// keep the descriptor, and read every secret later written into that inode.
//
// The test runs env_put under `umask 000` with `chmod` shadowed by a no-op
// that records its target's mode at the moment the chmod WOULD have run, so
// the post-hoc chmod cannot mask the creation mode. Every recorded mode and
// the final mode must be 0600: creation itself has to be private.
//
// On the normal path the final mode alone proves nothing, because the mktemp
// staging file (always 0600) is renamed over the touched file; the first
// recorded mode (taken right after `touch`) is the load-bearing check. The
// "mktemp fails" case forces the "${file}.tmp.$$" fallback staging file,
// which a plain redirection creates and env_put renames over $file, so there
// the final mode also fails without the fix.
//
// The epilogue checks that the umask stays scoped to env_put's subshell: the
// rest of the installer must keep the operator's umask.
func TestInstallScript_EnvPut_CreatesFilePrivateUnderLaxUmask(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "env_put")
	if _, err := exec.LookPath("stat"); err != nil {
		t.Fatalf("stat(1) is required to observe the creation mode: %v", err)
	}

	cases := []struct {
		name, stub string
	}{
		{name: "mktemp staging", stub: ""},
		{name: "mktemp fails", stub: `mktemp() { return 1; }`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertEnvPutCreatesPrivateUnderUmask000(t, fn, tc.stub)
		})
	}
}

// assertEnvPutCreatesPrivateUnderUmask000 runs env_put once on a fresh .env
// under `umask 000`, with chmod replaced by a probe and the given extra stub,
// and asserts every mode the probe saw, the final mode, the written value and
// the caller's unchanged umask.
func assertEnvPutCreatesPrivateUnderUmask000(t *testing.T, fn, stub string) {
	t.Helper()
	// A no-op chmod that appends `stat -c %a` of its target to "<target>.modes".
	const chmodProbe = `chmod() { stat -c '%a' -- "$2" >> "$2.modes"; }`
	envFile := filepath.Join(t.TempDir(), ".env")
	prelude := "umask 000\n" + chmodProbe + "\n" + stub
	epilogue := `printf 'UMASK_AFTER=%s\n' "$(umask)"`

	out, err := runEnvPutProcessWith(t, prelude, epilogue, fn, envFile, "CULVERT_SESSION_SECRET", "s3cret")
	if err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(envFile + ".modes")
	if err != nil {
		t.Fatalf("read chmod probe log (env_put never reached its chmod?): %v\noutput:\n%s", err, out)
	}
	modes := strings.Fields(string(raw))
	if len(modes) == 0 {
		t.Fatalf("chmod probe recorded no modes; output:\n%s", out)
	}
	for i, m := range modes {
		if m != "600" {
			t.Errorf("chmod #%d found %s at mode %s, want 600: the file was readable by others before "+
				"the chmod narrowed it (creation under umask 000 must already be private); all: %v",
				i+1, envFile, m, modes)
		}
	}

	fi, err := os.Stat(envFile)
	if err != nil {
		t.Fatalf("stat %s: %v", envFile, err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("final mode of %s is %#o with chmod disabled, want 0600", envFile, perm)
	}

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read %s: %v", envFile, err)
	}
	if !strings.Contains(string(got), "CULVERT_SESSION_SECRET=s3cret") {
		t.Errorf("value did not land; .env content:\n%s", got)
	}

	if !strings.Contains(out, "UMASK_AFTER=0000") {
		t.Errorf("env_put changed the calling shell's umask (it must stay scoped to its subshell); output:\n%s", out)
	}
}
