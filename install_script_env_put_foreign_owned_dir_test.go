package main

// install_script_env_put_foreign_owned_dir_test.go — env_put() must survive a
// stack directory the invoking user cannot write to.
//
// scripts/install.sh provisions $INSTALL_DIR owned by whoever ran it, so a
// first install under `sudo` (or cloud-init, as root) leaves /srv/culvert
// root-owned 0755 holding a root-owned 0600 .env and the root-owned 0644
// .env.lock env_put created. A later re-run by an unprivileged sudoer reuses
// that directory ("Culvert deployment already exists at …") without changing
// its ownership.
//
// env_put takes ownership of .env via sudo for exactly this cross-user re-run,
// but then opened its lock file ("$file.lock") and staged its temp file
// ("$file.XXXXXX", renamed over .env) in the SAME directory with the invoking
// user's own privileges. Both fail with EACCES, env_put returns non-zero, and
// because the installer calls it unconditionally at top level
// (`env_put CULVERT_INSTALL_CHANNEL …`) under `set -euo pipefail`, every such
// re-run aborted before `docker compose up`.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// seedForeignOwnedStack builds a stack dir the test's effective user cannot
// write to, holding an .env and .env.lock that become usable only once the
// `sudo chown <me> FILE` stub runs. It returns the .env path and a writable
// TMPDIR for the dropped user.
func seedForeignOwnedStack(t *testing.T, root bool) (envFile, scratch string) {
	t.Helper()
	base := t.TempDir()
	stack := filepath.Join(base, "stack")
	scratch = filepath.Join(base, "tmp")
	for _, d := range []string{stack, scratch} {
		if err := os.Mkdir(d, 0o755); err != nil { // #nosec G301 -- must stay traversable by the dropped uid
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	envFile = filepath.Join(stack, ".env")
	lockFile := envFile + ".lock"
	const seeded = "CULVERT_LOG_PASSPHRASE=keep-this-passphrase\nCULVERT_INSTALL_CHANNEL=stable\n"
	if err := os.WriteFile(envFile, []byte(seeded), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	if err := os.WriteFile(lockFile, nil, 0o600); err != nil {
		t.Fatalf("seed .env.lock: %v", err)
	}

	// "Owned by another user" is modelled the way the sibling unreadable-.env
	// test does: the two files are inaccessible (mode 000) until the `sudo
	// chown <me> FILE` stub makes them usable, which is what the real sudo
	// does for the operator. The DIRECTORY stays genuinely unwritable for the
	// whole run: nothing may be created in it or renamed into it.
	for _, f := range []string{envFile, lockFile} {
		if err := os.Chmod(f, 0o000); err != nil {
			t.Fatalf("chmod %s: %v", f, err)
		}
	}
	t.Cleanup(func() {
		_ = os.Chmod(stack, 0o755) // #nosec G302 -- restore so t.TempDir can remove it
		_ = os.Chmod(envFile, 0o600)
		_ = os.Chmod(lockFile, 0o600)
	})
	if !root {
		if err := os.Chmod(stack, 0o555); err != nil { // #nosec G302 -- deliberately unwritable test dir
			t.Fatalf("chmod stack: %v", err)
		}
		return envFile, scratch
	}
	for _, p := range []string{filepath.Dir(base), base} {
		if err := os.Chmod(p, 0o755); err != nil { // #nosec G302 -- test temp dir must be traversable by the dropped uid
			t.Fatalf("chmod %s: %v", p, err)
		}
	}
	// stack itself stays root-owned 0755: unwritable for uid 65534.
	for _, p := range []string{envFile, lockFile, scratch} {
		if err := os.Chown(p, 65534, 65534); err != nil {
			t.Fatalf("chown %s: %v", p, err)
		}
	}
	return envFile, scratch
}

func TestInstallScript_EnvPut_ForeignOwnedStackDir_DoesNotAbortReRun(t *testing.T) {
	root := os.Getuid() == 0
	if root {
		if _, err := exec.LookPath("setpriv"); err != nil {
			t.Skip("setpriv unavailable: cannot drop root to make the stack dir unwritable")
		}
	}
	envFile, scratch := seedForeignOwnedStack(t, root)

	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	script := `set -euo pipefail
info() { :; }
warn() { echo "WARN: $*" >&2; }
sudo() { if [[ "$1" == chown ]]; then chmod 600 "$3"; else return 1; fi; }
` + envPutFn + `
env_put CULVERT_INSTALL_CHANNEL lts "$1"
`
	args := []string{"-c", script, "install_script_env_put_foreign_owned_dir_test", envFile}
	var cmd *exec.Cmd
	if root {
		cmd = exec.CommandContext(t.Context(), "setpriv", append([]string{"--reuid=65534", "--regid=65534", "--clear-groups", "bash"}, args...)...) // #nosec G204 -- fixed test script content
	} else {
		cmd = exec.CommandContext(t.Context(), "bash", args...) // #nosec G204 -- fixed test script content
	}
	cmd.Env = append(os.Environ(), "TMPDIR="+scratch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("env_put failed in a stack dir the invoking user cannot write to, which aborts the "+
			"whole installer re-run under `set -euo pipefail`: %v\n%s", err, out)
	}

	if err := os.Chmod(envFile, 0o600); err != nil {
		t.Fatalf("chmod .env for read-back: %v", err)
	}
	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if !strings.Contains(string(got), "CULVERT_LOG_PASSPHRASE=keep-this-passphrase\n") {
		t.Fatalf("env_put lost an unrelated .env line; .env now:\n%s", got)
	}
	if !strings.Contains(string(got), "CULVERT_INSTALL_CHANNEL=lts\n") || strings.Contains(string(got), "CULVERT_INSTALL_CHANNEL=stable") {
		t.Fatalf("env_put did not replace the value (want exactly CULVERT_INSTALL_CHANNEL=lts); .env now:\n%s\noutput:\n%s", got, out)
	}
	leftovers, err := filepath.Glob(filepath.Join(scratch, "*"))
	if err != nil {
		t.Fatalf("glob scratch: %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("env_put left staging files holding .env secrets behind: %v", leftovers)
	}
}
