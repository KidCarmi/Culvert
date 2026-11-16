package main

// install_script_env_put_lock_symlink_test.go — env_put() must not follow a
// link planted at its lock path (SEC-INSTALL-LOCKLINK-1).
//
// env_put serializes its read/write transaction on "$file.lock", and every user
// of that path follows symlinks:
//
//   - `9>"$file.lock"`, the redirection that opens the transaction, TRUNCATES
//     whatever the link points at, with the invoking user's own privileges and
//     on every call. This needs no sudo and no unusual topology — only a stack
//     directory some other account can write (a group-writable deployment dir
//     shared by several operators).
//   - `sudo touch "$lock"` CREATES the link's target as root, and
//     `sudo chown <me> "$lock"` then hands it to the invoking sudoer
//     (/etc/sudoers.d/x, /etc/cron.d/x). That pair was added for the re-run
//     against a stack dir owned by ANOTHER user (see
//     install_script_env_put_foreign_owned_dir_test.go) — the very topology in
//     which someone else can plant the link.
//
// ".env.lock" is the sharp case precisely because, unlike ".env", it normally
// does not exist, so the `sudo touch` CREATION branch is reachable on an
// ordinary upgrade and not only on a first install. `-e` is false for a
// dangling symlink and cannot see that case at all, which is why the guard
// tests `-L`.
//
// CWE-59 (link following) / CWE-61 (symlink attack).

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// envPutLockBudget bounds one env_put run. Normal runs take tens of
// milliseconds, so this is pure headroom — its job is to turn a WEDGE into a
// fast, legible failure: `9>` on a FIFO with no reader blocks forever, and
// without a bound that hangs the whole package until the test binary's global
// timeout panics, reporting nothing about which assertion was lost.
const envPutLockBudget = 20 * time.Second

// envPutLockHarness runs install.sh's env_put against envFile with a `sudo`
// stub that RECORDS every call before acting, so a test can assert what env_put
// asked to be done with elevated privilege. Returns the combined output and the
// recorded sudo invocations.
//
// drop runs the script as an unprivileged uid, which is required whenever the
// scenario depends on a path the invoker cannot write (root ignores mode bits).
func envPutLockHarness(t *testing.T, envFile, scratch string, drop bool) (out string, sudoCalls []string) {
	t.Helper()
	sudoLog := filepath.Join(scratch, "sudo.log")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	script := `set -euo pipefail
info() { :; }
warn() { echo "WARN: $*" >&2; }
sudo() { echo "$*" >> "$SUDO_LOG"; case "$1" in
  chown) chmod 600 "$3" 2>/dev/null || true ;;
  touch) touch "$2" 2>/dev/null || return 1 ;;
  *) return 1 ;;
esac; }
` + envPutFn + `
env_put CULVERT_INSTALL_CHANNEL lts "$1"
`
	ctx, cancel := context.WithTimeout(t.Context(), envPutLockBudget)
	defer cancel()
	args := []string{"-c", script, "install_script_env_put_lock_symlink_test", envFile}
	var cmd *exec.Cmd
	switch {
	case !drop || os.Getuid() != 0:
		// Either the scenario wants our own privileges, or we are already
		// unprivileged and the seeded mode bits mean what they say.
		cmd = exec.CommandContext(ctx, "bash", args...) // #nosec G204 -- fixed test script content
	default:
		if _, err := exec.LookPath("setpriv"); err != nil {
			t.Skip("setpriv unavailable: cannot drop root to make the stack dir unwritable")
		}
		cmd = exec.CommandContext(ctx, "setpriv",
			append([]string{"--reuid=65534", "--regid=65534", "--clear-groups", "bash"}, args...)...) // #nosec G204 -- fixed test script content
	}
	cmd.Env = append(os.Environ(), "TMPDIR="+scratch, "SUDO_LOG="+sudoLog)
	// Cancelling the context kills `bash`, but env_put runs its transaction in
	// a SUBSHELL, and a subshell wedged on `9>` outlives its parent holding the
	// inherited stdout/stderr pipes open — which blocks CombinedOutput past the
	// deadline, so the bound above would never be observed. WaitDelay force-
	// closes those pipes shortly after the kill, which is what makes a wedge
	// report as one.
	cmd.WaitDelay = 5 * time.Second
	raw, err := cmd.CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("env_put did not finish within %s — it is WEDGED on the lock path, which is what opening a "+
			"non-regular file (a FIFO with no reader) does, and which hangs the installer rather than "+
			"aborting it.\noutput:\n%s", envPutLockBudget, raw)
	}
	// env_put must DEGRADE, never fail: the installer calls it at top level
	// under `set -euo pipefail`, so a non-zero return aborts the whole re-run.
	if err != nil {
		t.Fatalf("env_put must degrade rather than fail (a non-zero return aborts the installer re-run): %v\n%s", err, raw)
	}
	if b, rdErr := os.ReadFile(sudoLog); rdErr == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
			if line != "" {
				sudoCalls = append(sudoCalls, line)
			}
		}
	}
	return string(raw), sudoCalls
}

// TestInstallScript_EnvPut_LockSymlink_TruncatesNothing is the half that needs
// no privilege at all: the `9>"$file.lock"` redirection runs as the invoking
// user and truncates whatever the planted link points at. The stack dir here is
// WRITABLE — the ordinary topology — so none of the sudo branches are involved.
func TestInstallScript_EnvPut_LockSymlink_TruncatesNothing(t *testing.T) {
	const victim = "the other operator's content, which env_put must not touch\n"
	base := t.TempDir()
	stack := filepath.Join(base, "stack")
	outside := filepath.Join(base, "outside")
	scratch := filepath.Join(base, "tmp")
	for _, d := range []string{stack, outside, scratch} {
		if err := os.Mkdir(d, 0o755); err != nil { // #nosec G301 -- plain test dir
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	envFile := filepath.Join(stack, ".env")
	if err := os.WriteFile(envFile, []byte("CULVERT_INSTALL_CHANNEL=stable\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	// Writable by us, as an operator's own ~/.ssh/authorized_keys or crontab
	// would be — that is what makes the unprivileged truncation reachable.
	planted := filepath.Join(outside, "operator-owned-file")
	if err := os.WriteFile(planted, []byte(victim), 0o600); err != nil {
		t.Fatalf("seed victim file: %v", err)
	}
	if err := os.Symlink(planted, envFile+".lock"); err != nil {
		t.Fatalf("plant .env.lock symlink: %v", err)
	}

	out, sudoCalls := envPutLockHarness(t, envFile, scratch, false)

	got, err := os.ReadFile(planted)
	if err != nil {
		t.Fatalf("read %s: %v", planted, err)
	}
	if string(got) != victim {
		t.Fatalf("env_put truncated %s through the symlink planted at .env.lock: the `9>\"$file.lock\"` "+
			"redirection followed the link (CWE-59).\nwant %q\ngot  %q\noutput:\n%s", planted, victim, got, out)
	}
	if len(sudoCalls) != 0 {
		t.Errorf("no sudo call belongs on this path (the stack dir is writable); got %v", sudoCalls)
	}
	if !strings.Contains(out, "Refusing to use") {
		t.Errorf("env_put must say WHY it skipped the write, so the operator can go look at who owns the stack dir; output:\n%s", out)
	}
}

// TestInstallScript_EnvPut_DanglingLockSymlink_IsNeverHandedToSudo is the
// privileged half. A dangling link is invisible to `-e`, so without the `-L`
// guard env_put reaches `sudo touch "$lock"` — creating the link's target as
// root — and then `sudo chown <me> "$lock"`.
//
// The assertion is on what env_put ASKS SUDO TO DO, not on the resulting file:
// the stub necessarily runs with the test's own (dropped) privileges, so it
// cannot carry out the root action whose absence would otherwise be proved.
// Handing a path env_put has not established is a regular file to sudo at all
// is the defect.
func TestInstallScript_EnvPut_DanglingLockSymlink_IsNeverHandedToSudo(t *testing.T) {
	base := t.TempDir()
	stack := filepath.Join(base, "stack")
	outside := filepath.Join(base, "outside")
	scratch := filepath.Join(base, "tmp")
	for _, d := range []string{stack, outside, scratch} {
		if err := os.Mkdir(d, 0o755); err != nil { // #nosec G301 -- must stay traversable by the dropped uid
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	envFile := filepath.Join(stack, ".env")
	if err := os.WriteFile(envFile, []byte("CULVERT_INSTALL_CHANNEL=stable\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	planted := filepath.Join(outside, "sudoers.d-drop-in") // deliberately absent
	if err := os.Symlink(planted, envFile+".lock"); err != nil {
		t.Fatalf("plant .env.lock symlink: %v", err)
	}
	if os.Getuid() == 0 {
		for _, p := range []string{filepath.Dir(base), base} {
			if err := os.Chmod(p, 0o755); err != nil { // #nosec G302 -- traversable by the dropped uid
				t.Fatalf("chmod %s: %v", p, err)
			}
		}
		// The victim dir is writable by the dropped uid, so a `sudo touch` the
		// stub forwards really does create the file: the create is observable
		// here even though the stub is unprivileged.
		for _, p := range []string{envFile, scratch, outside} {
			if err := os.Chown(p, 65534, 65534); err != nil {
				t.Fatalf("chown %s: %v", p, err)
			}
		}
	}
	// Unwritable stack dir: this is what puts env_put on the sudo
	// lock-ownership path under test.
	if err := os.Chmod(stack, 0o555); err != nil { // #nosec G302 -- deliberately unwritable test dir
		t.Fatalf("chmod stack: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(stack, 0o755) }) // #nosec G302 -- restore so t.TempDir can remove it

	out, sudoCalls := envPutLockHarness(t, envFile, scratch, true)

	for _, call := range sudoCalls {
		if strings.Contains(call, ".env.lock") {
			t.Fatalf("env_put handed the planted .env.lock symlink to sudo (%q): `sudo touch` creates the "+
				"link's target as root and `sudo chown` hands it to the invoking sudoer (CWE-59). "+
				"All sudo calls: %v\noutput:\n%s", call, sudoCalls, out)
		}
	}
	if _, err := os.Lstat(planted); err == nil {
		t.Fatalf("env_put created %s through the planted .env.lock symlink", planted)
	} else if !os.IsNotExist(err) {
		t.Fatalf("lstat %s: %v", planted, err)
	}
	if !strings.Contains(out, "Refusing to use") {
		t.Errorf("env_put must say WHY it skipped the write; output:\n%s", out)
	}
}

// TestInstallScript_EnvPut_LockFifo_DoesNotHang covers the other non-regular
// file that must be refused: `9>` on a FIFO with no reader blocks forever, so a
// planted FIFO at the lock path wedges the installer instead of redirecting it.
func TestInstallScript_EnvPut_LockFifo_DoesNotHang(t *testing.T) {
	if _, err := exec.LookPath("mkfifo"); err != nil {
		t.Skip("mkfifo unavailable")
	}
	base := t.TempDir()
	stack := filepath.Join(base, "stack")
	scratch := filepath.Join(base, "tmp")
	for _, d := range []string{stack, scratch} {
		if err := os.Mkdir(d, 0o755); err != nil { // #nosec G301 -- plain test dir
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	envFile := filepath.Join(stack, ".env")
	if err := os.WriteFile(envFile, []byte("CULVERT_INSTALL_CHANNEL=stable\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	if err := exec.CommandContext(t.Context(), "mkfifo", envFile+".lock").Run(); err != nil { // #nosec G204 -- fixed args
		t.Skipf("mkfifo failed: %v", err)
	}

	// envPutLockBudget turns the wedge into a bounded failure rather than a
	// hang that takes the whole package down with it.
	out, _ := envPutLockHarness(t, envFile, scratch, false)
	if !strings.Contains(out, "Refusing to use") {
		t.Errorf("a FIFO at the lock path must be refused, not opened; output:\n%s", out)
	}
}

// TestInstallScript_EnvPut_RegularLockFileStillApplies is the negative control.
// The guard must refuse LINKS, not unwritable stack dirs: the foreign-owned
// re-run that env_put's sudo lock-ownership block exists to serve has an
// ordinary regular .env.lock and must still apply the value.
func TestInstallScript_EnvPut_RegularLockFileStillApplies(t *testing.T) {
	base := t.TempDir()
	stack := filepath.Join(base, "stack")
	scratch := filepath.Join(base, "tmp")
	for _, d := range []string{stack, scratch} {
		if err := os.Mkdir(d, 0o755); err != nil { // #nosec G301 -- must stay traversable by the dropped uid
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	envFile := filepath.Join(stack, ".env")
	if err := os.WriteFile(envFile, []byte("CULVERT_LOG_PASSPHRASE=keep\nCULVERT_INSTALL_CHANNEL=stable\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	if err := os.WriteFile(envFile+".lock", nil, 0o600); err != nil {
		t.Fatalf("seed .env.lock: %v", err)
	}
	if os.Getuid() == 0 {
		for _, p := range []string{filepath.Dir(base), base} {
			if err := os.Chmod(p, 0o755); err != nil { // #nosec G302 -- traversable by the dropped uid
				t.Fatalf("chmod %s: %v", p, err)
			}
		}
		for _, p := range []string{envFile, envFile + ".lock", scratch} {
			if err := os.Chown(p, 65534, 65534); err != nil {
				t.Fatalf("chown %s: %v", p, err)
			}
		}
	}
	if err := os.Chmod(stack, 0o555); err != nil { // #nosec G302 -- deliberately unwritable test dir
		t.Fatalf("chmod stack: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(stack, 0o755) }) // #nosec G302 -- restore so t.TempDir can remove it

	out, _ := envPutLockHarness(t, envFile, scratch, true)

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if !strings.Contains(string(got), "CULVERT_INSTALL_CHANNEL=lts\n") || strings.Contains(string(got), "CULVERT_INSTALL_CHANNEL=stable") {
		t.Fatalf("the link guard must not break the foreign-owned re-run it sits in front of: want the value "+
			"replaced, .env now:\n%s\noutput:\n%s", got, out)
	}
	if !strings.Contains(string(got), "CULVERT_LOG_PASSPHRASE=keep\n") {
		t.Fatalf("env_put lost an unrelated .env line; .env now:\n%s", got)
	}
}
