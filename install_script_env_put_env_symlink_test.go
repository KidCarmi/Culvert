package main

// install_script_env_put_env_symlink_test.go — env_put() must never act
// through a symlink at the env file itself with sudo (SEC-INSTALL-ENVLINK-1).
//
// The lock path is covered by install_script_env_put_lock_symlink_test.go. The
// env file is different because operators legitimately symlink it, so a link is
// not refused as such. What is refused:
//
//   - a DANGLING link: `-e` is false for it, so env_put used to treat it as a
//     missing file, and `touch`/`sudo touch` created the link's target (as root
//     on the sudo branch);
//   - handing a LIVE link to sudo: `sudo chown <me> "$file"` follows the link
//     and gives the invoking sudoer the target (`.env -> /etc/shadow`).
//
// The harness (envPutLockHarness) records every sudo call, so the privileged
// tests assert on what env_put ASKS SUDO TO DO: the stub runs at the test's own
// dropped privileges and cannot itself perform the root action.
//
// CWE-59 (link following) / CWE-61 (symlink attack).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// envSymlinkDirs creates base/{stack,outside,tmp} (0700) under a fresh temp dir
// and, when running as root, hands them to the unprivileged uid the harness
// drops to, so the dropped uid can traverse them without wider mode bits.
func envSymlinkDirs(t *testing.T) (stack, outside, scratch string) {
	t.Helper()
	base := t.TempDir()
	stack = filepath.Join(base, "stack")
	outside = filepath.Join(base, "outside")
	scratch = filepath.Join(base, "tmp")
	for _, d := range []string{stack, outside, scratch} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	if os.Getuid() == 0 {
		for _, p := range []string{filepath.Dir(base), base, stack, outside, scratch} {
			if err := os.Chown(p, 65534, 65534); err != nil {
				t.Fatalf("chown %s: %v", p, err)
			}
		}
	}
	return stack, outside, scratch
}

// sudoNamed reports whether any recorded sudo call has path as its last
// argument (the harness logs "$*", e.g. "chown nobody /x/.env").
func sudoNamed(calls []string, path string) (string, bool) {
	for _, c := range calls {
		f := strings.Fields(c)
		if len(f) > 0 && f[len(f)-1] == path {
			return c, true
		}
	}
	return "", false
}

// A dangling .env link in an ordinary, writable stack dir: no sudo is involved,
// but env_put's own `touch "$file"` used to create the link's target.
func TestInstallScript_EnvPut_DanglingEnvSymlink_CreatesNothing(t *testing.T) {
	stack, outside, scratch := envSymlinkDirs(t)
	envFile := filepath.Join(stack, ".env")
	target := filepath.Join(outside, "not-yet-there") // deliberately absent
	if err := os.Symlink(target, envFile); err != nil {
		t.Fatalf("plant .env symlink: %v", err)
	}

	out, sudoCalls := envPutLockHarness(t, envFile, scratch, false)

	if _, err := os.Lstat(target); err == nil {
		t.Fatalf("env_put created %s through the dangling .env symlink (CWE-59)\noutput:\n%s", target, out)
	} else if !os.IsNotExist(err) {
		t.Fatalf("lstat %s: %v", target, err)
	}
	if len(sudoCalls) != 0 {
		t.Errorf("no sudo call belongs on this path (the stack dir is writable); got %v", sudoCalls)
	}
	if !strings.Contains(out, "Refusing to use") {
		t.Errorf("env_put must say why it skipped the write; output:\n%s", out)
	}
}

// The privileged dangling case: with the stack dir unwritable, env_put used to
// reach `sudo touch "$file"`, which creates the link's target as root.
func TestInstallScript_EnvPut_DanglingEnvSymlink_IsNeverHandedToSudo(t *testing.T) {
	stack, outside, scratch := envSymlinkDirs(t)
	envFile := filepath.Join(stack, ".env")
	target := filepath.Join(outside, "sudoers.d-drop-in") // deliberately absent
	if err := os.Symlink(target, envFile); err != nil {
		t.Fatalf("plant .env symlink: %v", err)
	}
	if err := os.Chmod(stack, 0o500); err != nil {
		t.Fatalf("chmod stack: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(stack, 0o700) })

	out, sudoCalls := envPutLockHarness(t, envFile, scratch, true)

	if call, ok := sudoNamed(sudoCalls, envFile); ok {
		t.Fatalf("env_put handed the dangling .env symlink to sudo (%q): `sudo touch` creates its target as "+
			"root (CWE-59). All sudo calls: %v\noutput:\n%s", call, sudoCalls, out)
	}
	if _, err := os.Lstat(target); err == nil {
		t.Fatalf("env_put created %s through the dangling .env symlink", target)
	}
	if !strings.Contains(out, "Refusing to use") {
		t.Errorf("env_put must say why it skipped the write; output:\n%s", out)
	}
}

// A live .env link the invoker cannot write: env_put used to run
// `sudo chown <me> "$file"`, which follows the link and gives the invoker the
// target. It must degrade (warn and skip) instead.
func TestInstallScript_EnvPut_LiveEnvSymlink_TargetIsNeverChownedThroughSudo(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("needs root to seed a target the dropped uid cannot write")
	}
	stack, outside, scratch := envSymlinkDirs(t)
	envFile := filepath.Join(stack, ".env")
	target := filepath.Join(outside, "root-owned-secret")
	const secret = "root's content, which env_put must neither take nor change\n"
	if err := os.WriteFile(target, []byte(secret), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Chown(target, 0, 0); err != nil { // stays root-owned: unwritable for the dropped uid
		t.Fatalf("chown target: %v", err)
	}
	if err := os.Symlink(target, envFile); err != nil {
		t.Fatalf("plant .env symlink: %v", err)
	}

	out, sudoCalls := envPutLockHarness(t, envFile, scratch, true)

	if call, ok := sudoNamed(sudoCalls, envFile); ok {
		t.Fatalf("env_put handed the .env symlink to sudo (%q): `sudo chown` follows the link and gives the "+
			"invoker the target (CWE-59). All sudo calls: %v\noutput:\n%s", call, sudoCalls, out)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(got) != secret {
		t.Fatalf("env_put changed the link target %s:\n%s", target, got)
	}
	if !strings.Contains(out, "Cannot write") {
		t.Errorf("env_put must degrade with a warning when it cannot write a linked .env; output:\n%s", out)
	}
}

// Negative control: a symlinked .env the invoker CAN write keeps working.
// Operators do link their env file; the guard must refuse dangling links and
// sudo-through-links, not links.
func TestInstallScript_EnvPut_WritableEnvSymlinkStillApplies(t *testing.T) {
	stack, outside, scratch := envSymlinkDirs(t)
	envFile := filepath.Join(stack, ".env")
	target := filepath.Join(outside, "real.env")
	if err := os.WriteFile(target, []byte("CULVERT_LOG_PASSPHRASE=keep\nCULVERT_INSTALL_CHANNEL=stable\n"), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if err := os.Symlink(target, envFile); err != nil {
		t.Fatalf("link .env: %v", err)
	}

	out, sudoCalls := envPutLockHarness(t, envFile, scratch, false)

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if !strings.Contains(string(got), "CULVERT_INSTALL_CHANNEL=lts\n") || strings.Contains(string(got), "CULVERT_INSTALL_CHANNEL=stable") {
		t.Fatalf("a writable symlinked .env must still be updated; .env now:\n%s\noutput:\n%s", got, out)
	}
	if !strings.Contains(string(got), "CULVERT_LOG_PASSPHRASE=keep\n") {
		t.Fatalf("env_put lost an unrelated .env line; .env now:\n%s", got)
	}
	if strings.Contains(out, "Refusing to use") || len(sudoCalls) != 0 {
		t.Errorf("a writable linked .env needs no refusal and no sudo; sudo=%v output:\n%s", sudoCalls, out)
	}
}
