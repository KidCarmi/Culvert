package main

// install_script_env_selfheal_symlink_test.go — SEC-INSTALL-ENVLINK-1 at the
// EARLY self-heal sites, not just inside env_put.
//
// PR #1898/#1909 established the contract that `sudo` must never act THROUGH a
// symlink at $INSTALL_DIR/.env, because `sudo chown <me> "$file"` follows the
// link and hands the invoking sudoer the TARGET (`.env -> /etc/shadow`), and
// whoever can write the stack dir can plant one. It enforced that inside
// env_put only. Two other functions take ownership of the SAME path with the
// same primitive, guarded only by `-e`/`! -r`, which both FOLLOW links:
//
//	setup_at_rest_encryption
//	persist_host_env_session_secret
//
// Both run BEFORE the first env_put at top level, so the guard that existed
// could not cover them and the escalation happened first. These tests pin the
// guard at the early sites.
//
// As with the env_put harness, the sudo stub runs at the test's own dropped
// privileges and cannot perform the root action, so the assertion is on what
// the script ASKS SUDO TO DO.
//
// CWE-59 (link following) / CWE-61 (symlink attack) → CWE-269.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// persistSecretHarness runs the extracted persist_host_env_session_secret
// against envFile with every dependency stubbed, and returns its output plus
// the sudo calls it asked for. Privileges are dropped when running as root so
// that a mode-0000 file is genuinely unreadable (root bypasses the check, which
// would make the positive control vacuous).
func persistSecretHarness(t *testing.T, stack, scratch string) (out string, sudoCalls []string) {
	t.Helper()
	sudoLog := filepath.Join(scratch, "sudo.log")
	fn := extractShellFunction(t, "scripts/install.sh", "persist_host_env_session_secret")
	script := `set -euo pipefail
info() { :; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; exit 1; }
sudo() { echo "$*" >> "$SUDO_LOG"; return 0; }
env_file_value_set() { return 1; }   # absent: fall through to the persist path
env_put_required() { echo "env_put_required $*" >&2; }
INSTALL_DIR="$1"
` + fn + `
persist_host_env_session_secret
`
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	args := []string{"-c", script, "install_script_env_selfheal_symlink_test", stack}
	var cmd *exec.Cmd
	if os.Getuid() == 0 {
		if _, err := exec.LookPath("setpriv"); err != nil {
			t.Skip("setpriv unavailable: cannot drop root, and root reads a mode-0000 file regardless")
		}
		cmd = exec.CommandContext(ctx, "setpriv",
			append([]string{"--reuid=65534", "--regid=65534", "--clear-groups", "bash"}, args...)...) // #nosec G204 -- fixed test script content
	} else {
		cmd = exec.CommandContext(ctx, "bash", args...) // #nosec G204 -- fixed test script content
	}
	cmd.Env = append(os.Environ(),
		"TMPDIR="+scratch,
		"SUDO_LOG="+sudoLog,
		// 64 hex chars, so the shape check downstream of the guard passes.
		"CULVERT_SESSION_SECRET="+strings.Repeat("a", 64),
	)
	cmd.WaitDelay = 5 * time.Second
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("persist_host_env_session_secret must degrade rather than fail: %v\n%s", err, raw)
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

// A LIVE .env symlink whose target the invoker cannot read is the escalation
// case: `-e` is true and `! -r` is true, so the unguarded self-heal asked sudo
// to chown the link — which lands on the TARGET the planter chose.
func TestInstallScript_PersistSecret_LiveEnvSymlink_IsNeverHandedToSudo(t *testing.T) {
	stack, outside, scratch := envSymlinkDirs(t)
	envFile := filepath.Join(stack, ".env")
	victim := filepath.Join(outside, "shadow-stand-in")
	if err := os.WriteFile(victim, []byte("root:$6$planted::::::\n"), 0o000); err != nil {
		t.Fatalf("seed unreadable victim: %v", err)
	}
	if err := os.Symlink(victim, envFile); err != nil {
		t.Fatalf("plant .env symlink: %v", err)
	}

	out, sudoCalls := persistSecretHarness(t, stack, scratch)

	if call, found := sudoNamed(sudoCalls, envFile); found {
		t.Errorf("persist_host_env_session_secret handed a symlinked .env to sudo (%q) — "+
			"chown follows the link and gives the invoking sudoer %s (CWE-59)\noutput:\n%s", call, victim, out)
	}
	if call, found := sudoNamed(sudoCalls, victim); found {
		t.Errorf("sudo was asked to act on the link TARGET directly (%q)\noutput:\n%s", call, out)
	}
}

// Positive control: the guard must be narrow. A REGULAR unreadable .env is the
// case the self-heal exists for, and it must still take ownership — otherwise
// this fix would have silently disabled a working repair path.
func TestInstallScript_PersistSecret_RegularUnreadableEnv_StillSelfHeals(t *testing.T) {
	stack, _, scratch := envSymlinkDirs(t)
	envFile := filepath.Join(stack, ".env")
	if err := os.WriteFile(envFile, []byte("CULVERT_OTHER=1\n"), 0o000); err != nil {
		t.Fatalf("seed unreadable .env: %v", err)
	}

	out, sudoCalls := persistSecretHarness(t, stack, scratch)

	call, found := sudoNamed(sudoCalls, envFile)
	if !found {
		t.Fatalf("a REGULAR unreadable .env must still be self-healed via sudo chown; "+
			"sudo calls were %v\noutput:\n%s", sudoCalls, out)
	}
	if !strings.HasPrefix(call, "chown ") {
		t.Errorf("expected the self-heal to be a chown, got %q", call)
	}
}

// TestInstallScript_EnvSelfHealChownSitesAreLinkGuarded is the drift guard.
//
// The behavioural test above covers persist_host_env_session_secret, which
// extracts cleanly. setup_at_rest_encryption does not (its first unindented
// brace falls past the top-level call site), and a future function could add a
// third site. So assert the contract structurally over the whole script: every
// `sudo chown … "$envfile"` must have an `-L "$envfile"` test in the lines
// immediately above it. This is what actually failed before — the contract was
// honoured at one site and not at the others.
func TestInstallScript_EnvSelfHealChownSitesAreLinkGuarded(t *testing.T) {
	// Anchored to the package source dir for the same reason the SPA reads are
	// (see TestTestFileReadsAreCWDIndependent): a concurrent os.Chdir must not
	// be able to turn this wall into a flake.
	raw, err := os.ReadFile(filepath.Join(pkgSourceDir(), "scripts", "install.sh"))
	if err != nil {
		t.Fatalf("read installer: %v", err)
	}
	lines := strings.Split(string(raw), "\n")
	chownEnvfile := regexp.MustCompile(`sudo\s+chown\s+.*"\$envfile"`)
	linkGuard := regexp.MustCompile(`-L\s+"\$envfile"`)

	const lookback = 10
	sites := 0
	for i, line := range lines {
		if !chownEnvfile.MatchString(line) {
			continue
		}
		sites++
		guarded := false
		for j := i - 1; j >= 0 && j >= i-lookback; j-- {
			if linkGuard.MatchString(lines[j]) {
				guarded = true
				break
			}
		}
		if !guarded {
			t.Errorf("scripts/install.sh:%d: `sudo chown` on $envfile with no `-L \"$envfile\"` guard "+
				"within %d lines above it — sudo would act THROUGH a planted symlink and hand the "+
				"invoking sudoer an attacker-chosen path (SEC-INSTALL-ENVLINK-1, CWE-59):\n\t%s",
				i+1, lookback, strings.TrimSpace(line))
		}
	}
	if sites == 0 {
		t.Fatal("found no `sudo chown … \"$envfile\"` site: this guard has lost its subject, " +
			"so update it rather than letting it pass vacuously")
	}
}

// carryForwardHarness runs the extracted carry_forward_prior_secrets with a
// prior deployment seeded at $BASE/Culvert/.env and every dependency stubbed.
//
// The sudo stub PERFORMS the copy with cp, which follows a symlinked
// destination exactly as `install` does. That effect is real at the test's own
// privilege (the victim path is test-owned), so the assertion is on the file
// system rather than only on the recorded call.
func carryForwardHarness(t *testing.T, base, stack, scratch string) (out string, sudoCalls []string) {
	t.Helper()
	sudoLog := filepath.Join(scratch, "sudo.log")
	fn := extractShellFunction(t, "scripts/install.sh", "carry_forward_prior_secrets")
	script := `set -euo pipefail
info() { :; }
warn() { echo "WARN: $*" >&2; }
sudo() {
  echo "$*" >> "$SUDO_LOG"
  case "$1" in
    install)
      # Model install's destination handling: it opens the destination
      # O_CREAT|O_TRUNC, which FOLLOWS a symlink there. cp does the same.
      eval "src=\${$(($#-1))}; dst=\${$#}"
      cp -- "$src" "$dst"
      ;;
    *) return 1 ;;
  esac
}
getent() { echo "tester:x:0:0::$BASE:/bin/sh"; }
INSTALL_DIR="$1"
` + fn + `
carry_forward_prior_secrets
`
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script, //nolint:gosec // fixed test script content
		"install_script_env_selfheal_symlink_test", stack)
	cmd.Env = append(os.Environ(), "TMPDIR="+scratch, "SUDO_LOG="+sudoLog, "BASE="+base, "SUDO_USER=tester")
	cmd.WaitDelay = 5 * time.Second
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("carry_forward_prior_secrets must never be fatal: %v\n%s", err, raw)
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

// `-f "$INSTALL_DIR/.env"` is FALSE for a DANGLING link, so the early return
// missed it and `sudo install` wrote the PRIOR stack's secrets through the link
// — as root, to a path the planter chose.
func TestInstallScript_CarryForward_DanglingEnvSymlink_WritesNothingThrough(t *testing.T) {
	const secret = "CULVERT_CA_PASSPHRASE=prior-stack-secret\n"
	stack, outside, scratch := envSymlinkDirs(t)
	base := filepath.Dir(stack)

	prior := filepath.Join(base, "Culvert")
	if err := os.Mkdir(prior, 0o700); err != nil {
		t.Fatalf("mkdir prior: %v", err)
	}
	if err := os.WriteFile(filepath.Join(prior, ".env"), []byte(secret), 0o600); err != nil {
		t.Fatalf("seed prior .env: %v", err)
	}

	victim := filepath.Join(outside, "cron.d-drop-in") // deliberately absent
	if err := os.Symlink(victim, filepath.Join(stack, ".env")); err != nil {
		t.Fatalf("plant dangling .env symlink: %v", err)
	}

	out, sudoCalls := carryForwardHarness(t, base, stack, scratch)

	if b, err := os.ReadFile(victim); err == nil {
		t.Errorf("carry_forward_prior_secrets wrote through the dangling .env symlink to %s (CWE-59); "+
			"content now %q\nsudo calls: %v\noutput:\n%s", victim, string(b), sudoCalls, out)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat victim: %v", err)
	}
	if !strings.Contains(out, "Refusing to carry secrets forward") {
		t.Errorf("the skip must say why; output:\n%s", out)
	}
}

// Positive control: with no .env present at all — the case this function exists
// for — the prior secrets must still be carried forward.
func TestInstallScript_CarryForward_NoEnv_StillCarriesForward(t *testing.T) {
	const secret = "CULVERT_CA_PASSPHRASE=prior-stack-secret\n"
	stack, _, scratch := envSymlinkDirs(t)
	base := filepath.Dir(stack)

	prior := filepath.Join(base, "Culvert")
	if err := os.Mkdir(prior, 0o700); err != nil {
		t.Fatalf("mkdir prior: %v", err)
	}
	if err := os.WriteFile(filepath.Join(prior, ".env"), []byte(secret), 0o600); err != nil {
		t.Fatalf("seed prior .env: %v", err)
	}

	out, sudoCalls := carryForwardHarness(t, base, stack, scratch)

	got, err := os.ReadFile(filepath.Join(stack, ".env"))
	if err != nil {
		t.Fatalf("the prior .env must still be carried forward: %v\nsudo calls: %v\noutput:\n%s",
			err, sudoCalls, out)
	}
	if string(got) != secret {
		t.Errorf("carried-forward content = %q, want %q", string(got), secret)
	}
}
