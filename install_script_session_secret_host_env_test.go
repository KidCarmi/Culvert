package main

// install_script_session_secret_host_env_test.go — regression coverage for a
// fresh-install failure mode: docs/OPERATIONS.md §3 tells an operator setting
// up a multi-node deployment to "set CULVERT_SESSION_SECRET ... on every
// node" so admin sessions stay valid cluster-wide, and exporting it as a host
// environment variable is the natural non-interactive way to do that (it is
// exactly what setup_at_rest_encryption() already does for
// CULVERT_LOG_PASSPHRASE/CULVERT_CA_PASSPHRASE, and what
// install_script_setup_at_rest_encryption_host_env_test.go pins for those two
// variables). But every docker compose invocation in install.sh runs as
// plain `sudo docker compose ...` (no `-E`), and sudo's default env_reset
// policy strips inherited variables from the child process — docker compose
// interpolates ${CULVERT_SESSION_SECRET:-} in docker-compose.yml from ITS OWN
// process environment plus $INSTALL_DIR/.env, never from the shell that
// invoked the install script. Before this fix, install.sh had NO handling at
// all for CULVERT_SESSION_SECRET (unlike the CA/log passphrases), so a
// host-env-only value was silently dropped: every node fell back to its own
// random per-process signing key (session.InitRandomKey, session.go) instead
// of the shared cluster key the operator asked for, and admin sessions
// silently stopped validating across nodes — no error, no warning, just
// cluster-wide logouts on the next session-affinity miss.
//
// Verified directly against sudo's actual behavior:
//
//	CULVERT_SESSION_SECRET=$(openssl rand -hex 32) sudo docker compose config
//
// resolves the substitution to "" in this environment — the same env_reset
// default install_script_setup_at_rest_encryption_host_env_test.go documents.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runPersistHostEnvSessionSecret assembles the REAL persist_host_env_session_
// secret() + its helpers out of scripts/install.sh, runs it with envSetup (a
// snippet exporting a host-env CULVERT_SESSION_SECRET) injected before the
// call, and returns stdout+stderr, the exit code, and the resulting .env
// content.
func runPersistHostEnvSessionSecret(t *testing.T, dir, envSetup string) (output string, exitCode int, envContent string) {
	t.Helper()
	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "persist_host_env_session_secret")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
` + "INSTALL_DIR=" + dir + "\n" + envSetup + "\n"

	script := stubs + envPutFn + "\n" + fn + "\n" + "persist_host_env_session_secret\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()

	exitCode = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("shell script failed to run: %v\n%s", err, out)
		}
	}

	envContent = ""
	if b, rerr := os.ReadFile(filepath.Join(dir, ".env")); rerr == nil {
		envContent = string(b)
	}
	return string(out), exitCode, envContent
}

// runPersistHostEnvSessionSecretWithStub is runPersistHostEnvSessionSecret
// plus an extra shell snippet (stubbedBuiltins) inserted AFTER the real
// function definitions but BEFORE the call, so a test can shadow a builtin
// like `grep` to simulate a real read failure (EACCES) without needing to
// actually run as an unprivileged user against a root-owned file.
func runPersistHostEnvSessionSecretWithStub(t *testing.T, dir, envSetup, stubbedBuiltins string) (output string, exitCode int, envContent string) {
	t.Helper()
	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "persist_host_env_session_secret")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")

	stubs := `
info() { :; }
warn() { echo "WARN: $*" >&2; }
error() { echo "ERROR: $*" >&2; exit 7; }
sudo() { :; }
` + "INSTALL_DIR=" + dir + "\n" + envSetup + "\n"

	script := stubs + envPutFn + "\n" + fn + "\n" + stubbedBuiltins + "\n" + "persist_host_env_session_secret\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()

	exitCode = 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			t.Fatalf("shell script failed to run: %v\n%s", err, out)
		}
	}

	envContent = ""
	if b, rerr := os.ReadFile(filepath.Join(dir, ".env")); rerr == nil {
		envContent = string(b)
	}
	return string(out), exitCode, envContent
}

// TestInstallScript_PersistHostEnvSessionSecret_UnreadableExistingValueIsNeverOverwritten
// proves the Codex-flagged defect (PR #1310 review): on an unprivileged
// rerun after a prior root/sudo install left .env owned by root, a read of
// the existing CULVERT_SESSION_SECRET line can fail with a real error
// (EACCES, simulated here via a shadowed grep returning exit 2) rather than
// "pattern not found" (exit 1). Conflating that failure with absence would
// fall through to env_put, which performs its own ownership self-heal and
// would then unconditionally overwrite the real existing signing key it
// never actually saw — silently invalidating cluster sessions. The fix must
// distinguish "confirmed absent" (grep exit 1) from "could not verify" (any
// other exit) and leave the file untouched in the latter case.
func TestInstallScript_PersistHostEnvSessionSecret_UnreadableExistingValueIsNeverOverwritten(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	existing := strings.Repeat("33", 32)
	if err := os.WriteFile(envFile, []byte("CULVERT_SESSION_SECRET="+existing+"\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}

	hostEnv := strings.Repeat("44", 32)
	// Simulate a real read failure (e.g. permission denied) on EVERY grep
	// call, regardless of what the file actually contains — this is exactly
	// what an unreadable-to-this-user root-owned file looks like from the
	// script's point of view.
	out, exitCode, envContent := runPersistHostEnvSessionSecretWithStub(t, dir,
		`export CULVERT_SESSION_SECRET="`+hostEnv+`"`,
		`grep() { return 2; }`)

	if exitCode != 0 {
		t.Fatalf("persist_host_env_session_secret should fail safe (exit 0, warn-and-skip) on an unreadable "+
			"existing .env, not error out; exit %d, output:\n%s", exitCode, out)
	}
	if !strings.Contains(envContent, "CULVERT_SESSION_SECRET="+existing) {
		t.Fatalf("an existing CULVERT_SESSION_SECRET that could not be VERIFIED present (simulated read "+
			"failure) was overwritten anyway — a permission-denied read must never be treated as \"not "+
			"configured\". .env content:\n%s", envContent)
	}
	if strings.Contains(envContent, hostEnv) {
		t.Fatalf("the host-env value was written despite the existing entry being unverifiable; .env content:\n%s", envContent)
	}
}

// TestInstallScript_PersistHostEnvSessionSecret_PersistsToEnvFile proves that
// a CULVERT_SESSION_SECRET supplied only via the host environment gets
// written into $INSTALL_DIR/.env — the only place a later plain `sudo docker
// compose up` (no `-E`) can actually read it from.
func TestInstallScript_PersistHostEnvSessionSecret_PersistsToEnvFile(t *testing.T) {
	dir := t.TempDir()
	secret := strings.Repeat("ab", 32) // 64 hex chars = 32 bytes
	out, exitCode, envContent := runPersistHostEnvSessionSecret(t, dir,
		`export CULVERT_SESSION_SECRET="`+secret+`"`)

	if exitCode != 0 {
		t.Fatalf("persist_host_env_session_secret failed (exit %d); output:\n%s", exitCode, out)
	}
	if !strings.Contains(envContent, "CULVERT_SESSION_SECRET="+secret) {
		t.Fatalf("a CULVERT_SESSION_SECRET supplied only via the host environment was never persisted to "+
			"$INSTALL_DIR/.env. Every docker compose invocation in install.sh runs as plain `sudo docker "+
			"compose ...`, and sudo's default env_reset policy drops inherited variables from the child "+
			"process — docker compose can ONLY see this secret via .env. Without it, every node silently "+
			"falls back to its own random session-signing key and admin sessions stop validating cluster-wide "+
			"with no warning. .env content:\n%s", envContent)
	}
}

// TestInstallScript_PersistHostEnvSessionSecret_DoesNotOverrideExistingEnvFile
// proves the fix doesn't over-correct: when .env already has a value, a
// different host-env value must never overwrite it (env_put's "never
// overwrite an existing value" contract).
func TestInstallScript_PersistHostEnvSessionSecret_DoesNotOverrideExistingEnvFile(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	onDisk := strings.Repeat("11", 32)
	if err := os.WriteFile(envFile, []byte("CULVERT_SESSION_SECRET="+onDisk+"\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}

	hostEnv := strings.Repeat("22", 32)
	out, exitCode, envContent := runPersistHostEnvSessionSecret(t, dir,
		`export CULVERT_SESSION_SECRET="`+hostEnv+`"`)
	if exitCode != 0 {
		t.Fatalf("persist_host_env_session_secret failed (exit %d); output:\n%s", exitCode, out)
	}
	if !strings.Contains(envContent, "CULVERT_SESSION_SECRET="+onDisk) {
		t.Fatalf("an on-disk .env value was overwritten by a differing host-env value; .env content:\n%s", envContent)
	}
	if strings.Contains(envContent, hostEnv) {
		t.Fatalf("the host-env value leaked into .env despite an existing on-disk value; .env content:\n%s", envContent)
	}
}

// TestInstallScript_PersistHostEnvSessionSecret_RejectsShortHostEnvSecret
// proves that a host-env-supplied secret shorter than the 64-hex-char (32
// byte) floor session.go's initSessionSecret() enforces is rejected (fails
// closed) rather than persisted, which would make every node panic/crash-loop
// on boot instead of failing the install with a clear message up front.
func TestInstallScript_PersistHostEnvSessionSecret_RejectsShortHostEnvSecret(t *testing.T) {
	dir := t.TempDir()
	out, exitCode, envContent := runPersistHostEnvSessionSecret(t, dir,
		`export CULVERT_SESSION_SECRET="deadbeef"`)

	if exitCode == 0 {
		t.Fatalf("persist_host_env_session_secret accepted an 8-character host-env CULVERT_SESSION_SECRET "+
			"instead of failing closed; output:\n%s\n.env content:\n%s", out, envContent)
	}
	if strings.Contains(envContent, "deadbeef") {
		t.Fatalf("the too-short secret was written to .env despite a non-zero exit; .env content:\n%s", envContent)
	}
}

// TestInstallScript_PersistHostEnvSessionSecret_RejectsNonHexHostEnvSecret
// proves that a host-env-supplied secret containing non-hex characters is
// rejected rather than persisted verbatim — session.go's hex.DecodeString
// would reject it at boot anyway, so failing here gives an actionable error
// instead of a boot-time panic on every node.
func TestInstallScript_PersistHostEnvSessionSecret_RejectsNonHexHostEnvSecret(t *testing.T) {
	dir := t.TempDir()
	notHex := strings.Repeat("zz", 32) // right length, wrong alphabet
	out, exitCode, envContent := runPersistHostEnvSessionSecret(t, dir,
		`export CULVERT_SESSION_SECRET="`+notHex+`"`)

	if exitCode == 0 {
		t.Fatalf("persist_host_env_session_secret accepted a non-hex host-env CULVERT_SESSION_SECRET instead "+
			"of failing closed; output:\n%s\n.env content:\n%s", out, envContent)
	}
	if strings.Contains(envContent, notHex) {
		t.Fatalf("the non-hex secret was written to .env despite a non-zero exit; .env content:\n%s", envContent)
	}
}

// TestInstallScript_PersistHostEnvSessionSecret_NoHostEnvIsANoop proves the
// common case (no CULVERT_SESSION_SECRET at all) does nothing — no .env
// created, no error.
func TestInstallScript_PersistHostEnvSessionSecret_NoHostEnvIsANoop(t *testing.T) {
	dir := t.TempDir()
	out, exitCode, envContent := runPersistHostEnvSessionSecret(t, dir, "")

	if exitCode != 0 {
		t.Fatalf("persist_host_env_session_secret failed with no CULVERT_SESSION_SECRET set (exit %d); output:\n%s", exitCode, out)
	}
	if envContent != "" {
		t.Fatalf("expected no .env content with no CULVERT_SESSION_SECRET set, got:\n%s", envContent)
	}
}
