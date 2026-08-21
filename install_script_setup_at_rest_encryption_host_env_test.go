package main

// install_script_setup_at_rest_encryption_host_env_test.go — regression
// coverage for a fresh-install failure mode: an operator supplies
// CULVERT_CA_PASSPHRASE / CULVERT_LOG_PASSPHRASE as a HOST environment
// variable (a natural way to script a non-interactive install — and exactly
// what secret_already_set()'s "${!var:-}" branch is designed to detect), but
// every docker compose invocation in install.sh runs as plain `sudo docker
// compose ...`. sudo's default env_reset policy strips arbitrary inherited
// variables from the child process, and docker compose interpolates
// ${CULVERT_CA_PASSPHRASE:-} in docker-compose.yml from ITS OWN process
// environment plus $INSTALL_DIR/.env — never from the shell that invoked the
// install script. So a host-env-only passphrase that setup_at_rest_encryption
// treats as "already configured" (and therefore never writes to .env) never
// actually reaches the container: the SSL-inspection Root CA private key ends
// up encrypted with an EMPTY passphrase instead of the operator's real one
// (or, on a redeploy against an existing encrypted CA bundle, decryption
// fails and SSL inspection silently disables — see warn_if_ssl_inspection_
// broken's own description of exactly this failure mode).
//
// Verified directly against sudo's actual behavior:
//
//	CULVERT_CA_PASSPHRASE=mysecret sudo docker compose config
//
// resolves the substitution to "" in this environment — this is not a
// hypothetical, it is sudo's documented env_reset default (also the default
// on Ubuntu/Debian/RHEL, the distros install.sh targets).
//
// Persisting a host-env value into .env must go through the same
// length/character-safety validation an operator-typed passphrase gets
// (validate_passphrase_for_env_file) — a too-short value is brute-forceable,
// and an unsafe character (above all a raw "$") gets re-interpolated by
// docker compose itself when the .env file is later read, so the value that
// reaches the container may not even be the value that was supplied.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runSetupAtRestEncryptionWithHostEnv assembles the REAL setup_at_rest_
// encryption() + its helpers out of scripts/install.sh, runs it with envSetup
// (a snippet exporting host-env passphrase vars) injected before the call,
// and returns stdout+stderr, the exit code, and the resulting .env content.
func runSetupAtRestEncryptionWithHostEnv(t *testing.T, dir, envSetup string) (output string, exitCode int, envContent string) {
	t.Helper()
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")
	validateFn := extractShellFunction(t, "scripts/install.sh", "validate_passphrase_for_env_file")

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
` + "INSTALL_DIR=" + dir + "\n" + envSetup + "\n"

	script := stubs + secretFn + "\n" + envPutFn + "\n" + validateFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

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

// TestInstallScript_SetupAtRestEncryption_PersistsHostEnvPassphrase proves
// that when CULVERT_CA_PASSPHRASE is supplied only via the host environment
// (not yet present in .env), setup_at_rest_encryption() persists it into
// $INSTALL_DIR/.env — the only place a later `sudo docker compose up` can
// actually read it from.
func TestInstallScript_SetupAtRestEncryption_PersistsHostEnvPassphrase(t *testing.T) {
	dir := t.TempDir()
	out, exitCode, envContent := runSetupAtRestEncryptionWithHostEnv(t, dir,
		`export CULVERT_CA_PASSPHRASE="host-supplied-passphrase-1234"`)

	if exitCode != 0 {
		t.Fatalf("setup_at_rest_encryption failed (exit %d); output:\n%s", exitCode, out)
	}
	if !strings.Contains(envContent, "CULVERT_CA_PASSPHRASE=host-supplied-passphrase-1234") {
		t.Fatalf("a CULVERT_CA_PASSPHRASE supplied only via the host environment was never persisted to "+
			"$INSTALL_DIR/.env. Every docker compose invocation in install.sh runs as plain `sudo docker "+
			"compose ...`, and sudo's default env_reset policy drops inherited variables from the child "+
			"process — docker compose can ONLY see this passphrase via .env. Without it, the SSL-inspection "+
			"Root CA key silently ends up encrypted with an empty passphrase (or, on a redeploy, an existing "+
			"encrypted CA bundle fails to decrypt and SSL inspection silently disables). .env content:\n%s", envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_HostEnvDoesNotOverrideExistingEnvFile
// proves the fix doesn't over-correct: when .env ALREADY has a value for the
// variable, a different host-env value must never overwrite it (env_put's
// "we never overwrite an existing value" contract, restated in
// setup_at_rest_encryption's own doc comment).
func TestInstallScript_SetupAtRestEncryption_HostEnvDoesNotOverrideExistingEnvFile(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("CULVERT_CA_PASSPHRASE=original-on-disk-value\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}

	out, exitCode, _ := runSetupAtRestEncryptionWithHostEnv(t, dir,
		`export CULVERT_CA_PASSPHRASE="different-host-env-value"`)
	if exitCode != 0 {
		t.Fatalf("setup_at_rest_encryption failed (exit %d); output:\n%s", exitCode, out)
	}

	envContent, rerr := os.ReadFile(envFile)
	if rerr != nil {
		t.Fatalf("read .env: %v", rerr)
	}
	if !strings.Contains(string(envContent), "CULVERT_CA_PASSPHRASE=original-on-disk-value") {
		t.Fatalf("an on-disk .env value was overwritten by a differing host-env value; .env content:\n%s", envContent)
	}
	if strings.Contains(string(envContent), "different-host-env-value") {
		t.Fatalf("the host-env value leaked into .env despite an existing on-disk value; .env content:\n%s", envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_RejectsTooShortHostEnvPassphrase
// proves that a host-env-supplied passphrase below the 12-character floor is
// rejected (fails closed) instead of being persisted at a brute-forceable
// strength — the same floor an operator-typed passphrase (choice 2) enforces.
func TestInstallScript_SetupAtRestEncryption_RejectsTooShortHostEnvPassphrase(t *testing.T) {
	dir := t.TempDir()
	out, exitCode, envContent := runSetupAtRestEncryptionWithHostEnv(t, dir,
		`export CULVERT_CA_PASSPHRASE="short"`)

	if exitCode == 0 {
		t.Fatalf("setup_at_rest_encryption accepted a 5-character host-env CULVERT_CA_PASSPHRASE instead of "+
			"failing closed; output:\n%s\n.env content:\n%s", out, envContent)
	}
	if strings.Contains(envContent, "short") {
		t.Fatalf("the too-short passphrase was written to .env despite a non-zero exit; .env content:\n%s", envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_RejectsUnsafeCharHostEnvPassphrase
// proves that a host-env-supplied passphrase containing a character docker
// compose's .env interpolation would reinterpret (a literal "$") is rejected
// rather than written raw — writing it as-is would let compose silently
// substitute a DIFFERENT value than the one the operator actually supplied
// the next time `sudo docker compose up` reads .env.
func TestInstallScript_SetupAtRestEncryption_RejectsUnsafeCharHostEnvPassphrase(t *testing.T) {
	dir := t.TempDir()
	out, exitCode, envContent := runSetupAtRestEncryptionWithHostEnv(t, dir,
		`export CULVERT_CA_PASSPHRASE='unsafe$dollarSignPassphrase123'`)

	if exitCode == 0 {
		t.Fatalf("setup_at_rest_encryption accepted a host-env CULVERT_CA_PASSPHRASE containing \"$\" instead of "+
			"failing closed; output:\n%s\n.env content:\n%s", out, envContent)
	}
	if strings.Contains(envContent, "dollarSignPassphrase") {
		t.Fatalf("the unsafe-character passphrase was written to .env despite a non-zero exit; .env content:\n%s", envContent)
	}
}
