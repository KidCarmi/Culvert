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

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestInstallScript_SetupAtRestEncryption_PersistsHostEnvPassphrase proves
// that when CULVERT_CA_PASSPHRASE is supplied only via the host environment
// (not yet present in .env), setup_at_rest_encryption() persists it into
// $INSTALL_DIR/.env — the only place a later `sudo docker compose up` can
// actually read it from.
func TestInstallScript_SetupAtRestEncryption_PersistsHostEnvPassphrase(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	dir := t.TempDir()

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
` + "INSTALL_DIR=" + dir + "\n" +
		`export CULVERT_CA_PASSPHRASE="host-supplied-passphrase-1234"` + "\n"

	script := stubs + secretFn + "\n" + envPutFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("setup_at_rest_encryption failed: %v\n%s", err, out)
	}

	envContent := ""
	if b, rerr := os.ReadFile(filepath.Join(dir, ".env")); rerr == nil {
		envContent = string(b)
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
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("CULVERT_CA_PASSPHRASE=original-on-disk-value\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
` + "INSTALL_DIR=" + dir + "\n" +
		`export CULVERT_CA_PASSPHRASE="different-host-env-value"` + "\n"

	script := stubs + secretFn + "\n" + envPutFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("setup_at_rest_encryption failed: %v\n%s", err, out)
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
