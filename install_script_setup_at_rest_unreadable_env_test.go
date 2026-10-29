package main

// install_script_setup_at_rest_unreadable_env_test.go — setup_at_rest_encryption()
// must not replace an at-rest passphrase it could not read.
//
// env_file_value_set answers 2 for an .env it cannot read (a root-owned 0600
// file left by a prior `sudo` install, re-run unprivileged). The CA branch of
// setup_at_rest_encryption() tested `! env_file_value_set …`, which is true
// for 2 as well as 1, so a host-environment CULVERT_CA_PASSPHRASE was appended
// over the CA passphrase already in the file (env_put then takes ownership
// via sudo and writes). The persisted, still-encrypted /data/ca.bundle then
// fails to decrypt and SSL inspection is silently disabled — the failure
// persist_host_env_session_secret() already guards against for the session key.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_SetupAtRestEncryption_UnreadableEnvKeepsExistingCAPassphrase(t *testing.T) {
	root := os.Getuid() == 0
	if root {
		if _, err := exec.LookPath("setpriv"); err != nil {
			t.Skip("setpriv unavailable: cannot drop root to make .env unreadable")
		}
	}
	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	if err := os.WriteFile(envFile, []byte("CULVERT_CA_PASSPHRASE=original-on-disk-value\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}
	if err := os.Chmod(envFile, 0o000); err != nil {
		t.Fatalf("chmod .env: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(envFile, 0o600) })
	if root {
		for _, p := range []string{filepath.Dir(dir), dir} {
			if err := os.Chmod(p, 0o755); err != nil {
				t.Fatalf("chmod %s: %v", p, err)
			}
			if err := os.Chown(p, 65534, 65534); err != nil {
				t.Fatalf("chown %s: %v", p, err)
			}
		}
		if err := os.Chown(envFile, 65534, 65534); err != nil {
			t.Fatalf("chown .env: %v", err)
		}
	}

	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := installSharedEnvPredicate(t) + "\n" + extractShellFunction(t, "scripts/install.sh", "secret_already_set")
	validateFn := extractShellFunction(t, "scripts/install.sh", "validate_passphrase_for_env_file")
	// `sudo chown <me> FILE` is modelled as the file becoming accessible to
	// this user, which is what it does for the operator in production.
	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
sudo() { if [[ "$1" == chown ]]; then chmod 600 "$3"; fi; }
INSTALL_DIR=` + dir + `
export CULVERT_CA_PASSPHRASE="different-host-env-value"
`
	script := stubs + secretFn + "\n" + envPutFn + "\n" + validateFn + "\n" + setupFn + "\nsetup_at_rest_encryption\n"

	var cmd *exec.Cmd
	if root {
		cmd = exec.CommandContext(t.Context(), "setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "bash", "-c", script) // #nosec G204 -- fixed test script content
	} else {
		cmd = exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("setup_at_rest_encryption failed: %v\n%s", err, out)
	}

	got, err := os.ReadFile(envFile)
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if !strings.Contains(string(got), "CULVERT_CA_PASSPHRASE=original-on-disk-value") ||
		strings.Contains(string(got), "different-host-env-value") {
		t.Fatalf("an .env that could not be read at check time had its CA passphrase replaced by the "+
			"host-env value, orphaning the encrypted CA bundle; .env now:\n%s", got)
	}
}
