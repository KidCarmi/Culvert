package main

// install_script_session_secret_errexit_test.go — scripts/install.sh runs under
// `set -euo pipefail`, but the sibling tests run persist_host_env_session_secret
// in a bare `bash -c` where errexit is off. This pins the real-installer shape:
// an existing .env that lacks CULVERT_SESSION_SECRET (grep exit 1) must fall
// through to persisting the host-env value, not abort the install.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_PersistSessionSecret_UnderErrexit_ExistingEnvWithoutSecret(t *testing.T) {
	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "persist_host_env_session_secret")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("CULVERT_LOG_PASSPHRASE=abcdefghijklmnop\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("ab", 32)

	script := "set -euo pipefail\n" +
		"info() { :; }\nwarn() { :; }\nerror() { echo \"ERROR: $*\" >&2; exit 7; }\n" +
		"INSTALL_DIR=" + dir + "\nexport CULVERT_SESSION_SECRET=" + secret + "\n" +
		envPutFn + "\n" + fn + "\n" +
		"persist_host_env_session_secret\necho REACHED_END\n"

	out, err := exec.CommandContext(t.Context(), "bash", "-c", script).CombinedOutput() // #nosec G204 -- fixed test script content
	if err != nil || !strings.Contains(string(out), "REACHED_END") {
		t.Fatalf("persist_host_env_session_secret aborted under set -e: err=%v out=%q", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(dir, ".env"))
	if !strings.Contains(string(b), "CULVERT_SESSION_SECRET="+secret) {
		t.Fatalf("secret not persisted; .env=%q", b)
	}
}
