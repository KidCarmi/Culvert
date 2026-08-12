package main

// install_script_setup_at_rest_encryption_test.go — regression coverage for
// the setup_at_rest_encryption() helper in scripts/install.sh, which prompts
// an operator for the CULVERT_LOG_PASSPHRASE / CULVERT_CA_PASSPHRASE stored
// in $INSTALL_DIR/.env. Those values are used verbatim as PBKDF2-SHA256 input
// (internal/ca/ca.go: EncryptBundle, 600k iterations) to AES-256-GCM-encrypt
// the SSL-inspection Root CA private key and saved request logs at rest — the
// same key material MITM interception depends on.
//
// This extracts the REAL setup_at_rest_encryption() + env_put() function
// bodies out of scripts/install.sh (rather than duplicating them here) and
// exercises them under bash, so the test tracks the actual installer script
// instead of a copy that can drift.
//
// choice=2 ("Enter my own passphrase") only validates: non-empty, confirmation
// match, and a safe .env character set. There is NO minimum length check —
// neither here nor anywhere the passphrase is later consumed
// (internal/ca/ca.go has none either) — so an operator who picks this option
// can encrypt the CA key and logstore with a single-character passphrase,
// which a PBKDF2 attacker brute-forces instantly regardless of 600k
// iterations. Non-interactive/auto-generated installs (the default, and the
// only path CI's install-lifecycle-e2e exercises) are unaffected: they always
// produce a 40-character random passphrase via gen_passphrase and never reach
// this code path.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runSetupAtRestEncryptionChoice2 drives the REAL setup_at_rest_encryption()
// (forced into the "enter my own passphrase" branch) with the given
// passphrase entered twice (as if typed at both prompts), and returns the
// combined stdout+stderr, the process exit code, and the resulting .env
// content (empty if the file was never written).
func runSetupAtRestEncryptionChoice2(t *testing.T, passphrase string) (output string, exitCode int, envContent string) {
	t.Helper()
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")

	// setup_at_rest_encryption only reaches the "own passphrase" branch when
	// stdin is a TTY (`[[ -t 0 ]]`) and the operator types "2" at the prompt.
	// A non-TTY test harness can't fake that, so force the default straight to
	// "2" — this exercises exactly the same case-2 validation block a real
	// interactive operator's choice would run.
	setupFn = strings.Replace(setupFn, `local choice="1"`, `local choice="2"`, 1)

	dir := t.TempDir()

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 1; }
secret_already_set() { return 1; }
` + "INSTALL_DIR=" + dir + "\n"

	script := stubs + envPutFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	cmd.Stdin = bytes.NewBufferString(passphrase + "\n" + passphrase + "\n")
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

// TestInstallScript_SetupAtRestEncryption_RejectsTrivialPassphrase proves that
// an operator-entered passphrase too short to resist brute-force (here, a
// single character) is REJECTED rather than silently used to encrypt the
// SSL-inspection CA private key and saved logs at rest.
func TestInstallScript_SetupAtRestEncryption_RejectsTrivialPassphrase(t *testing.T) {
	output, exitCode, envContent := runSetupAtRestEncryptionChoice2(t, "a")

	if exitCode == 0 {
		t.Fatalf("setup_at_rest_encryption accepted a 1-character passphrase (\"a\") for CA-key/log "+
			"encryption at rest — it should be rejected as too weak to resist a PBKDF2 brute-force. "+
			"output:\n%s\n.env content:\n%s", output, envContent)
	}
	if strings.Contains(envContent, "PASSPHRASE=a\n") {
		t.Fatalf("a trivial 1-character passphrase was written to .env despite a non-zero exit; "+
			".env content:\n%s", envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_AcceptsStrongPassphrase is the
// baseline sanity check: a reasonably long operator-supplied passphrase is
// still accepted and persisted, so the length floor does not regress the
// legitimate case.
func TestInstallScript_SetupAtRestEncryption_AcceptsStrongPassphrase(t *testing.T) {
	strong := "Correct-Horse-Battery-42"
	output, exitCode, envContent := runSetupAtRestEncryptionChoice2(t, strong)

	if exitCode != 0 {
		t.Fatalf("setup_at_rest_encryption rejected a strong %d-character passphrase (exit %d); output:\n%s",
			len(strong), exitCode, output)
	}
	if !strings.Contains(envContent, "CULVERT_LOG_PASSPHRASE="+strong) {
		t.Fatalf(".env does not contain the expected passphrase; .env content:\n%s", envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_FreshDeployWithPriorLogPassphraseStillEncryptsCA
// proves that a FRESH deployment (is_fresh_deployment == true) whose .env
// already carries a CULVERT_LOG_PASSPHRASE — e.g. exported by an automated/
// scripted install, or left over from an interrupted prior run — still ends
// up with the SSL-inspection Root CA private key encrypted at rest.
//
// This uses the REAL secret_already_set() (not stubbed), because the bug
// this guards against lives in how setup_at_rest_encryption()'s early-return
// guard combines secret_already_set for BOTH variables: on a fresh
// deployment with only CULVERT_LOG_PASSPHRASE pre-set, the guard used to
// treat encryption as "already configured" and return immediately, printing
// a message that implies encryption is configured while silently leaving
// CULVERT_CA_PASSPHRASE unset — so the CA private key generated on this
// fresh install is stored unencrypted, with no warning at all (roadmap:
// CA-at-rest encryption is a documented security surface, see CLAUDE.md).
func TestInstallScript_SetupAtRestEncryption_FreshDeployWithPriorLogPassphraseStillEncryptsCA(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	const priorLogPass = "already-set-log-passphrase-1234"
	if err := os.WriteFile(envFile, []byte("CULVERT_LOG_PASSPHRASE="+priorLogPass+"\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
` + "INSTALL_DIR=" + dir + "\n"

	script := stubs + secretFn + "\n" + envPutFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	cmd.Stdin = bytes.NewReader(nil)                              // non-interactive: stdin is not a TTY
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("setup_at_rest_encryption failed: %v\n%s", err, out)
	}

	got, rerr := os.ReadFile(envFile)
	if rerr != nil {
		t.Fatalf("read %s: %v", envFile, rerr)
	}
	envContent := string(got)

	if !strings.Contains(envContent, "CULVERT_LOG_PASSPHRASE="+priorLogPass) {
		t.Fatalf("the pre-existing CULVERT_LOG_PASSPHRASE was lost/changed; .env content:\n%s", envContent)
	}
	if !strings.Contains(envContent, "CULVERT_CA_PASSPHRASE=") {
		t.Fatalf("fresh deployment left the SSL-inspection CA private key UNENCRYPTED at rest: "+
			"CULVERT_LOG_PASSPHRASE was already configured, so setup_at_rest_encryption() bailed out "+
			"entirely without ever setting CULVERT_CA_PASSPHRASE. output:\n%s\n.env content:\n%s",
			out, envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_FreshDeployWithUnsafeHostLogPassphraseSkipsCA
// proves that when CULVERT_LOG_PASSPHRASE is supplied only via the host
// environment and contains characters that are unsafe to persist verbatim in
// .env (docker compose re-interpolates $-references when reading .env — the
// exact class of characters the choice=2 "enter my own passphrase" path
// below already rejects for this reason), setup_at_rest_encryption() must
// NOT blindly copy it into CULVERT_CA_PASSPHRASE. Doing so risks docker
// compose resolving the persisted CA passphrase to a DIFFERENT string than
// the actual (host-env, unmangled) log passphrase, silently splitting one
// intended shared key into two different ones.
func TestInstallScript_SetupAtRestEncryption_FreshDeployWithUnsafeHostLogPassphraseSkipsCA(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")

	const unsafeLogPass = `abc$def`
	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
export CULVERT_LOG_PASSPHRASE='` + unsafeLogPass + `'
` + "INSTALL_DIR=" + dir + "\n"

	script := stubs + secretFn + "\n" + envPutFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	cmd.Stdin = bytes.NewReader(nil)                              // non-interactive: stdin is not a TTY
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("setup_at_rest_encryption failed: %v\n%s", err, out)
	}

	envContent := ""
	if b, rerr := os.ReadFile(envFile); rerr == nil {
		envContent = string(b)
	}

	if strings.Contains(envContent, "CULVERT_CA_PASSPHRASE=") {
		t.Fatalf("an unsafe-charset host CULVERT_LOG_PASSPHRASE (%q) was copied verbatim into "+
			"CULVERT_CA_PASSPHRASE in .env — docker compose's own .env interpolation could resolve this "+
			"to a DIFFERENT value than the real log passphrase, silently mismatching the two encryption "+
			"keys; output:\n%s\n.env content:\n%s", unsafeLogPass, out, envContent)
	}
}
