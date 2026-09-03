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
	validateFn := extractShellFunction(t, "scripts/install.sh", "validate_passphrase_for_env_file")

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

	script := stubs + validateFn + "\n" + envPutFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

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

// TestInstallScript_SetupAtRestEncryption_HostEnvOnlyCAPassphraseIsPersisted
// proves that when CULVERT_CA_PASSPHRASE is already set — but ONLY in this
// process's environment, e.g. exported by an automated/non-interactive
// install before running scripts/install.sh, and not yet written to .env —
// setup_at_rest_encryption() persists it to .env rather than treating it as
// "already configured" and silently doing nothing.
//
// This matters because later in scripts/install.sh the stack is started with
// plain `sudo docker compose up -d --wait ...` (no `-E`), which does NOT
// forward the invoking shell's environment to the child process. A
// CULVERT_CA_PASSPHRASE that lives only in this process's env and never
// makes it into .env is therefore silently dropped: docker compose resolves
// `${CULVERT_CA_PASSPHRASE:-}` to empty, and the proxy starts up and
// generates/persists its Root CA private key UNENCRYPTED — exactly the
// "proxy recreates with an empty passphrase" failure mode
// carry_forward_prior_secrets() (scripts/install.sh) documents and guards
// against for a different trigger (a re-run landing in a new stack dir).
func TestInstallScript_SetupAtRestEncryption_HostEnvOnlyCAPassphraseIsPersisted(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	const hostCAPass = "host-env-only-ca-passphrase-5678" // #nosec G101 -- synthetic test fixture; never leaves this test

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
export CULVERT_CA_PASSPHRASE='` + hostCAPass + `'
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

	if !strings.Contains(envContent, "CULVERT_CA_PASSPHRASE="+hostCAPass) {
		t.Fatalf("a CULVERT_CA_PASSPHRASE set only in the host environment was never persisted to .env; "+
			"'sudo docker compose up' (no -E) does not forward this shell's environment, so the proxy would "+
			"start with an EMPTY CA passphrase and store its Root CA private key unencrypted. "+
			"output:\n%s\n.env content:\n%s", out, envContent)
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

// TestInstallScript_SetupAtRestEncryption_HostEnvOnlyCAPassphraseWithEmbeddedNewlineRejected
// proves that the host-env-only-CA-passphrase persistence path (added
// alongside TestInstallScript_SetupAtRestEncryption_HostEnvOnlyCAPassphraseIsPersisted
// above) rejects a value containing an embedded newline rather than
// persisting it. Both halves of "abcdefgh\nijklmnop" are individually
// charset-clean, so a charset check run with plain (line-splitting) `grep`
// checks each half separately and never sees the disallowed newline — env_put
// would then append the value as TWO lines ("CULVERT_CA_PASSPHRASE=abcdefgh"
// followed by a bare "ijklmnop"), corrupting the persisted passphrase and
// potentially leaving an existing CA bundle undecryptable (Codex review on
// PR #1156). The check must treat the whole value as one unit (`grep -z`).
func TestInstallScript_SetupAtRestEncryption_HostEnvOnlyCAPassphraseWithEmbeddedNewlineRejected(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")
	validateFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "validate_passphrase_for_env_file")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
export CULVERT_CA_PASSPHRASE=$'abcdefgh\nijklmnop'
` + "INSTALL_DIR=" + dir + "\n"

	script := stubs + secretFn + "\n" + envPutFn + "\n" + validateFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	cmd.Stdin = bytes.NewReader(nil)                              // non-interactive: stdin is not a TTY
	out, err := cmd.CombinedOutput()
	// The host-env family now fails CLOSED through the shared validator (the
	// same contract as the interactive choice-2 path), so the malformed value
	// must abort the run rather than be skipped with a warning.
	if err == nil {
		t.Fatalf("setup_at_rest_encryption accepted an embedded-newline CULVERT_CA_PASSPHRASE; output:\n%s", out)
	}

	envContent := ""
	if b, rerr := os.ReadFile(envFile); rerr == nil {
		envContent = string(b)
	}

	if strings.Contains(envContent, "CULVERT_CA_PASSPHRASE=") {
		t.Fatalf("a host CULVERT_CA_PASSPHRASE containing an embedded newline (\"abcdefgh\\nijklmnop\", each "+
			"half individually charset-clean) was persisted to .env instead of being rejected — a "+
			"line-splitting charset check misses the newline, and env_put then appends the value as two "+
			"malformed .env lines, corrupting the passphrase; output:\n%s\n.env content:\n%s", out, envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_ReuseForCAMatchesPersistedLogPassphrase
// proves that the "fresh deployment, log passphrase already set, no CA
// passphrase yet" reuse branch derives CULVERT_CA_PASSPHRASE from the log
// passphrase that is actually PERSISTED IN .ENV — the value docker compose
// will read at runtime (`sudo docker compose up`, no `-E`, does not forward
// this shell's environment) — rather than from a same-named variable that
// happens to be set in the invoking shell's environment.
//
// Trigger: .env already carries CULVERT_LOG_PASSPHRASE=X (e.g. left over
// from an interrupted prior run, or written by a previous installer
// invocation), and THIS run's host environment separately exports
// CULVERT_LOG_PASSPHRASE=Y with a different value (e.g. an automation
// wrapper that (re)generates a passphrase every run without first checking
// whether .env already has one). Because .env already has a non-empty entry,
// the earlier host-env-persistence block (scripts/install.sh:1596-1599)
// leaves .env untouched at X — so the log passphrase actually in effect at
// runtime is X, not Y. The reuse branch must derive the CA passphrase from
// that same X so the two encryption keys the info message ("also encrypting
// the SSL-inspection CA key with the existing CULVERT_LOG_PASSPHRASE")
// claims are shared actually match.
func TestInstallScript_SetupAtRestEncryption_ReuseForCAMatchesPersistedLogPassphrase(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	const persistedLogPass = "persisted-in-env-log-passphrase-AAAA"
	const divergentHostLogPass = "different-host-env-log-passphrase-BB" // #nosec G101 -- synthetic test fixture; never leaves this test
	if err := os.WriteFile(envFile, []byte("CULVERT_LOG_PASSPHRASE="+persistedLogPass+"\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
export CULVERT_LOG_PASSPHRASE='` + divergentHostLogPass + `'
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

	if !strings.Contains(envContent, "CULVERT_LOG_PASSPHRASE="+persistedLogPass) {
		t.Fatalf("the pre-existing .env CULVERT_LOG_PASSPHRASE was lost/changed; .env content:\n%s", envContent)
	}
	if strings.Contains(envContent, "CULVERT_CA_PASSPHRASE="+divergentHostLogPass) {
		t.Fatalf("CULVERT_CA_PASSPHRASE was derived from the host-environment CULVERT_LOG_PASSPHRASE (%q) "+
			"instead of the value actually persisted in .env (%q) and used by docker compose at runtime — "+
			"the SSL-inspection CA key and saved logs would end up encrypted with two DIFFERENT passphrases "+
			"despite the installer claiming to share one. output:\n%s\n.env content:\n%s",
			divergentHostLogPass, persistedLogPass, out, envContent)
	}
	if !strings.Contains(envContent, "CULVERT_CA_PASSPHRASE="+persistedLogPass) {
		t.Fatalf("CULVERT_CA_PASSPHRASE was not set to the persisted .env CULVERT_LOG_PASSPHRASE (%q); "+
			".env content:\n%s", persistedLogPass, envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_ReuseBranchSurvivesMissingEnvEntry
// proves that the CA-reuse branch does not abort the whole installer under
// `set -euo pipefail` when secret_already_set() reports the log passphrase
// as configured but .env genuinely holds no CULVERT_LOG_PASSPHRASE= entry
// (e.g. the host-env-persistence block just above degraded without writing
// — env_put warns and returns successfully rather than aborting when
// INSTALL_DIR/.env is owned by another user and sudo cannot take it, per
// env_put's own documented "DEGRADE" contract; scripts/install.sh itself
// runs under `set -euo pipefail`, unlike this test harness's other cases,
// so it must be enabled here too to reproduce the real failure mode).
//
// Regression for a bug introduced while fixing the CA/log-passphrase
// divergence above: reading .env's CULVERT_LOG_PASSPHRASE via
// `grep | tail | cut` and assigning the result directly meant a grep that
// matched nothing (real exit 1, propagated by pipefail) aborted the
// unconditional command-substitution assignment — and therefore the whole
// installer — before the host-environment fallback on the next line ever
// ran. Caught by automated PR review (chatgpt-codex-connector).
func TestInstallScript_SetupAtRestEncryption_ReuseBranchSurvivesMissingEnvEntry(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")

	dir := t.TempDir()
	envFile := filepath.Join(dir, ".env")
	// .env exists (so the `-f "$envfile"` branch is taken and grep actually
	// runs) but carries no CULVERT_LOG_PASSPHRASE= line at all.
	if err := os.WriteFile(envFile, []byte("SOME_OTHER_VAR=x\n"), 0o600); err != nil {
		t.Fatalf("seed .env: %v", err)
	}

	stubs := `
set -euo pipefail
info() { :; }
warn() { echo "WARN: $*"; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 0; }
secret_already_set() { [[ "$1" == "CULVERT_LOG_PASSPHRASE" ]] && return 0; return 1; }
` + "INSTALL_DIR=" + dir + "\n"

	script := stubs + envPutFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n" + `echo "REACHED_END"` + "\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	cmd.Stdin = bytes.NewReader(nil)                              // non-interactive: stdin is not a TTY
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("setup_at_rest_encryption aborted the installer instead of degrading gracefully when .env has "+
			"no CULVERT_LOG_PASSPHRASE entry (grep-no-match propagated through pipefail into an unguarded "+
			"command-substitution assignment): %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "REACHED_END") {
		t.Fatalf("script exited 0 but never reached the statement after setup_at_rest_encryption; output:\n%s", out)
	}
}
