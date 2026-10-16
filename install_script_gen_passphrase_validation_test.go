package main

// install_script_gen_passphrase_validation_test.go — regression coverage for
// the auto-generate branch of setup_at_rest_encryption() in
// scripts/install.sh, which is the DEFAULT, non-interactive path every
// automated/scripted install takes (and the only one CI's
// install-lifecycle-e2e exercises — see
// install_script_setup_at_rest_encryption_test.go's header comment).
//
// validate_passphrase_for_env_file()'s own doc comment claims it "enforces
// the same length + character-safety contract on a passphrase regardless of
// where it came from (operator-typed or host-env-supplied)" — but the
// auto-generate branch (scripts/install.sh, setup_at_rest_encryption(),
// `case "$choice" in ... *) pass="$(gen_passphrase)" ...`) never calls it.
// gen_passphrase() itself has no length floor beyond "non-empty": it tries
// `openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | head -c 40`, and only
// falls through to /dev/urandom (then error()) if the result is EMPTY — a
// broken/wrapped `openssl` (e.g. a FIPS-mode build that writes an engine
// warning ahead of the base64 data on stdout, or a hardened-image stub) can
// legitimately yield a short-but-non-empty alnum string, which sails
// straight past every guard and gets persisted as the passphrase that
// PBKDF2-SHA256-derives the AES-256-GCM key protecting the SSL-inspection
// Root CA private key and saved request logs at rest.
//
// The identical short value typed by an operator (choice=2) or supplied via
// the host environment is correctly REJECTED by validate_passphrase_for_env_file's
// 12-character floor. This test proves the auto-generate branch diverges
// from that contract by simulating a degraded gen_passphrase() (as the
// broken-openssl trigger would produce) and asserting the installer's
// behavior on a passphrase far below the documented floor.
//
// This extracts the REAL setup_at_rest_encryption() + env_put() function
// bodies out of scripts/install.sh (rather than duplicating them here) and
// exercises them under bash, so the test tracks the actual installer script
// instead of a copy that can drift.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runGenPassphrase drives the REAL gen_passphrase() with `opensslStub` as the
// body of a shell function shadowing `openssl` (empty string leaves the real
// system openssl in place). Returns its stdout output (the generated
// passphrase) and the combined stdout+stderr for diagnostics.
func runGenPassphrase(t *testing.T, opensslStub string) (pass, output string) {
	t.Helper()
	fn := extractShellFunction(t, "scripts/install.sh", "gen_passphrase")

	stubs := "error() { echo \"ERROR: $*\" >&2; exit 7; }\n"
	if opensslStub != "" {
		stubs += "openssl() { " + opensslStub + "; }\n"
	}

	script := stubs + fn + "\n" + "gen_passphrase\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("gen_passphrase failed: %v\n%s", err, out)
	}
	return string(out), string(out)
}

// TestInstallScript_GenPassphrase_FallsBackWhenOpensslOutputIsShort proves
// gen_passphrase() itself falls back to /dev/urandom — rather than accepting
// whatever `openssl` printed — when a degraded `openssl` (e.g. a FIPS-mode
// build writing an engine warning ahead of, or instead of, the base64 data on
// stdout) produces a short-but-non-empty alnum string. Flagged by Codex review
// on PR #1491: the deterministic diagnostic text "FIPSmodeselftestfailed" (22
// alnum characters) is well above validate_passphrase_for_env_file's
// 12-character floor and contains no unsafe characters, so it would be
// accepted and persisted as if it were a genuine random 40-character
// passphrase — a predictable encryption key with no error and no warning.
func TestInstallScript_GenPassphrase_FallsBackWhenOpensslOutputIsShort(t *testing.T) {
	const diagnostic = "FIPSmodeselftestfailed" // 22 chars, all alnum, >= the 12-char floor
	pass, output := runGenPassphrase(t, `printf '%s' '`+diagnostic+`'`)

	if pass == diagnostic {
		t.Fatalf("gen_passphrase returned the degraded openssl's %d-character diagnostic text %q "+
			"verbatim instead of falling back to /dev/urandom for a full-length passphrase; output:\n%s",
			len(diagnostic), diagnostic, output)
	}
	if len(pass) != 40 {
		t.Fatalf("gen_passphrase returned a %d-character passphrase (%q) after a degraded openssl; "+
			"want exactly 40 (the /dev/urandom fallback's target length); output:\n%s", len(pass), pass, output)
	}
}

// TestInstallScript_GenPassphrase_NormalOpensslProduces40Chars is the
// baseline sanity check against the REAL system openssl: the common case
// still yields exactly 40 characters, so the added full-length requirement
// does not regress normal operation.
func TestInstallScript_GenPassphrase_NormalOpensslProduces40Chars(t *testing.T) {
	pass, output := runGenPassphrase(t, "")
	if len(pass) != 40 {
		t.Fatalf("gen_passphrase returned a %d-character passphrase (%q) using the real system openssl; "+
			"want exactly 40; output:\n%s", len(pass), pass, output)
	}
}

// runSetupAtRestEncryptionAutoGenerate drives the REAL setup_at_rest_encryption()
// on its default non-interactive path (stdin is not a TTY, so `choice` stays
// "1" and the `*)` auto-generate branch runs), with gen_passphrase() stubbed
// to return genPass instead of a real 40-character random value — simulating
// a degraded/broken openssl on the host. Returns the combined stdout+stderr,
// the process exit code, and the resulting .env content (empty if the file
// was never written).
func runSetupAtRestEncryptionAutoGenerate(t *testing.T, genPass string) (output string, exitCode int, envContent string) {
	t.Helper()
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	validateFn := extractShellFunction(t, "scripts/install.sh", "validate_passphrase_for_env_file")

	dir := t.TempDir()

	stubs := `
info() { :; }
warn() { :; }
error() { echo "ERROR: $*" >&2; exit 7; }
is_fresh_deployment() { return 1; }
secret_already_set() { return 1; }
gen_passphrase() { printf '%s' '` + genPass + `'; }
` + "INSTALL_DIR=" + dir + "\n"

	script := stubs + validateFn + "\n" + envPutFn + "\n" + setupFn + "\n" + "setup_at_rest_encryption\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	cmd.Stdin = bytes.NewReader(nil)                              // non-interactive: stdin is not a TTY
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

// TestInstallScript_SetupAtRestEncryption_AutoGenerateRejectsShortPassphrase
// proves that the default (non-interactive, auto-generate) branch of
// setup_at_rest_encryption() applies the SAME 12-character floor the
// operator-typed (choice=2) and host-env-supplied paths already enforce via
// validate_passphrase_for_env_file. A gen_passphrase() that (due to a
// degraded openssl) returns a short-but-non-empty value must not be
// silently accepted and persisted as the CA/log encryption key.
func TestInstallScript_SetupAtRestEncryption_AutoGenerateRejectsShortPassphrase(t *testing.T) {
	const shortPass = "abc123" // 6 chars, well under the 12-char floor
	output, exitCode, envContent := runSetupAtRestEncryptionAutoGenerate(t, shortPass)

	if exitCode == 0 {
		t.Fatalf("setup_at_rest_encryption's auto-generate branch accepted a %d-character passphrase "+
			"(%q) for CA-key/log encryption at rest — the identical value would be rejected by "+
			"validate_passphrase_for_env_file on the operator-typed (choice=2) or host-env-supplied paths. "+
			"output:\n%s\n.env content:\n%s", len(shortPass), shortPass, output, envContent)
	}
	if strings.Contains(envContent, "CULVERT_LOG_PASSPHRASE="+shortPass) {
		t.Fatalf("a %d-character auto-generated passphrase (%q) was written to .env despite a non-zero exit; "+
			".env content:\n%s", len(shortPass), shortPass, envContent)
	}
}

// TestInstallScript_SetupAtRestEncryption_AutoGenerateAcceptsNormalPassphrase
// is the baseline sanity check: gen_passphrase()'s normal 40-character
// output is still accepted and persisted, so the added floor check does not
// regress the legitimate, overwhelmingly common case.
func TestInstallScript_SetupAtRestEncryption_AutoGenerateAcceptsNormalPassphrase(t *testing.T) {
	normalPass := strings.Repeat("a", 40)
	output, exitCode, envContent := runSetupAtRestEncryptionAutoGenerate(t, normalPass)

	if exitCode != 0 {
		t.Fatalf("setup_at_rest_encryption's auto-generate branch rejected a normal 40-character "+
			"passphrase (exit %d); output:\n%s", exitCode, output)
	}
	if !strings.Contains(envContent, "CULVERT_LOG_PASSPHRASE="+normalPass) {
		t.Fatalf(".env does not contain the expected auto-generated passphrase; .env content:\n%s", envContent)
	}
}

// TestInstallScript_GenPassphrase_FallsBackWhenOpensslOutputIsLong pins the
// truncation half of the degraded-openssl case (Codex review, PR #1491): a
// generator that prints MORE than 40 allowed characters of deterministic text
// must not be cut down to exactly 40 and accepted as key material — the raw
// output is validated before any truncation.
func TestInstallScript_GenPassphrase_FallsBackWhenOpensslOutputIsLong(t *testing.T) {
	long := strings.Repeat("0", 50)
	pass, output := runGenPassphrase(t, `printf '%s\n' '`+long+`'`)
	if pass == long[:40] {
		t.Fatalf("gen_passphrase truncated a degraded openssl's 50-character output to 40 zeroes and accepted it; output:\n%s", output)
	}
	if len(pass) != 40 {
		t.Fatalf("gen_passphrase returned a %d-character passphrase (%q); want 40 from the fallback; output:\n%s", len(pass), pass, output)
	}
}

// TestInstallScript_GenPassphrase_FallsBackWhenOpensslPrefixesAWarning covers
// the other degraded shape: a diagnostic line written to stdout AHEAD of an
// otherwise-valid base64 block. Filtering would splice the warning's letters
// into the passphrase; the raw-shape check must reject it instead.
func TestInstallScript_GenPassphrase_FallsBackWhenOpensslPrefixesAWarning(t *testing.T) {
	const warning = "WARNINGFIPSengineselftestfailed"
	valid := strings.Repeat("Ab1", 21) + "Z" // 64 chars of the base64 alphabet
	pass, output := runGenPassphrase(t, `printf '%s\n%s\n' '`+warning+`' '`+valid+`'`)
	if strings.HasPrefix(pass, warning[:20]) || strings.HasPrefix(pass, valid[:20]) {
		t.Fatalf("gen_passphrase accepted a warning-prefixed openssl output (%q); output:\n%s", pass, output)
	}
	if len(pass) != 40 {
		t.Fatalf("gen_passphrase returned a %d-character passphrase (%q); want 40 from the fallback; output:\n%s", len(pass), pass, output)
	}
}
