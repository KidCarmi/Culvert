package main

// install_script_secret_already_set_crlf_test.go — secret_already_set() in
// scripts/install.sh decides whether setup_at_rest_encryption() may skip
// generating/prompting for CULVERT_{LOG,CA}_PASSPHRASE. A .env saved with
// CRLF line endings (Windows editor, git autocrlf) and an EMPTY placeholder
// (`CULVERT_CA_PASSPHRASE=\r\n`) was counted as "configured" because the
// trailing CR satisfied `.+`, yet docker compose resolves that value to empty,
// so the Root CA key would be persisted unencrypted while the installer
// reported the passphrase as already set.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretAlreadySet_CRLFEmptyValueIsNotSet(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")
	dir := t.TempDir()
	cases := []struct {
		name, content string
		want          bool
	}{
		{"empty LF", "CULVERT_X=\n", false},
		{"empty CRLF", "CULVERT_X=\r\n", false},
		{"value LF", "CULVERT_X=abc\n", true},
		{"value CRLF", "CULVERT_X=abc\r\n", true},
		{"other var only, CRLF", "CULVERT_Y=abc\r\nCULVERT_X=\r\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envFile := filepath.Join(dir, "env-"+tc.name)
			if err := os.WriteFile(envFile, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			script := fn + "\nsecret_already_set CULVERT_X \"$1\""
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "t", envFile) // #nosec G204 -- fixed test script
			cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
			err := cmd.Run()
			got := err == nil
			if got != tc.want {
				t.Fatalf("secret_already_set on %q = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

// The disk-only "persist the host secret" guards in setup_at_rest_encryption()
// and persist_host_env_session_secret() used the same `^VAR=.+` predicate, so a
// CRLF-empty placeholder in .env made them skip env_put for a real host-exported
// value (compose then reads the empty .env value).
func TestHostEnvPersist_CRLFEmptyPlaceholderIsOverwrittenByHostValue(t *testing.T) {
	t.Run("log passphrase", func(t *testing.T) {
		dir := t.TempDir()
		seedCRLFEnv(t, dir, "CULVERT_LOG_PASSPHRASE=\r\n")
		out, code, env := runSetupAtRestEncryptionWithHostEnv(t, dir,
			`export CULVERT_LOG_PASSPHRASE="host-supplied-passphrase-1234"`)
		if code != 0 || !strings.Contains(env, "CULVERT_LOG_PASSPHRASE=host-supplied-passphrase-1234") {
			t.Fatalf("host log passphrase not persisted over CRLF-empty placeholder (exit %d)\n%s\n.env: %q", code, out, env)
		}
	})
	t.Run("ca passphrase", func(t *testing.T) {
		dir := t.TempDir()
		seedCRLFEnv(t, dir, "CULVERT_CA_PASSPHRASE=\r\n")
		out, code, env := runSetupAtRestEncryptionWithHostEnv(t, dir,
			`export CULVERT_CA_PASSPHRASE="host-supplied-passphrase-1234"`)
		if code != 0 || !strings.Contains(env, "CULVERT_CA_PASSPHRASE=host-supplied-passphrase-1234") {
			t.Fatalf("host CA passphrase not persisted over CRLF-empty placeholder (exit %d)\n%s\n.env: %q", code, out, env)
		}
	})
	t.Run("session secret", func(t *testing.T) {
		dir := t.TempDir()
		seedCRLFEnv(t, dir, "CULVERT_SESSION_SECRET=\r\n")
		secret := strings.Repeat("ab", 32)
		out, code, env := runPersistHostEnvSessionSecret(t, dir, `export CULVERT_SESSION_SECRET="`+secret+`"`)
		if code != 0 || !strings.Contains(env, "CULVERT_SESSION_SECRET="+secret) {
			t.Fatalf("host session secret not persisted over CRLF-empty placeholder (exit %d)\n%s\n.env: %q", code, out, env)
		}
	})
}

func seedCRLFEnv(t *testing.T, dir, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The installer runs under `set -euo pipefail`. persist_host_env_session_secret
// probes .env with a bare grep and reads $? on the next line, so a "no entry"
// answer (grep exit 1) aborted the whole install before the host secret could be
// persisted. The other host-env tests run without errexit and could not see it.
func TestPersistHostEnvSessionSecret_NoEntryDoesNotAbortUnderErrexit(t *testing.T) {
	secret := strings.Repeat("ab", 32)
	for name, seed := range map[string]string{
		"crlf empty placeholder": "CULVERT_SESSION_SECRET=\r\n",
		"unrelated entry only":   "CULVERT_OTHER=1\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			seedCRLFEnv(t, dir, seed)
			out, code, env := runPersistHostEnvSessionSecret(t, dir,
				"set -e\nexport CULVERT_SESSION_SECRET=\""+secret+"\"")
			if code != 0 || !strings.Contains(env, "CULVERT_SESSION_SECRET="+secret) {
				t.Fatalf("install aborted or secret not persisted under errexit (exit %d)\n%s\n.env: %q", code, out, env)
			}
		})
	}
}
