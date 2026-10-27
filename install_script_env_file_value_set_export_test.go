package main

// install_script_env_file_value_set_export_test.go — docker compose's dotenv
// parser accepts an optional `export ` prefix and leading blanks before a
// KEY=VALUE line. env_file_value_set() must agree, or setup_at_rest_encryption()
// believes an operator-supplied passphrase is absent, generates a second one and
// appends it; compose then resolves the LAST entry, so the CA key encrypted with
// the original passphrase can no longer be decrypted.

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_EnvFileValueSet_ExportPrefixAndIndent(t *testing.T) {
	fn := installSharedEnvPredicate(t)
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"export prefix", "export CULVERT_CA_PASSPHRASE=abcdef123456\n", true},
		{"export prefix quoted", "export CULVERT_CA_PASSPHRASE=\"abcdef123456\"\n", true},
		{"leading spaces", "  CULVERT_CA_PASSPHRASE=abcdef123456\n", true},
		{"leading tab", "\tCULVERT_CA_PASSPHRASE=abcdef123456\n", true},
		{"export empty", "export CULVERT_CA_PASSPHRASE=\n", false},
		{"export empty quotes", "export CULVERT_CA_PASSPHRASE=\"\"\n", false},
		{"commented export", "# export CULVERT_CA_PASSPHRASE=abcdef123456\n", false},
		{"different var with export", "export XCULVERT_CA_PASSPHRASE=abcdef123456\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envfile := filepath.Join(t.TempDir(), ".env")
			if err := os.WriteFile(envfile, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			script := fn + "\nenv_file_value_set CULVERT_CA_PASSPHRASE \"$1\"\n"
			err := exec.CommandContext(t.Context(), "bash", "-c", script, "bash", envfile).Run() // #nosec G204 -- fixed test script
			if got := err == nil; got != tc.want {
				t.Fatalf("env_file_value_set(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

// The CA-reuse branch of setup_at_rest_encryption() must read the log
// passphrase in every form env_file_value_set() accepts; otherwise the branch is
// entered but finds no value and leaves CULVERT_CA_PASSPHRASE unset, so the
// proxy persists the CA key unencrypted.
func TestInstallScript_SetupAtRestEncryption_ReuseBranchReadsExportedLogPassphrase(t *testing.T) {
	setupFn := extractShellFunctionBraceAware(t, "scripts/install.sh", "setup_at_rest_encryption")
	envPutFn := extractShellFunction(t, "scripts/install.sh", "env_put")
	secretFn := installSharedEnvPredicate(t) + "\n" + extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	for _, line := range []string{
		"export CULVERT_LOG_PASSPHRASE=already-set-log-passphrase-1234",
		"  CULVERT_LOG_PASSPHRASE=already-set-log-passphrase-1234",
	} {
		t.Run(line, func(t *testing.T) {
			dir := t.TempDir()
			envFile := filepath.Join(dir, ".env")
			if err := os.WriteFile(envFile, []byte(line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			stubs := "info() { :; }\nwarn() { :; }\nerror() { echo \"ERROR: $*\" >&2; exit 7; }\n" +
				"is_fresh_deployment() { return 0; }\nunset CULVERT_LOG_PASSPHRASE CULVERT_CA_PASSPHRASE\nINSTALL_DIR=" + dir + "\n"
			script := stubs + secretFn + "\n" + envPutFn + "\n" + setupFn + "\nsetup_at_rest_encryption\n"
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script
			cmd.Stdin = bytes.NewReader(nil)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("setup_at_rest_encryption failed: %v\n%s", err, out)
			}
			got, _ := os.ReadFile(envFile)
			if !strings.Contains(string(got), "CULVERT_CA_PASSPHRASE=already-set-log-passphrase-1234") {
				t.Fatalf("CA passphrase not derived from the existing log passphrase; .env:\n%s", got)
			}
		})
	}
}
