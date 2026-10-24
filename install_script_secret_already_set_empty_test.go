package main

// install_script_secret_already_set_empty_test.go — regression coverage for
// secret_already_set() in scripts/install.sh. setup_at_rest_encryption() skips
// generating a passphrase whenever secret_already_set() is true, so a value
// that docker compose resolves to the EMPTY string must not count as set:
// otherwise the SSL-inspection CA key is persisted unencrypted and nothing is
// generated.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_SecretAlreadySet_EmptyValuesAreNotSet(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"plain value", "CULVERT_CA_PASSPHRASE=abcdef123456\n", true},
		{"double-quoted value", "CULVERT_CA_PASSPHRASE=\"abcdef123456\"\n", true},
		{"single-quoted value", "CULVERT_CA_PASSPHRASE='abcdef123456'\n", true},
		{"CRLF value", "CULVERT_CA_PASSPHRASE=abcdef123456\r\n", true},
		{"empty", "CULVERT_CA_PASSPHRASE=\n", false},
		{"empty double quotes", "CULVERT_CA_PASSPHRASE=\"\"\n", false},
		{"empty single quotes", "CULVERT_CA_PASSPHRASE=''\n", false},
		{"empty CRLF", "CULVERT_CA_PASSPHRASE=\r\n", false},
		{"whitespace only", "CULVERT_CA_PASSPHRASE=   \n", false},
		{"empty with inline comment", "CULVERT_CA_PASSPHRASE= # not set\n", false},
		{"empty quotes with inline comment", "CULVERT_CA_PASSPHRASE=\"\" # not set\n", false},
		{"quoted value with inline comment", "CULVERT_CA_PASSPHRASE=\"abcdef123456\" # note\n", true},
		{"commented out", "# CULVERT_CA_PASSPHRASE=abcdef123456\n", false},
		{"absent while other vars set", "CULVERT_LOG_PASSPHRASE=abcdef123456\r\nOTHER=x\n", false},
		{"empty CRLF before a set var", "CULVERT_CA_PASSPHRASE=\r\nCULVERT_LOG_PASSPHRASE=abcdef123456\r\n", false},
		{"set CRLF after an empty var", "CULVERT_LOG_PASSPHRASE=\r\nCULVERT_CA_PASSPHRASE=abcdef123456\r\n", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envfile := filepath.Join(t.TempDir(), ".env")
			if err := os.WriteFile(envfile, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			script := "unset CULVERT_CA_PASSPHRASE\n" + fn + "\nsecret_already_set CULVERT_CA_PASSPHRASE \"$1\"\n"
			err := exec.CommandContext(t.Context(), "bash", "-c", script, "bash", envfile).Run() // #nosec G204 -- fixed test script
			got := err == nil
			if got != tc.want {
				t.Fatalf("secret_already_set(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

// A large .env must not turn a successful early-exit match into a SIGPIPE
// failure of the upstream reader under the installer's `set -o pipefail`.
func TestInstallScript_SecretAlreadySet_LargeEnvUnderPipefail(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")
	envfile := filepath.Join(t.TempDir(), ".env")
	content := "CULVERT_CA_PASSPHRASE=abcdef123456\n" + strings.Repeat("# filler line to exceed the pipe buffer\n", 1<<20)
	if err := os.WriteFile(envfile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "set -euo pipefail\nunset CULVERT_CA_PASSPHRASE\n" + fn + "\nsecret_already_set CULVERT_CA_PASSPHRASE \"$1\"\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "bash", envfile) // #nosec G204 -- fixed test script
	if err := cmd.Run(); err != nil {
		t.Fatalf("secret_already_set on a large .env with a leading match = %v, want success", err)
	}
}
