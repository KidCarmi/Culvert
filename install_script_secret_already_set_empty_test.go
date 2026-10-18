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
		{"commented out", "# CULVERT_CA_PASSPHRASE=abcdef123456\n", false},
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
