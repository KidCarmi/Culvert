package main

// install_script_secret_already_set_crlf_test.go — secret_already_set() must
// treat an EMPTY value as "not set" even when the .env file has CRLF line
// endings (a file edited on Windows, or copied through a CRLF-converting tool).
// env_put normalizes CRLF to LF, but only when it is called; the "is it already
// configured?" probe runs BEFORE that, so a trailing "\r" used to satisfy the
// `.+` value pattern and an empty passphrase was reported as already configured,
// skipping at-rest-encryption setup.

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestInstallScript_SecretAlreadySet_EmptyValueCRLF(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")

	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"LF empty", "CULVERT_LOG_PASSPHRASE=\n", false},
		{"CRLF empty", "CULVERT_LOG_PASSPHRASE=\r\n", false},
		{"CRLF empty amid other vars", "A=1\r\nCULVERT_LOG_PASSPHRASE=\r\nB=2\r\n", false},
		{"LF value", "CULVERT_LOG_PASSPHRASE=abcdefghijkl\n", true},
		{"CRLF value", "CULVERT_LOG_PASSPHRASE=abcdefghijkl\r\n", true},
		{"other var only", "CULVERT_CA_PASSPHRASE=abcdefghijkl\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			envFile := filepath.Join(t.TempDir(), ".env")
			if err := os.WriteFile(envFile, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			// unset host env so only the file decides
			script := fn + "\nunset CULVERT_LOG_PASSPHRASE\nsecret_already_set CULVERT_LOG_PASSPHRASE \"$1\"\n"
			cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "t", envFile) // #nosec G204 -- fixed test script
			err := cmd.Run()
			got := err == nil
			if got != tc.want {
				t.Fatalf("secret_already_set = %v, want %v for %q", got, tc.want, tc.content)
			}
		})
	}
}
