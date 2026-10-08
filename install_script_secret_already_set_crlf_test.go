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
