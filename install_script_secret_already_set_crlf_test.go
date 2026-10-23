package main

// install_script_secret_already_set_crlf_test.go — secret_already_set() must
// treat a CRLF-terminated EMPTY assignment ("VAR=\r\n", as left by a .env
// edited on Windows) as unset. env_put() normalizes CRLF to LF, but the
// reader did not: "\r" satisfied the non-empty "=.+" match, so
// setup_at_rest_encryption skipped generating the passphrase and the stack
// started with at-rest encryption silently disabled.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_SecretAlreadySet_CRLFEmptyValueIsUnset(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")
	envFile := filepath.Join(t.TempDir(), ".env")
	content := "EMPTY_CRLF=\r\nSET_CRLF=hunter2hunter2\r\nEMPTY_LF=\n"
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		want bool
	}{
		{"EMPTY_CRLF", false},
		{"EMPTY_LF", false},
		{"SET_CRLF", true},
		{"MISSING", false},
	}
	for _, tc := range cases {
		script := fn + "\nsecret_already_set \"$1\" \"$2\""
		cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "t", tc.name, envFile) // #nosec G204 -- fixed test script
		err := cmd.Run()
		got := err == nil
		if got != tc.want {
			t.Errorf("secret_already_set %s = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// With the installer's `set -o pipefail`, a match near the top of a large .env
// must still report "set" (no SIGPIPE-driven false negative from a pipeline).
func TestInstallScript_SecretAlreadySet_LargeEnvUnderPipefail(t *testing.T) {
	fn := extractShellFunction(t, "scripts/install.sh", "secret_already_set")
	envFile := filepath.Join(t.TempDir(), ".env")
	content := "CULVERT_LOG_PASSPHRASE=hunter2hunter2\n" + strings.Repeat("# filler comment line\n", 40000)
	if err := os.WriteFile(envFile, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	script := "set -euo pipefail\n" + fn + "\nsecret_already_set CULVERT_LOG_PASSPHRASE \"$1\""
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script, "t", envFile) // #nosec G204 -- fixed test script
	if err := cmd.Run(); err != nil {
		t.Fatalf("secret_already_set on large .env under pipefail = %v, want success", err)
	}
}
