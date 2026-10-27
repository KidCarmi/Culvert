package main

// install_script_env_file_value_set_export_test.go — docker compose's dotenv
// parser accepts an optional `export ` prefix and leading blanks before a
// KEY=VALUE line. env_file_value_set() must agree, or setup_at_rest_encryption()
// believes an operator-supplied passphrase is absent, generates a second one and
// appends it; compose then resolves the LAST entry, so the CA key encrypted with
// the original passphrase can no longer be decrypted.

import (
	"os"
	"os/exec"
	"path/filepath"
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
