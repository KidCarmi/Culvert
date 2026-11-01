package main

// install_script_env_put_nonutf8_test.go — env_put() in scripts/install.sh
// rewrites the operator's .env through `grep -v`. Under a UTF-8 locale GNU grep
// treats a line containing invalid UTF-8 (e.g. a Latin-1 byte in a hand-edited
// comment or value) as binary and does not emit it with -v, so the rewrite
// silently DELETED that line from .env.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallScript_EnvPut_PreservesNonUTF8Lines(t *testing.T) {
	if out, err := exec.CommandContext(t.Context(), "locale", "-a").Output(); err != nil ||
		!strings.Contains(strings.ToLower(string(out)), "c.utf") {
		t.Skip("no C.UTF-8 locale available")
	}
	fn := extractShellFunction(t, "scripts/install.sh", "env_put")

	envFile := filepath.Join(t.TempDir(), ".env")
	seed := "# caf\xe9 note\nCULVERT_OTHER=p\xe4ss\nCULVERT_X=old\n"
	if err := os.WriteFile(envFile, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.CommandContext(t.Context(), "bash", "-c", fn+"\n"+`env_put CULVERT_X new "$1"`, "t", envFile) // #nosec G204 -- fixed test script
	cmd.Env = append(os.Environ(), "LC_ALL=C.UTF-8")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("env_put failed: %v\n%s", err, out)
	}

	got, _ := os.ReadFile(envFile)
	want := "# caf\xe9 note\nCULVERT_OTHER=p\xe4ss\nCULVERT_X=new\n"
	if string(got) != want {
		t.Fatalf("env_put altered unrelated .env lines\n got: %q\nwant: %q", got, want)
	}
}
