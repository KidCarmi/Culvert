package config

import (
	"strings"
	"testing"
)

// TestLoad_ComposeFileRejectsWhatTheInstallerRejects pins compose_file to the
// same acceptance set packaging/culvert-maint/install.sh enforces before it
// renders the sudoers allowlist: a bare filename that is not "." or "..", with
// no whitespace, quotes, pipe or control characters (reject_unsafe).
//
// compose_file is joined under compose_project_dir by the runner
// (filepath.Join(dir, file)), so "." and ".." name the project dir itself or
// its PARENT rather than a file in it, and every value here becomes a sudoers
// literal / argv token. A hand-edited config.toml holding one of these must
// fail at Load — the agent's documented fail-closed contract — instead of
// starting and failing every later operation at sudo or compose.
func TestLoad_ComposeFileRejectsWhatTheInstallerRejects(t *testing.T) {
	rejected := map[string]string{
		"dot":                 ".",
		"dotdot":              "..",
		"internal whitespace": "docker compose.yml",
		"tab":                 "docker\tcompose.yml",
		"double quote":        `a\"b.yml`,
		"single quote":        "a'b.yml",
		"pipe":                "a|b.yml",
	}
	for name, v := range rejected {
		t.Run(name, func(t *testing.T) {
			body := minimalValid + "\ncompose_file = \"" + v + "\""
			cfg, err := Load(writeConfig(t, body))
			if err == nil {
				t.Fatalf("compose_file=%q accepted (ComposeFile=%q); the installer rejects it", v, cfg.ComposeFile)
			}
			if !strings.Contains(err.Error(), "compose_file") {
				t.Errorf("error does not name compose_file: %v", err)
			}
		})
	}

	// Positive control: an ordinary alternative filename still loads.
	cfg, err := Load(writeConfig(t, minimalValid+"\ncompose_file = \"compose.prod.yml\""))
	if err != nil {
		t.Fatalf("Load (valid compose_file): %v", err)
	}
	if cfg.ComposeFile != "compose.prod.yml" {
		t.Errorf("ComposeFile: got %q", cfg.ComposeFile)
	}
}
