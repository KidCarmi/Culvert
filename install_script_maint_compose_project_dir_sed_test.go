package main

// install_script_maint_compose_project_dir_sed_test.go — regression coverage
// for set_maint_compose_project_dir() in scripts/install.sh.
//
// install_maint_agent points the agent's config.toml at the stack directory
// ($INSTALL_DIR, from CULVERT_DIR) with a `sed s|…|…|`. The directory sits on
// the REPLACEMENT side, where an unescaped `&` expands to the whole matched
// line and `\` starts an escape. `&` is a legal path character that
// packaging/culvert-maint/install.sh accepts (and escapes itself via
// sed_escape_replacement), so CULVERT_DIR=/opt/R&D must round-trip intact.

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestSetMaintComposeProjectDir_SpecialCharsRoundTrip(t *testing.T) {
	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "set_maint_compose_project_dir")
	for _, dir := range []string{"/srv/stack", "/opt/R&D", "/opt/a&b&c"} {
		t.Run(dir, func(t *testing.T) {
			cfg := filepath.Join(t.TempDir(), "config.toml")
			seed := "compose_project_dir = \"/srv/culvert\"\nallow_peers = [\"culvert-cp\"]\n"
			if err := os.WriteFile(cfg, []byte(seed), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			script := "sudo() { \"$@\"; }\n" + fn + "\n" + `set_maint_compose_project_dir "$1" "$2"` + "\n"
			out, err := exec.CommandContext(t.Context(), "bash", "-c", script, "x", cfg, dir).CombinedOutput() // #nosec G204 -- fixed test script
			if err != nil {
				t.Fatalf("script failed: %v\n%s", err, out)
			}
			got, _ := os.ReadFile(cfg)
			want := "compose_project_dir = \"" + dir + "\"\nallow_peers = [\"culvert-cp\"]\n"
			if string(got) != want {
				t.Errorf("config.toml =\n%s\nwant:\n%s", got, want)
			}
		})
	}
}
