package main

// Workstream C: on an appliance the installer configures the maintenance agent
// for `compose up --no-build` and binds the sidecar tag to the image ID the
// appliance recorded ("ref=sha256:<id>"), so the agent refuses an image change
// while the tag names other bytes. The block is extracted from
// scripts/install.sh; the written line must match the agent's accepted grammar
// (cmd/culvert-maint/internal/config: localImageRefRE + localImageIDRE).

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var agentLocalImageLineRE = regexp.MustCompile(`^local_only_images = \["[a-z0-9][a-z0-9._/-]{0,199}:[A-Za-z0-9_][A-Za-z0-9._-]{0,127}(=sha256:[0-9a-f]{64})?"\]$`)

func runAgentConfigBlock(t *testing.T, manifest string) string {
	t.Helper()
	root := t.TempDir()
	install := filepath.Join(root, "srv")
	state := filepath.Join(root, "appliance-state")
	for _, d := range []string{install, state} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "manifest.env"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	compose := "services:\n  clamav:\n    image: culvert/clamav:1.5.4-culvert.2\n"
	if err := os.WriteFile(filepath.Join(install, "docker-compose.yml"), []byte(compose), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "config.toml")
	if err := os.WriteFile(cfg, []byte("compose_project_dir = \"/srv/culvert\"\nlocal_only_images = [\"stale:1\"]"), 0o600); err != nil {
		t.Fatal(err)
	}
	var fns []string
	for _, n := range []string{"sidecar_image_of", "is_appliance", "appliance_manifest_value"} {
		fns = append(fns, extractShellFunction(t, "scripts/install.sh", n))
	}
	block := extractShellLineRange(t, "scripts/install.sh",
		`sudo sed -i -e '/^[[:space:]]*compose_no_build[[:space:]]*=/d'`, `info "Maintenance agent: appliance mode`)
	script := `set -euo pipefail
info() { :; }
sudo() { "$@"; }
APPLIANCE_STATE_DIR="$ROOT/appliance-state"
APPLIANCE_OPT_DIR="$ROOT/appliance-opt"
APPLIANCE_ETC_DIR="$ROOT/appliance-etc"
` + strings.Join(fns, "\n") + "\nf() {\n" + block + "\n  fi\n}\nf\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script built from the repo's install.sh
	cmd.Env = append(os.Environ(), "ROOT="+root, "INSTALL_DIR="+install, "cfg="+cfg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("block failed: %v\n%s", err, out)
	}
	b, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestInstallScript_AgentConfig_BindsSidecarToRecordedID(t *testing.T) {
	got := runAgentConfigBlock(t, bakedManifest("culvert/clamav:1.5.4-culvert.2"))
	want := `local_only_images = ["culvert/clamav:1.5.4-culvert.2=` + applianceBakedID + `"]`
	if !strings.Contains(got, "compose_no_build = true\n") || !strings.Contains(got, want+"\n") {
		t.Fatalf("agent config must carry --no-build and the ID-bound sidecar, got:\n%s", got)
	}
	if strings.Count(got, "local_only_images") != 1 || strings.Contains(got, "stale:1") {
		t.Fatalf("a re-run must replace, not append to, the previous entry:\n%s", got)
	}
	for _, l := range strings.Split(got, "\n") {
		if strings.HasPrefix(l, "local_only_images") && !agentLocalImageLineRE.MatchString(l) {
			t.Fatalf("written line is outside the agent's accepted grammar: %q", l)
		}
	}
}
