package main

// install_script_maint_sudoers_compose_dir_trailing_slash_test.go — the
// sudoers allowlist packaging/culvert-maint/install.sh renders must name the
// SAME compose path the agent later runs under sudo.
//
// The agent canonicalizes compose_project_dir with filepath.Clean
// (cmd/culvert-maint/internal/config/config.go) and builds the `-f` argument
// with filepath.Join (cmd/culvert-maint/internal/runner/runner.go). The
// installer read the raw TOML value and rendered "$PROJECT_DIR/$COMPOSE_FILE"
// verbatim. sudo matches a Cmnd's arguments literally, so an operator-edited
//
//	compose_project_dir = "/srv/culvert/"
//
// rendered `docker compose -f /srv/culvert//docker-compose.yml ps --format json`
// while the agent ran `... -f /srv/culvert/docker-compose.yml ...`: every direct
// compose rule (ps, down, up -d) was denied, so Release Management could not
// read state or upgrade, and the installer still reported success.
//
// The test drives the REAL validation block and the REAL render block, both
// extracted from the script, so it tracks the script rather than a copy.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func renderMaintSudoersThroughValidation(t *testing.T, projectDir string) (string, error) {
	t.Helper()
	const script = "packaging/culvert-maint/install.sh"
	die := `die()  { printf 'install.sh: ERROR — %s\n' "$*" >&2; exit 1; }`
	unsafe := extractShellFunction(t, script, "reject_unsafe")
	sedEsc := extractShellFunction(t, script, "sed_escape_replacement")
	colonEsc := extractShellFunction(t, script, "sudoers_escape_colon")
	validate := extractShellLineRange(t, script,
		"# Validate compose_project_dir: present, absolute", "# Validate compose_file:")
	render := extractShellLineRange(t, script,
		`COMPOSE_PATH="$PROJECT_DIR/$COMPOSE_FILE"`, `rm -f "$RENDERED_SUDOERS_TMP"`)

	body := die + "\n" + unsafe + "\n" + sedEsc + "\n" + colonEsc + "\n" +
		"PROJECT_DIR='" + projectDir + "'\n" +
		"COMPOSE_FILE='docker-compose.yml'\n" +
		"PROXY_REPO='ghcr.io/kidcarmi/culvert'\n" +
		"COMPOSE_OVERRIDE_FILE=''\n" +
		"SUDOERS_TEMPLATE='packaging/sudoers/culvert-maint'\n" +
		validate + "\n" + render + "\n" +
		`printf '%s\n' "$RENDERED_SUDOERS"` + "\n"

	out, err := exec.CommandContext(t.Context(), "sh", "-c", body).CombinedOutput() // #nosec G204 -- fixed test script content
	if err != nil {
		return string(out), err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines[len(lines)-1], nil
}

// agentComposePath is the `-f` value the agent passes: filepath.Clean at config
// load (config.go), then filepath.Join with compose_file (runner.go).
func agentComposePath(projectDir string) string {
	return filepath.Join(filepath.Clean(projectDir), "docker-compose.yml")
}

func TestCulvertMaintInstall_SudoersComposePathMatchesAgentForTrailingSlash(t *testing.T) {
	for _, dir := range []string{"/srv/culvert", "/srv/culvert/", "/srv/culvert//"} {
		t.Run(dir, func(t *testing.T) {
			rendered, err := renderMaintSudoersThroughValidation(t, dir)
			if err != nil {
				t.Fatalf("installer refused compose_project_dir=%q: %v\n%s", dir, err, rendered)
			}
			data, err := os.ReadFile(rendered) //nolint:gosec // test reads a path its own render script just wrote
			if err != nil {
				t.Fatalf("read rendered sudoers: %v", err)
			}
			want := "/usr/bin/docker compose -f " + agentComposePath(dir) + " ps --format json"
			if !strings.Contains(string(data), want) {
				var got []string
				for _, l := range strings.Split(string(data), "\n") {
					if strings.Contains(l, "ps --format json") && !strings.HasPrefix(l, "#") {
						got = append(got, l)
					}
				}
				t.Fatalf("compose_project_dir=%q: sudoers does not allow the agent's command\n want rule containing: %s\n got: %q",
					dir, want, got)
			}
		})
	}
}

// A non-canonical path the installer cannot reproduce exactly (dot segments,
// interior double slashes) must be refused rather than rendered into a rule
// the agent can never match.
func TestCulvertMaintInstall_SudoersRefusesNonCanonicalComposeDir(t *testing.T) {
	for _, dir := range []string{"/srv//culvert", "/srv/./culvert", "/srv/x/../culvert", "/srv/culvert/.", "/srv/culvert/.."} {
		t.Run(dir, func(t *testing.T) {
			out, err := renderMaintSudoersThroughValidation(t, dir)
			if err == nil {
				t.Fatalf("installer accepted non-canonical compose_project_dir=%q; agent would run -f %s", dir, agentComposePath(dir))
			}
			if !strings.Contains(out, "compose_project_dir") {
				t.Fatalf("refusal for %q does not name compose_project_dir:\n%s", dir, out)
			}
		})
	}
}
