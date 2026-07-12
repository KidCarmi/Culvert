package main

// install_script_maint_sudoers_compose_path_colon_test.go — regression
// coverage for a sibling of the Gap B bug already fixed for proxy_repo (see
// install_script_maint_sudoers_render_test.go): the sudoers render pipeline
// in packaging/culvert-maint/install.sh colon-escapes proxy_repo before
// substituting it into the {proxy_repo} placeholder, but does NOT apply the
// same sudoers_escape_colon() treatment to {compose_path} /
// {compose_override_path} — even though compose_project_dir (validated only
// by reject_unsafe, which does not reject ':') flows into COMPOSE_PATH and
// is substituted into the MIDDLE of a Cmnd spec
// ("docker compose -f {compose_path} ps --format json").
//
// A compose_project_dir containing a colon (a perfectly legal Linux
// directory-name character, e.g. a path incorporating a timestamp or a
// mount label) therefore renders an unescaped ':' into /etc/sudoers.d/
// culvert-maint, which sudo's grammar treats as a Host/Runas separator —
// `visudo -c` rejects the file with a syntax error, aborting the
// maintenance-agent install exactly like the already-fixed proxy_repo case.
//
// This extracts the REAL sed_escape_replacement()/sudoers_escape_colon()
// helpers and the REAL Pass-1/Pass-2 render block (by line-range, since that
// code lives at script top level, not inside a function) out of
// packaging/culvert-maint/install.sh, so a fix to the script is picked up
// automatically and the test does not silently drift from the real
// pipeline.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// extractShellLineRange returns the lines from the first line containing
// startSubstr through the first subsequent line containing endSubstr
// (inclusive of both), extracted verbatim from scriptPath. Used for script
// regions that aren't wrapped in a named function (extractShellFunction
// handles those).
func extractShellLineRange(t *testing.T, scriptPath, startSubstr, endSubstr string) string {
	t.Helper()
	raw, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("read %s: %v", scriptPath, err)
	}
	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, line := range lines {
		if strings.Contains(line, startSubstr) {
			start = i
			break
		}
	}
	if start == -1 {
		t.Fatalf("could not find line containing %q in %s", startSubstr, scriptPath)
	}
	for i := start; i < len(lines); i++ {
		if strings.Contains(lines[i], endSubstr) {
			return strings.Join(lines[start:i+1], "\n")
		}
	}
	t.Fatalf("could not find line containing %q after %q in %s", endSubstr, startSubstr, scriptPath)
	return ""
}

// renderMaintSudoersForComposeDir reproduces the installer's REAL Pass-1 +
// Pass-2 sudoers render (extracted verbatim from packaging/culvert-maint/
// install.sh, not hand-copied) for a given compose_project_dir, with no
// compose_override_file configured. Returns the path to the rendered file.
func renderMaintSudoersForComposeDir(t *testing.T, projectDir string) string {
	t.Helper()
	sedEsc := extractShellFunction(t, "packaging/culvert-maint/install.sh", "sed_escape_replacement")
	colonEsc := extractShellFunction(t, "packaging/culvert-maint/install.sh", "sudoers_escape_colon")
	renderBlock := extractShellLineRange(t, "packaging/culvert-maint/install.sh",
		`COMPOSE_PATH="$PROJECT_DIR/$COMPOSE_FILE"`, `rm -f "$RENDERED_SUDOERS_TMP"`)

	script := sedEsc + "\n" + colonEsc + "\n" +
		"PROJECT_DIR='" + projectDir + "'\n" +
		"COMPOSE_FILE='docker-compose.yml'\n" +
		"PROXY_REPO='ghcr.io/kidcarmi/culvert'\n" +
		"COMPOSE_OVERRIDE_FILE=''\n" +
		"SUDOERS_TEMPLATE='packaging/sudoers/culvert-maint'\n" +
		renderBlock + "\n" +
		`printf '%s\n' "$RENDERED_SUDOERS"` + "\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("render script failed: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines[len(lines)-1]
}

// TestCulvertMaintInstall_SudoersRender_ComposeProjectDirEscapesColon proves
// that a compose_project_dir containing a colon — legal on Linux, and passed
// by reject_unsafe (which rejects whitespace/quotes/pipe/control chars but
// not ':') — renders into a sudoers Cmnd spec with the colon escaped, so
// `visudo -c` accepts the file. Before the fix, {compose_path} was
// substituted with only sed_escape_replacement (no sudoers_escape_colon),
// leaving a bare ':' that visudo rejects — aborting the maintenance-agent
// install with a cryptic sudoers syntax error, exactly like the
// already-fixed proxy_repo case (Gap B).
func TestCulvertMaintInstall_SudoersRender_ComposeProjectDirEscapesColon(t *testing.T) {
	requireVisudoForTest(t)

	rendered := renderMaintSudoersForComposeDir(t, "/srv/culvert-2026-07-11T12:00:00")

	data, err := os.ReadFile(rendered) //nolint:gosec // test reads a path its own render script just wrote
	if err != nil {
		t.Fatalf("read rendered sudoers: %v", err)
	}
	if strings.Contains(string(data), "/srv/culvert-2026-07-11T12:00:00/") {
		t.Errorf("compose_project_dir colon left UNESCAPED in rendered sudoers (visudo will reject it):\n%s", data)
	}

	// #nosec G204 -- fixed argv; `rendered` is a temp path this test wrote
	if out, err := exec.CommandContext(t.Context(), "visudo", "-c", "-f", rendered).CombinedOutput(); err != nil {
		t.Fatalf("visudo -c rejected the rendered sudoers for a compose_project_dir containing a colon: %v\n%s", err, out)
	}
}

// TestCulvertMaintInstall_SudoersRender_ComposeProjectDirNoColonStillValid is
// the baseline sanity check: an ordinary compose_project_dir with no colon
// (the common case) still renders clean and passes `visudo -c`.
func TestCulvertMaintInstall_SudoersRender_ComposeProjectDirNoColonStillValid(t *testing.T) {
	requireVisudoForTest(t)

	rendered := renderMaintSudoersForComposeDir(t, "/srv/culvert")

	// #nosec G204 -- fixed argv; `rendered` is a temp path this test wrote
	if out, err := exec.CommandContext(t.Context(), "visudo", "-c", "-f", rendered).CombinedOutput(); err != nil {
		t.Fatalf("visudo -c rejected the rendered sudoers for a plain compose_project_dir: %v\n%s", err, out)
	}
}
