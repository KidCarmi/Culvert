package main

// install_script_maint_sudoers_comma_test.go — regression coverage for a
// second sibling of the Gap B bug already fixed for the sudoers-colon case
// (proxy_repo: install_script_maint_sudoers_render_test.go; compose_path:
// install_script_maint_sudoers_compose_path_colon_test.go): sudoers treats
// an unescaped ',' the same way it treats an unescaped ':' inside a Cmnd
// spec — as a list separator, not a literal path character — so a
// compose_project_dir containing a comma (a perfectly legal Linux directory
// name character, e.g. a path incorporating a human-readable timestamp or a
// backup-rotation suffix like "/srv/culvert,backup") renders an unescaped
// ',' into /etc/sudoers.d/culvert-maint. `visudo -c` rejects that file with
// "expected a fully-qualified path name", aborting the maintenance-agent
// install exactly like the already-fixed colon case.
//
// reject_unsafe() (packaging/culvert-maint/install.sh) rejects control
// chars/whitespace/quotes/pipe but not ','; sudoers_escape_colon() — run on
// COMPOSE_PATH/PROXY_REPO/COMPOSE_OVERRIDE_PATH before every {placeholder}
// substitution — escapes only ':', not ','. Confirmed against the real
// visudo binary (v1.9.15p5): an unescaped comma in a Cmnd path is rejected,
// while `\,` parses OK, exactly mirroring the colon case.
//
// This reuses renderMaintSudoersForComposeDir (defined in
// install_script_maint_sudoers_compose_path_colon_test.go), which extracts
// the REAL sed_escape_replacement()/sudoers_escape_colon() helpers and the
// REAL Pass-1/Pass-2 render block out of packaging/culvert-maint/install.sh,
// so a fix to the script is picked up automatically and this test cannot
// silently drift from the real pipeline.

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestCulvertMaintInstall_SudoersRender_ComposeProjectDirEscapesComma proves
// that a compose_project_dir containing a comma — legal on Linux, and passed
// by reject_unsafe (which rejects whitespace/quotes/pipe/control chars but
// not ',') — renders into a sudoers Cmnd spec with the comma escaped, so
// `visudo -c` accepts the file. Before the fix, {compose_path} was
// substituted with only colon-escaping (no comma-escaping), leaving a bare
// ',' that visudo rejects as "expected a fully-qualified path name" —
// aborting the maintenance-agent install with a cryptic sudoers syntax
// error, exactly like the already-fixed colon case (Gap B).
func TestCulvertMaintInstall_SudoersRender_ComposeProjectDirEscapesComma(t *testing.T) {
	requireVisudoForTest(t)

	rendered := renderMaintSudoersForComposeDir(t, "/srv/culvert,backup")

	data, err := os.ReadFile(rendered) //nolint:gosec // test reads a path its own render script just wrote
	if err != nil {
		t.Fatalf("read rendered sudoers: %v", err)
	}
	if strings.Contains(string(data), "/srv/culvert,backup/") {
		t.Errorf("compose_project_dir comma left UNESCAPED in rendered sudoers (visudo will reject it):\n%s", data)
	}

	// #nosec G204 -- fixed argv; `rendered` is a temp path this test wrote
	if out, err := exec.CommandContext(t.Context(), "visudo", "-c", "-f", rendered).CombinedOutput(); err != nil {
		t.Fatalf("visudo -c rejected the rendered sudoers for a compose_project_dir containing a comma: %v\n%s", err, out)
	}
}
