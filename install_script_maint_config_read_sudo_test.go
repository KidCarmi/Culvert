package main

// install_script_maint_config_read_sudo_test.go — regression coverage for a
// missing-sudo defect in scripts/install.sh's Release Management wiring.
//
// packaging/culvert-maint/install.sh installs /etc/culvert-maint as
// `install -m 0750 -o root -g culvert-maint -d /etc/culvert-maint` and
// /etc/sudoers.d/culvert-maint as `install -m 0440 -o root -g root` — see
// packaging/culvert-maint/install.sh:323,512. scripts/install.sh's primary,
// documented usage (README.md: `curl ... | bash`, no leading `sudo`) runs as
// a non-root, sudo-CAPABLE user: it sprinkles `sudo` only where a specific
// command needs it (e.g. `sudo docker ...`, `sudo systemctl ...`), exactly
// like `maint_toml_string`'s `sudo awk ... "$file"` and
// `patch_allow_peers_numeric_uid`'s `sudo awk ... "$cfg"` a few lines above
// the code under test here. That invoking user is never added to the
// culvert-maint group (nothing in scripts/install.sh does a `usermod -aG
// culvert-maint`), so any UNPRIVILEGED read of a path under the 0750
// root:culvert-maint /etc/culvert-maint directory hits EACCES on the
// directory itself — and bash's `[[ -f ]]`/`grep`/`tail` all report that as
// "the file doesn't exist" / "no match", not as a permission error.
//
// Four reads of that config slipped through without the `sudo` every sibling
// read in this file correctly uses:
//   - wire_release_agent_for_compose's own existence gate (~line 1986):
//     `[[ ! -f "$cfg" || ! -f "$sudoers" ]]` ALWAYS takes the "config or
//     sudoers file is missing" early return on a normal non-root install,
//     even though both files are present and correctly installed — Release
//     Management's local-socket auto-wiring can never activate on the
//     documented install path.
//   - the idempotent-newline check before appending compose_override_file
//     (~line 2042): `tail -c1 "$cfg"` — downstream of (and currently
//     unreachable because of) the bug above, but would misread "permission
//     denied" as "already ends in a newline" once the gate above is fixed,
//     per the surrounding comment's own stated threat model.
//   - the compose_project_dir migration for a custom CULVERT_DIR (~line
//     2418) and the pre-RuntimeDirectory socket_path migration (~line 2433)
//     in install_maint_agent: both are `grep -q '...' /etc/culvert-maint/
//     config.toml` with no `sudo`, so neither migration ever fires on a
//     non-root install.
//
// This is a static contract test (the same style as
// install_script_wait_timeout_test.go) rather than a live-privilege-
// separation test: deterministically reproducing the real EACCES needs an
// actual non-root user with working passwordless sudo, which the test
// environment cannot assume (and this repo's CI runs as root in some lanes,
// which would silently defeat a chmod-based reproduction by bypassing DAC
// checks). Instead this pins the actual, unambiguous defect directly against
// the script source: every line that reads $cfg/$sudoers must also invoke
// sudo, matching every other read of the same files in this script.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// sudoWordRE matches the standalone command token "sudo" — NOT as a
// substring of "sudoers" (the sudoers.d drop-in file this same script reads
// right alongside $cfg), which a naive strings.Contains(line, "sudo") would
// wrongly treat as evidence of privilege elevation.
var sudoWordRE = regexp.MustCompile(`\bsudo\b`)

// linesContaining returns every line of text that contains substr.
func linesContaining(text, substr string) []string {
	var out []string
	for _, ln := range strings.Split(text, "\n") {
		if strings.Contains(ln, substr) {
			out = append(out, ln)
		}
	}
	return out
}

// assertSoleLineUsesSudo finds the exactly-one line in body containing
// substr and fails the test unless that line also invokes sudo as a command
// — i.e. the read is privilege-elevated, matching every sibling read of the
// same maintenance-agent config files.
func assertSoleLineUsesSudo(t *testing.T, body, fnName, substr string) {
	t.Helper()
	matches := linesContaining(body, substr)
	if len(matches) != 1 {
		t.Fatalf("%s: expected exactly 1 line containing %q, found %d (script drifted — update this test's anchor): %v",
			fnName, substr, len(matches), matches)
	}
	if !sudoWordRE.MatchString(matches[0]) {
		t.Errorf("%s: read of the maintenance-agent config/sudoers file is not sudo-elevated — "+
			"the primary non-root `curl | bash` install user is never added to the culvert-maint "+
			"group, so this unprivileged read hits EACCES on the 0750 root:culvert-maint directory "+
			"and silently behaves as if the file were absent:\n  %s", fnName, strings.TrimSpace(matches[0]))
	}
}

// TestInstallScript_WireReleaseAgent_ExistenceGateUsesSudo is the primary
// regression: wire_release_agent_for_compose's own "does the maint-agent
// config/sudoers exist" gate must read both paths as root (via `sudo`), or
// it always concludes they are missing on a normal non-root install and
// Release Management auto-wiring is permanently disabled.
func TestInstallScript_WireReleaseAgent_ExistenceGateUsesSudo(t *testing.T) {
	body := extractShellFunctionBraceAware(t, "scripts/install.sh", "wire_release_agent_for_compose")

	assertSoleLineUsesSudo(t, body, "wire_release_agent_for_compose", `-f "$cfg"`)
	assertSoleLineUsesSudo(t, body, "wire_release_agent_for_compose", `-f "$sudoers"`)
}

// TestInstallScript_WireReleaseAgent_NewlineCheckUsesSudo covers the
// downstream idempotent-newline probe (`tail -c1 "$cfg"`): once the
// existence gate above is fixed and this code becomes reachable on a
// non-root install, an unprivileged `tail` would still misread "permission
// denied" as "file already ends in a newline" and could corrupt
// /etc/culvert-maint/config.toml per the surrounding comment's own
// documented threat model.
func TestInstallScript_WireReleaseAgent_NewlineCheckUsesSudo(t *testing.T) {
	body := extractShellFunctionBraceAware(t, "scripts/install.sh", "wire_release_agent_for_compose")

	assertSoleLineUsesSudo(t, body, "wire_release_agent_for_compose", `tail -c1 "$cfg"`)
}

// TestInstallScript_InstallMaintAgent_ConfigMigrationChecksUseSudo covers
// install_maint_agent's two one-time config migrations (repointing
// compose_project_dir at a custom CULVERT_DIR, and moving socket_path to the
// managed runtime dir) — both gated on an unprivileged `grep -q ... /etc/
// culvert-maint/config.toml` that never matches on a non-root install, so
// neither migration ever runs.
func TestInstallScript_InstallMaintAgent_ConfigMigrationChecksUseSudo(t *testing.T) {
	body := extractShellFunctionBraceAware(t, "scripts/install.sh", "install_maint_agent")

	assertSoleLineUsesSudo(t, body, "install_maint_agent", `grep -q '^compose_project_dir = "/srv/culvert"' /etc/culvert-maint/config.toml`)
	assertSoleLineUsesSudo(t, body, "install_maint_agent", `grep -q '^socket_path = "/run/culvert-maint.sock"' /etc/culvert-maint/config.toml`)
}

// TestInstallScript_MaintConfigPaths_SanityCheck guards the test file itself
// against silent drift: fail loudly (not just skip) if scripts/install.sh no
// longer exists where every other install_script_*_test.go expects it.
func TestInstallScript_MaintConfigPaths_SanityCheck(t *testing.T) {
	if _, err := os.Stat("scripts/install.sh"); err != nil {
		t.Fatalf("scripts/install.sh not found: %v", err)
	}
}
