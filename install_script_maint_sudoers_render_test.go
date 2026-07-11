package main

// install_script_maint_sudoers_render_test.go — regression coverage for the
// sudoers render pipeline in packaging/culvert-maint/install.sh, specifically
// the colon-escaping of {proxy_repo} (Gap B).
//
// The maintenance-agent installer renders packaging/sudoers/culvert-maint by
// substituting {compose_path} and {proxy_repo} with sed. sudo treats a bare
// ':' in a Cmnd spec as the Runas/Host separator, so a proxy_repo that carries
// a registry PORT (e.g. 127.0.0.1:5000/culvert, or any private registry on a
// non-default port) rendered an UNESCAPED ':' that `visudo -c` rejects with a
// syntax error — leaving the systemd unit + sudoers uninstalled and the agent
// surfacing as "Agent unreachable". The template's own literal colons
// (sha256\:, culvert/proxy\:pinned) are hand-escaped; the substituted repo was
// not. sudoers_escape_colon() (run before sed_escape_replacement) closes that.
//
// This extracts the REAL sed_escape_replacement() + sudoers_escape_colon()
// helper bodies out of packaging/culvert-maint/install.sh and reproduces the
// installer's Pass-1 substitution, then validates the result with `visudo -c`
// — the same tool the installer gates on — so a regression in either helper
// (or the render call site) fails here deterministically.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// requireVisudoForTest skips when visudo isn't on PATH — the render assertion
// below validates against the real sudoers grammar and can't be meaningfully
// checked without it.
func requireVisudoForTest(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("visudo"); err != nil {
		t.Skip("visudo not available in this environment — skipping")
	}
}

// renderMaintSudoers reproduces the installer's Pass-1 substitution: it sources
// the REAL sed_escape_replacement + sudoers_escape_colon helpers from
// packaging/culvert-maint/install.sh and renders packaging/sudoers/culvert-maint
// with the given proxy_repo (the {compose_override_path} line is dropped, as the
// installer does when no override is configured). Returns the rendered file path.
func renderMaintSudoers(t *testing.T, proxyRepo string) string {
	t.Helper()
	sedEsc := extractShellFunction(t, "packaging/culvert-maint/install.sh", "sed_escape_replacement")
	colonEsc := extractShellFunction(t, "packaging/culvert-maint/install.sh", "sudoers_escape_colon")

	out := filepath.Join(t.TempDir(), "culvert-maint.rendered")
	// Mirror install.sh §6 Pass-1 exactly: colon-escape proxy_repo FIRST, then
	// sed-escape it, and drop the override-only line (no override configured).
	script := sedEsc + "\n" + colonEsc + "\n" +
		"PROXY_REPO='" + proxyRepo + "'\n" +
		"COMPOSE_PATH='/srv/culvert/docker-compose.yml'\n" +
		`sed -e "s|{compose_path}|$(sed_escape_replacement "$COMPOSE_PATH")|g" ` +
		`-e "s|{proxy_repo}|$(sed_escape_replacement "$(sudoers_escape_colon "$PROXY_REPO")")|g" ` +
		`packaging/sudoers/culvert-maint | sed '/{compose_override_path}/d' > '` + out + "'\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("render sudoers failed: %v\n%s", err, b)
	}
	return out
}

// pullTagLines returns the rendered `docker pull`/`docker tag` NOPASSWD command
// lines (the P1.4 image pull/retag entries that embed {proxy_repo}).
func pullTagLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path) //nolint:gosec // test reads a path it just wrote
	if err != nil {
		t.Fatalf("read rendered sudoers: %v", err)
	}
	var out []string
	for _, ln := range strings.Split(string(data), "\n") {
		if strings.Contains(ln, "NOPASSWD:") &&
			(strings.Contains(ln, "/usr/bin/docker pull ") || strings.Contains(ln, "/usr/bin/docker tag ")) {
			out = append(out, ln)
		}
	}
	if len(out) != 2 {
		t.Fatalf("expected exactly 2 pull/tag NOPASSWD lines, got %d:\n%s", len(out), strings.Join(out, "\n"))
	}
	return out
}

// TestCulvertMaintInstall_SudoersRender_PortedRepoEscapesColon is the Gap B
// regression: a proxy_repo with a registry port must render with the port colon
// backslash-escaped so `visudo -c` accepts the file. Before the fix, the port
// colon rendered bare and visudo rejected the whole file, aborting the agent
// install (observed in the agent-day2-update e2e binding to 127.0.0.1:5000).
func TestCulvertMaintInstall_SudoersRender_PortedRepoEscapesColon(t *testing.T) {
	requireVisudoForTest(t)

	rendered := renderMaintSudoers(t, "127.0.0.1:5000/culvert")

	for _, ln := range pullTagLines(t, rendered) {
		// The port colon MUST be escaped; a bare "127.0.0.1:5000" is the bug.
		if strings.Contains(ln, "127.0.0.1:5000") {
			t.Errorf("port colon left UNESCAPED in rendered sudoers line (visudo will reject it):\n  %s", ln)
		}
		if !strings.Contains(ln, `127.0.0.1\:5000`) {
			t.Errorf("expected escaped port colon (127.0.0.1\\:5000) in rendered sudoers line:\n  %s", ln)
		}
	}

	if out, err := exec.CommandContext(t.Context(), "visudo", "-c", "-f", rendered).CombinedOutput(); err != nil {
		t.Fatalf("visudo -c rejected the rendered sudoers for a ported proxy_repo (Gap B regression): %v\n%s", err, out)
	}
}

// TestCulvertMaintInstall_SudoersRender_DefaultRepoStillValid guards against
// over-escaping: the no-port default repo must still render clean and pass
// `visudo -c`, with the repo substituted verbatim (no stray backslash).
func TestCulvertMaintInstall_SudoersRender_DefaultRepoStillValid(t *testing.T) {
	requireVisudoForTest(t)

	rendered := renderMaintSudoers(t, "ghcr.io/kidcarmi/culvert")

	for _, ln := range pullTagLines(t, rendered) {
		if !strings.Contains(ln, "ghcr.io/kidcarmi/culvert@sha256") {
			t.Errorf("default repo not substituted verbatim in rendered sudoers line:\n  %s", ln)
		}
		if strings.Contains(ln, `ghcr.io\`) {
			t.Errorf("no-port repo should carry no backslash escape (over-escaping):\n  %s", ln)
		}
	}

	if out, err := exec.CommandContext(t.Context(), "visudo", "-c", "-f", rendered).CombinedOutput(); err != nil {
		t.Fatalf("visudo -c rejected the rendered sudoers for the default proxy_repo: %v\n%s", err, out)
	}
}
