package main

// install_script_patch_allow_peers_test.go — regression coverage for the
// patch_allow_peers_numeric_uid() helper in scripts/install.sh, which
// wire_release_agent_for_compose uses to authorize the running proxy
// container's UID in /etc/culvert-maint/config.toml's allow_peers array
// before wiring Release Management over the local maintenance-agent socket.
//
// This extracts the REAL patch_allow_peers_numeric_uid() function body out
// of scripts/install.sh (rather than duplicating it here) and exercises it
// under bash, so the test tracks the actual installer script instead of a
// copy that can drift. `sudo` and `install` are shadowed with no-op/plain-
// copy shell functions so the test does not require real root or a
// pre-existing culvert-maint system group — the function's own privileged
// calls are the only thing being substituted, not the awk logic under test.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runPatchAllowPeers extracts the real patch_allow_peers_numeric_uid()
// function from scripts/install.sh and runs it against a temp config file
// seeded with the given allow_peers line, returning the resulting
// /etc/culvert-maint/config.toml content (patched in place, as the real
// function does) and the function's own exit status.
func runPatchAllowPeers(t *testing.T, allowPeersLine, uid string) (content string, exitCode int) {
	t.Helper()
	fn := extractShellFunctionBraceAware(t, "scripts/install.sh", "patch_allow_peers_numeric_uid")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	toml := "compose_project_dir = \"/srv/culvert\"\n" +
		allowPeersLine + "\n" +
		"socket_path = \"/run/culvert-maint/culvert-maint.sock\"\n"
	if err := os.WriteFile(cfgPath, []byte(toml), 0o644); err != nil { //nolint:gosec // test fixture, not sensitive
		t.Fatalf("write config.toml: %v", err)
	}

	// Shadow sudo (identity — no real privilege escalation needed for a temp
	// file the test already owns) and install (plain copy — the test only
	// cares about resulting file content, not root:culvert-maint ownership,
	// which the real installer applies as a separate, already-covered concern).
	shadows := `
sudo() { "$@"; }
install() {
  local src dst
  src="${@: -2:1}"
  dst="${@: -1}"
  cp "$src" "$dst"
}
`
	// patch_allow_peers_numeric_uid hardcodes cfg=/etc/culvert-maint/config.toml
	// as a local default — rewrite that one literal to our temp path so the
	// test never touches the real system config.
	fn = strings.Replace(fn, `cfg="/etc/culvert-maint/config.toml"`, `cfg="`+cfgPath+`"`, 1)

	script := shadows + fn + "\n" +
		`patch_allow_peers_numeric_uid "` + uid + `"` + "\n" +
		`echo "EXIT:$?"` + "\n"

	cmd := exec.CommandContext(t.Context(), "bash", "-c", script) // #nosec G204 -- fixed test script content, not external/user input
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("shell script failed: %v\n%s", err, out)
	}
	outStr := string(out)
	exitCode = -1
	for _, line := range strings.Split(outStr, "\n") {
		if strings.HasPrefix(line, "EXIT:") {
			if line == "EXIT:0" {
				exitCode = 0
			} else {
				exitCode = 1
			}
		}
	}

	got, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read patched config.toml: %v", err)
	}
	return string(got), exitCode
}

// TestInstallScript_PatchAllowPeers_EmptyArrayProducesValidTOML proves that
// patching allow_peers when the operator's config has an EMPTY array
// (`allow_peers = []`, e.g. a deliberate "no peers authorized yet" starting
// state, or config.example.toml hand-edited to clear the default before
// assigning real peers) produces a syntactically valid TOML array.
//
// The generic non-empty-array branch does
// `sub(/[[:space:]]*\][[:space:]]*$/, ", \"" uid "\"]", line)` — it always
// prepends a comma before the new element, assuming at least one existing
// element precedes the closing bracket. Against an empty array that turns
// `allow_peers = []` into `allow_peers = [, "1000"]`, which is not valid
// TOML: a leading comma with no preceding array element. The maintenance
// agent's config loader (cmd/culvert-maint/internal/config) uses a strict
// TOML decoder, so this failure mode is not silent — /etc/culvert-maint/
// config.toml becomes unparsable and the agent (and every subsequent
// wire_release_agent_for_compose run) breaks until an operator manually
// repairs the file, even though the function itself reports success.
func TestInstallScript_PatchAllowPeers_EmptyArrayProducesValidTOML(t *testing.T) {
	content, exitCode := runPatchAllowPeers(t, `allow_peers = []`, "1000")

	if exitCode != 0 {
		t.Fatalf("patch_allow_peers_numeric_uid returned failure (exit %d) against an empty array; resulting config:\n%s", exitCode, content)
	}
	if strings.Contains(content, "[, ") || strings.Contains(content, "[,\"") {
		t.Fatalf("patch_allow_peers_numeric_uid produced invalid TOML from an empty allow_peers array "+
			"(leading comma with no array element); resulting config:\n%s", content)
	}
	want := `allow_peers = ["1000"]`
	if !strings.Contains(content, want) {
		t.Fatalf("patched config does not contain %q; got:\n%s", want, content)
	}
}

// TestInstallScript_PatchAllowPeers_DefaultArrayReplaced is the baseline
// sanity check: the documented default (`allow_peers = ["culvert-cp"]`) is
// replaced wholesale with the numeric UID, as designed.
func TestInstallScript_PatchAllowPeers_DefaultArrayReplaced(t *testing.T) {
	content, exitCode := runPatchAllowPeers(t, `allow_peers = ["culvert-cp"]`, "1000")

	if exitCode != 0 {
		t.Fatalf("patch_allow_peers_numeric_uid returned failure (exit %d); resulting config:\n%s", exitCode, content)
	}
	want := `allow_peers = ["1000"]`
	if !strings.Contains(content, want) {
		t.Fatalf("patched config does not contain %q; got:\n%s", want, content)
	}
}

// TestInstallScript_PatchAllowPeers_NonDefaultArrayAppended proves the
// append path (a non-empty, non-default array) still works: the UID is
// added as an additional element rather than replacing the existing one.
func TestInstallScript_PatchAllowPeers_NonDefaultArrayAppended(t *testing.T) {
	content, exitCode := runPatchAllowPeers(t, `allow_peers = ["alice"]`, "1000")

	if exitCode != 0 {
		t.Fatalf("patch_allow_peers_numeric_uid returned failure (exit %d); resulting config:\n%s", exitCode, content)
	}
	want := `allow_peers = ["alice", "1000"]`
	if !strings.Contains(content, want) {
		t.Fatalf("patched config does not contain %q; got:\n%s", want, content)
	}
}

// TestInstallScript_PatchAllowPeers_TrailingCommentStillPatched proves that a
// single-line allow_peers array followed by a trailing inline TOML comment
// (e.g. an operator's own note on who is authorized — an entirely normal
// TOML habit, and the exact line config.example.toml itself documents right
// above the default) is still recognized as a single-line array and patched.
//
// The array-continues-onto-later-lines detector used to test whether the RAW
// line ended in "]" (`line !~ /\][[:space:]]*$/`). A trailing comment after
// the closing bracket ("...]  # note") means the line does NOT end in "]",
// so a perfectly patchable single-line array was misclassified as spanning
// multiple lines and the function bailed out (exit 42 -> return 1) without
// touching the file — silently skipping Release Management auto-wiring
// (wire_release_agent_for_compose treats this failure as "skip", not fatal)
// on any config an operator had annotated.
func TestInstallScript_PatchAllowPeers_TrailingCommentStillPatched(t *testing.T) {
	content, exitCode := runPatchAllowPeers(t, `allow_peers = ["alice"]  # ops-managed peers`, "1000")

	if exitCode != 0 {
		t.Fatalf("patch_allow_peers_numeric_uid returned failure (exit %d) against a single-line array with a "+
			"trailing comment; resulting config:\n%s", exitCode, content)
	}
	want := `allow_peers = ["alice", "1000"]  # ops-managed peers`
	if !strings.Contains(content, want) {
		t.Fatalf("patched config does not contain %q (comment must be preserved); got:\n%s", want, content)
	}
}

// TestInstallScript_PatchAllowPeers_DefaultArrayWithTrailingCommentReplaced
// covers the same misclassification against the default-array replacement
// branch: a trailing comment on the exact packaged default line
// (`allow_peers = ["culvert-cp"]  # ...`) must still be recognized as the
// default and replaced, with the comment preserved.
func TestInstallScript_PatchAllowPeers_DefaultArrayWithTrailingCommentReplaced(t *testing.T) {
	content, exitCode := runPatchAllowPeers(t, `allow_peers = ["culvert-cp"]  # default peer, see docs`, "1000")

	if exitCode != 0 {
		t.Fatalf("patch_allow_peers_numeric_uid returned failure (exit %d) against the default array with a "+
			"trailing comment; resulting config:\n%s", exitCode, content)
	}
	want := `allow_peers = ["1000"]  # default peer, see docs`
	if !strings.Contains(content, want) {
		t.Fatalf("patched config does not contain %q (comment must be preserved); got:\n%s", want, content)
	}
}
