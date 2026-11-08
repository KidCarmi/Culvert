package main

// install_script_maint_compose_cli_wrapper_test.go covers how
// packaging/culvert-maint/install.sh renders and installs the root-owned
// compose-cli wrapper (packaging/culvert-maint/compose-cli).
//
// The wrapper replaced the sudoers argument wildcards (`--backup /backup/*`,
// `--restore /backup/* --mode …`, `--older-than * --keep-last *`) that sudo-rs,
// the default sudo on Ubuntu 26.04, rejects. sudo runs it as root, and the
// compose path is rendered into it as a single-quoted shell literal, so the
// render is a root-executed sink: these tests extract the REAL
// render_compose_cli_wrapper() and sed_escape_replacement() helpers from the
// installer, render the REAL template with compose paths full of shell
// metacharacters, run the result, and require docker to receive the path
// byte-for-byte (no expansion, no injection). The argument validation itself
// is covered by cmd/culvert-maint/internal/runner/wrapper_test.go.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	maintInstallScript   = "packaging/culvert-maint/install.sh"
	maintWrapperTemplate = "packaging/culvert-maint/compose-cli"
	maintSudoersTemplate = "packaging/sudoers/culvert-maint"
	maintWrapperDest     = "/usr/local/libexec/culvert-maint/compose-cli"
)

// wrapperRenderHarness is the bash prelude shared by these tests: the real
// helpers plus a stand-in die() (install.sh's is a one-line function that
// extractShellFunction cannot lift) and a fake docker that records its argv,
// one argument per line, to "$1.argv".
func wrapperRenderHarness(t *testing.T) string {
	t.Helper()
	return extractShellFunction(t, maintInstallScript, "sed_escape_replacement") + "\n" +
		extractShellFunction(t, maintInstallScript, "render_compose_cli_wrapper") + "\n" +
		`die() { printf 'install.sh: ERROR — %s\n' "$*" >&2; exit 1; }` + "\n" +
		`OUT=$1` + "\n" +
		`FAKE="$OUT.fake-docker"` + "\n" +
		`printf '#!/bin/sh\nprintf "%%s\\n" "$@" > "%s.argv"\n' "$OUT" > "$FAKE"` + "\n" +
		`chmod 0700 "$FAKE"` + "\n"
}

// TestCulvertMaintInstall_WrapperRender_ComposePathIsInert renders the wrapper
// for compose project directories carrying every shell metacharacter that
// install.sh's reject_unsafe() still admits, runs the rendered wrapper, and
// requires the fake docker to receive the exact compose path.
func TestCulvertMaintInstall_WrapperRender_ComposePathIsInert(t *testing.T) {
	harness := wrapperRenderHarness(t)
	marker := filepath.Join(t.TempDir(), "pwned")
	for _, dir := range []string{
		"/srv/culvert",
		"/srv/cul$vert",
		"/srv/$(touch " + marker + ")",
		"/srv/a`touch " + marker + "`b",
		`/srv/back\slash`,
		"/srv/amp&ersand",
		"/srv/colon:comma,dir",
		"/srv/semi;colon",
		"/srv/glob*star?",
		"/srv/brace{x}",
	} {
		composePath := dir + "/docker-compose.yml"
		out := filepath.Join(t.TempDir(), "compose-cli")
		// The test passes the compose path via a file so no Go-side quoting
		// is involved in getting it into the script.
		pathFile := out + ".path"
		if err := os.WriteFile(pathFile, []byte(composePath), 0o600); err != nil {
			t.Fatal(err)
		}
		script := harness +
			`CPATH=$(cat "$OUT.path")` + "\n" +
			`render_compose_cli_wrapper '` + maintWrapperTemplate + `' "$CPATH" "$OUT"` + "\n" +
			// Point the rendered copy at the fake docker (the shipped wrapper
			// has no runtime override), then run it as install.sh would let
			// sudo run it.
			`sed -i "s|^DOCKER_BIN=/usr/bin/docker$|DOCKER_BIN=$FAKE|" "$OUT"` + "\n" +
			`sh "$OUT" backup /backup/snap.tar.gz` + "\n"
		runShellScript(t, script, out)

		got, err := os.ReadFile(out + ".argv")
		if err != nil {
			t.Fatalf("%q: fake docker did not run: %v", dir, err)
		}
		want := strings.Join([]string{
			"compose", "-f", composePath, "--profile", "cli", "run", "--rm", "cli", "--backup", "/backup/snap.tar.gz",
		}, "\n") + "\n"
		if string(got) != want {
			t.Errorf("%q: docker argv mismatch\n got: %q\nwant: %q", dir, got, want)
		}
		rendered, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(rendered), "{compose_path}") {
			t.Errorf("%q: placeholder left in rendered wrapper", dir)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a compose path was EXECUTED during render or by the rendered wrapper (command substitution reached a shell)")
	}
}

// TestCulvertMaintInstall_WrapperRender_RefusesUnsafeComposePath proves the
// renderer itself refuses the values that could break out of the
// single-quoted literal or the one-line form, independently of reject_unsafe.
func TestCulvertMaintInstall_WrapperRender_RefusesUnsafeComposePath(t *testing.T) {
	harness := wrapperRenderHarness(t)
	for name, composePath := range map[string]string{
		"single quote": "/srv/it's/docker-compose.yml",
		"newline":      "/srv/a\nb/docker-compose.yml",
		"relative":     "srv/docker-compose.yml",
	} {
		t.Run(name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "compose-cli")
			if err := os.WriteFile(out+".path", []byte(composePath), 0o600); err != nil {
				t.Fatal(err)
			}
			// The trailing x keeps $(…) from stripping a trailing newline.
			script := harness +
				`CPATH=$(cat "$OUT.path"; printf x); CPATH=${CPATH%x}` + "\n" +
				`if ( render_compose_cli_wrapper '` + maintWrapperTemplate + `' "$CPATH" "$OUT" ) 2>/dev/null; then` + "\n" +
				`    echo "render accepted an unsafe compose path" >&2; exit 1` + "\n" +
				`fi` + "\n" +
				// Refused before anything is written: no partial wrapper.
				`[ ! -e "$OUT" ] || { echo "render wrote output for an unsafe compose path" >&2; exit 1; }` + "\n"
			runShellScript(t, script, out)
		})
	}
}

// TestCulvertMaintInstall_WrapperPathAgreesEverywhere pins the one root-owned
// path across the three places that must agree: the installer's destination,
// the sudoers grant (and its env_keep alias), and the agent runner constant.
func TestCulvertMaintInstall_WrapperPathAgreesEverywhere(t *testing.T) {
	install := readRepoFile(t, maintInstallScript)
	for _, want := range []string{
		"WRAPPER_DIR=/usr/local/libexec/culvert-maint\n",
		`WRAPPER_DEST="$WRAPPER_DIR/compose-cli"` + "\n",
		`WRAPPER_TEMPLATE="$SCRIPT_DIR/compose-cli"` + "\n",
		`install -m 0755 -o root -g root "$RENDERED_WRAPPER" "$WRAPPER_DEST"` + "\n",
	} {
		if !strings.Contains(install, want) {
			t.Errorf("%s missing %q", maintInstallScript, strings.TrimSpace(want))
		}
	}
	// The wrapper must be installed BEFORE the sudoers file that grants it,
	// and only after the rendered sudoers passed visudo -c.
	iVisudo := strings.Index(install, `if ! visudo -c -f "$RENDERED_SUDOERS"`)
	iWrapper := strings.Index(install, `install -m 0755 -o root -g root "$RENDERED_WRAPPER" "$WRAPPER_DEST"`)
	iSudoers := strings.Index(install, `install -m 0440 -o root -g root "$RENDERED_SUDOERS" "$SUDOERS_DEST"`)
	if iVisudo < 0 || iWrapper < 0 || iSudoers < 0 || iVisudo >= iWrapper || iWrapper >= iSudoers {
		t.Errorf("install order must be: visudo -c (rendered) → install wrapper → install sudoers; got offsets %d, %d, %d", iVisudo, iWrapper, iSudoers)
	}

	sudoers := readRepoFile(t, maintSudoersTemplate)
	for _, want := range []string{
		"\nculvert-maint ALL=(root) NOPASSWD: " + maintWrapperDest + "\n",
		"\nCmnd_Alias CULVERT_MAINT_PASSPHRASE_CMNDS = " + maintWrapperDest + "\n",
	} {
		if !strings.Contains(sudoers, want) {
			t.Errorf("%s missing %q", maintSudoersTemplate, strings.TrimSpace(want))
		}
	}

	runner := readRepoFile(t, "cmd/culvert-maint/internal/runner/templates_d16b.go")
	if !strings.Contains(runner, `const ComposeCLIWrapperPath = "`+maintWrapperDest+`"`) {
		t.Errorf("runner.ComposeCLIWrapperPath must be %q", maintWrapperDest)
	}

	if _, err := os.Stat(maintWrapperTemplate); err != nil {
		t.Errorf("%s missing: %v (install.sh requires it; the deploy bundle copies packaging/)", maintWrapperTemplate, err)
	}
}
