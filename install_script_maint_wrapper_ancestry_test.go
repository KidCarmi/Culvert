package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// ASTRA R1 on the #1825 port: the sudo-granted compose-cli wrapper lives in
// /usr/local/libexec/culvert-maint. The ported installer checked three
// LEXICAL directories with `find -H`, which follows a symlink without looking
// at the redirected destination's parents: with /usr/local/libexec pointing at
// /srv/delegated/libexec and /srv/delegated writable by an unprivileged
// account, every check passed, yet that account could later rename or replace
// the directory holding what sudo runs as root. check_root_dir_chain refuses
// any symlinked component and checks every component from / down, before
// anything is created through the path and again afterwards.

// chainHarness is the real check_root_dir_chain plus a stand-in die()
// (install.sh's is a one-line function extractShellFunction cannot lift).
func chainHarness(t *testing.T) string {
	t.Helper()
	return extractShellFunction(t, maintInstallScript, "check_root_dir_chain") + "\n" +
		`die() { printf 'install.sh: ERROR — %s\n' "$*" >&2; exit 1; }` + "\n"
}

// runChain runs `check_root_dir_chain DIR UID TOP` under shell sh (dash or
// bash) and reports whether it accepted, with its output.
func runChain(t *testing.T, sh, dir string, uid int, top string) (accepted bool, output string) {
	t.Helper()
	script := chainHarness(t) + `check_root_dir_chain "$1" "$2" "$3" && echo CHAIN-OK` + "\n"
	cmd := exec.CommandContext(t.Context(), sh, "-c", script, "chain", dir, strconv.Itoa(uid), top) // #nosec G204 -- fixed test script, test-owned paths
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatalf("%s: %v", sh, err)
	}
	return err == nil && strings.Contains(string(out), "CHAIN-OK"), string(out)
}

// mkdirMode creates p (and parents) under a test temp dir and sets its mode;
// the layouts need exact modes (0755, 0775, 0777), including unsafe ones.
func mkdirMode(t *testing.T, p string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(p, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil { //nolint:gosec // test-owned temp path; the unsafe modes are the point of the test
		t.Fatal(err)
	}
}

// symlinkTest creates link -> target under a test temp dir.
func symlinkTest(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil { //nolint:gosec // test-owned temp paths
		t.Fatal(err)
	}
}

type ancestryLayout struct {
	name   string
	build  func(t *testing.T, top string) string // returns the wrapper dir to check
	accept bool
	want   string
}

func ancestryLayouts() []ancestryLayout {
	wrapperDir := func(top string) string { return filepath.Join(top, "usr", "local", "libexec", "culvert-maint") }
	return []ancestryLayout{
		{name: "ordinary root-like chain (positive control)", accept: true, build: func(t *testing.T, top string) string {
			mkdirMode(t, wrapperDir(top), 0o755)
			return wrapperDir(top)
		}},
		{name: "wrapper directory not created yet (positive control)", accept: true, build: func(t *testing.T, top string) string {
			mkdirMode(t, filepath.Dir(wrapperDir(top)), 0o755)
			return wrapperDir(top)
		}},
		{name: "ASTRA R1: libexec is a symlink into a writable-parent directory", want: "is a symlink", build: func(t *testing.T, top string) string {
			astraLayout(t, top)
			return wrapperDir(top)
		}},
		{name: "the wrapper directory itself is a symlink", want: "is a symlink", build: func(t *testing.T, top string) string {
			mkdirMode(t, filepath.Dir(wrapperDir(top)), 0o755)
			mkdirMode(t, filepath.Join(top, "elsewhere"), 0o755)
			symlinkTest(t, filepath.Join(top, "elsewhere"), wrapperDir(top))
			return wrapperDir(top)
		}},
		{name: "group-writable ancestor", want: "not group/world-writable", build: func(t *testing.T, top string) string {
			mkdirMode(t, wrapperDir(top), 0o755)
			mkdirMode(t, filepath.Join(top, "usr", "local"), 0o775)
			return wrapperDir(top)
		}},
		{name: "world-writable top", want: "not group/world-writable", build: func(t *testing.T, top string) string {
			mkdirMode(t, filepath.Dir(wrapperDir(top)), 0o755)
			mkdirMode(t, top, 0o757)
			return wrapperDir(top)
		}},
		{name: "a '..' component", want: "'..' component", build: func(t *testing.T, top string) string {
			mkdirMode(t, filepath.Dir(wrapperDir(top)), 0o755)
			return filepath.Join(top, "usr", "local") + "/../local/libexec/culvert-maint"
		}},
	}
}

// astraLayout builds ASTRA's R1 case under top: usr/local/libexec is a symlink
// to srv/delegated/libexec, srv/delegated is world-writable (not sticky), and
// libexec and libexec/culvert-maint are 0755.
func astraLayout(t *testing.T, top string) {
	t.Helper()
	mkdirMode(t, filepath.Join(top, "usr", "local"), 0o755)
	mkdirMode(t, filepath.Join(top, "srv", "delegated", "libexec", "culvert-maint"), 0o755)
	mkdirMode(t, filepath.Join(top, "srv", "delegated", "libexec"), 0o755)
	mkdirMode(t, filepath.Join(top, "srv", "delegated"), 0o777)
	symlinkTest(t, filepath.Join(top, "srv", "delegated", "libexec"), filepath.Join(top, "usr", "local", "libexec"))
}

func TestCulvertMaintInstall_WrapperAncestryIsCheckedFromRootWithoutSymlinks(t *testing.T) {
	install := readRepoFile(t, maintInstallScript)
	if strings.Contains(install, "find -H") {
		t.Errorf("%s must not follow symlinks when checking the wrapper's directories (find -H)", maintInstallScript)
	}
	chain := `check_root_dir_chain "$WRAPPER_DIR" 0` + "\n"
	mkdir := `install -d -m 0755 -o root -g root "$WRAPPER_DIR"` + "\n"
	destLink := `if [ -L "$WRAPPER_DEST" ]; then die`
	wrapper := `install -m 0755 -o root -g root "$RENDERED_WRAPPER" "$WRAPPER_DEST"` + "\n"
	first, last := strings.Index(install, chain), strings.LastIndex(install, chain)
	iMkdir, iLink, iWrapper := strings.Index(install, mkdir), strings.Index(install, destLink), strings.Index(install, wrapper)
	if strings.Count(install, chain) != 2 || first < 0 || iMkdir < 0 || iLink < 0 || iWrapper < 0 ||
		first >= iMkdir || iMkdir >= last || last >= iLink || iLink >= iWrapper {
		t.Errorf("install.sh must run: check chain (UID 0, from /) → create the wrapper directory → check chain again → refuse a symlinked wrapper → install the wrapper; got offsets %d %d %d %d %d (chain calls: %d)",
			first, iMkdir, last, iLink, iWrapper, strings.Count(install, chain))
	}
}

func TestCulvertMaintInstall_WrapperAncestryRefusesUnsafeLayouts(t *testing.T) {
	uid := os.Getuid()
	for _, sh := range []string{"dash", "bash"} {
		if _, err := exec.LookPath(sh); err != nil {
			t.Logf("%s not available; skipped", sh)
			continue
		}
		for _, c := range ancestryLayouts() {
			t.Run(sh+"/"+c.name, func(t *testing.T) {
				top := filepath.Join(t.TempDir(), "root")
				mkdirMode(t, top, 0o755)
				dir := c.build(t, top)
				ok, out := runChain(t, sh, dir, uid, top)
				if ok != c.accept || (!c.accept && !strings.Contains(out, c.want)) {
					t.Fatalf("accepted=%v (want %v); output must contain %q:\n%s", ok, c.accept, c.want, out)
				}
			})
		}
		t.Run(sh+"/a different owner is refused", func(t *testing.T) {
			top := filepath.Join(t.TempDir(), "root")
			mkdirMode(t, filepath.Join(top, "usr", "local", "libexec"), 0o755)
			if ok, out := runChain(t, sh, filepath.Join(top, "usr", "local", "libexec", "culvert-maint"), uid+1, top); ok || !strings.Contains(out, "owned by uid") {
				t.Fatalf("a chain owned by uid %d must be refused for uid %d:\n%s", uid, uid+1, out)
			}
		})
	}
}

// The ported check (find -H on three lexical directories) accepts ASTRA's
// layout: the regression this test file exists for.
func TestCulvertMaintInstall_WrapperAncestryOldCheckAcceptedTheSymlinkLayout(t *testing.T) {
	top := filepath.Join(t.TempDir(), "root")
	mkdirMode(t, top, 0o755)
	astraLayout(t, top)
	old := `for _d in "$1/usr/local" "$1/usr/local/libexec" "$1/usr/local/libexec/culvert-maint"; do
  [ -n "$(find -H "$_d" -maxdepth 0 -type d -user "$(id -u)" ! -perm /022)" ] || { echo "OLD-REFUSED $_d"; exit 1; }
done; echo OLD-ACCEPTED`
	out, err := exec.CommandContext(t.Context(), "sh", "-c", old, "old", top).CombinedOutput() // #nosec G204 -- fixed test script, test-owned path
	if err != nil || !strings.Contains(string(out), "OLD-ACCEPTED") {
		t.Fatalf("control: the old lexical find -H check was expected to accept the symlink layout:\n%s (%v)", out, err)
	}
	if ok, msg := runChain(t, "sh", filepath.Join(top, "usr", "local", "libexec", "culvert-maint"), os.Getuid(), top); ok {
		t.Fatalf("check_root_dir_chain accepted the layout the old check accepted:\n%s", msg)
	}
}
