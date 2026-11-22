package main

// install_script_amzn_rerun_keeps_docker_test.go — re-running
// scripts/install.sh on an Amazon Linux host must not uninstall the Docker
// Engine a previous run installed.
//
// On Amazon Linux the installer's own install step is `yum install -y docker`
// — the distro package IS the engine Culvert runs on there (there is no
// Docker CE repo for amzn). The "Cleaning up old Docker installations" step
// nevertheless ran `rpm -q docker && yum remove -y docker` on that family, so
// every re-run (a supported path — "Culvert deployment already exists at …")
// removed the working engine out from under the running stack and left the
// install step to put it back, which additionally needs a fresh
// api.github.com lookup for the Compose plugin; when that lookup fails the
// run aborts under `set -e` with the engine it just removed still stopped.
//
// Same class as install_script_rhel_rerun_keeps_docker_ce_test.go. The
// fixture is not hand-written: the "installed" package set is whatever the
// script's OWN amzn install arm asks yum for, so the test keeps holding if
// that arm ever changes what it installs.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// amznYumShim emulates `yum install|remove -y PKG...` over the
// newline-separated package list in $RPM_DB and logs every invocation.
const amznYumShim = `#!/bin/bash
echo "yum $*" >>"$YUM_LOG"
op="${1:-}"; shift || true
[[ "${1:-}" == "-y" ]] && shift
case "$op" in
  install)
    for p in "$@"; do grep -qxF -- "$p" "$RPM_DB" || echo "$p" >>"$RPM_DB"; done ;;
  remove)
    for p in "$@"; do
      grep -vxF -- "$p" "$RPM_DB" >"$RPM_DB.tmp" || true
      mv "$RPM_DB.tmp" "$RPM_DB"
    done ;;
  *) echo "unexpected yum invocation: $op $*" >&2; exit 1 ;;
esac
exit 0
`

// amznCurlShim answers the install arm's Compose release lookup.
const amznCurlShim = `#!/bin/bash
echo '  "tag_name": "v2.40.0",'
`

func TestInstallScript_AmznCleanup_KeepsInstallerDockerOnRerun(t *testing.T) {
	// The whole cleanup `case "$DISTRO_FAMILY"` (first occurrence in the
	// script), and the install step's amzn arm.
	cleanup := extractShellLines(t, "scripts/install.sh", `case "$DISTRO_FAMILY" in`, `info "Cleanup complete"`)
	install := extractShellLines(t, "scripts/install.sh", `info "Installing Docker on Amazon Linux..."`, "    arch)")

	// sudo passes the package manager through to the shims and swallows the
	// rest (mkdir/curl/chmod under /usr/local), so the host is never touched.
	harness := "set -euo pipefail\n" +
		"info() { :; }\nwarn() { :; }\nwait_for_apt_lock() { :; }\n" +
		"sudo() { case \"$1\" in yum|dnf|rpm) \"$@\" ;; *) : ;; esac; }\n" +
		"DISTRO_FAMILY=amzn\n" +
		"cleanup_step() {\n" + cleanup + "\n}\n" +
		"install_step() {\ncase amzn in\n  amzn)\n" + install + "\nesac\n}\n" +
		"cleanup_step\ninstall_step\n" + // first run on a fresh host
		"cp \"$RPM_DB\" \"$RPM_DB.after-first-run\"\n" +
		"cleanup_step\n" + // re-run: only the cleanup step
		"echo FRAGMENT_OK\n"

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{"rpm": rhelRpmShim, "yum": amznYumShim, "curl": amznCurlShim} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(src), 0o700); err != nil { //nolint:gosec // test-owned shim
			t.Fatal(err)
		}
	}
	db := filepath.Join(dir, "rpmdb")
	if err := os.WriteFile(db, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(dir, "yum.log")
	cmd := exec.CommandContext(t.Context(), "bash", "-c", harness) //nolint:gosec // fixed harness built from repo script
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"RPM_DB="+db,
		"YUM_LOG="+logFile,
	)
	out, err := cmd.CombinedOutput()
	rawCalls, _ := os.ReadFile(logFile) //nolint:gosec // test-owned path
	calls := string(rawCalls)
	if err != nil || !strings.Contains(string(out), "FRAGMENT_OK") {
		t.Fatalf("harness aborted: %v\noutput:\n%s\nyum calls:\n%s", err, out, calls)
	}

	readPkgs := func(path string) []string {
		raw, rerr := os.ReadFile(path) //nolint:gosec // test-owned path
		if rerr != nil {
			t.Fatal(rerr)
		}
		return strings.Fields(string(raw))
	}
	firstRun := readPkgs(db + ".after-first-run")
	if len(firstRun) == 0 {
		t.Fatalf("fixture: the amzn install arm installed nothing through yum\nyum calls:\n%s", calls)
	}
	left := map[string]bool{}
	for _, p := range readPkgs(db) {
		left[p] = true
	}
	for _, p := range firstRun {
		if !left[p] {
			t.Errorf("re-run cleanup uninstalled %q, which the installer's own amzn install step installed; "+
				"installed after the first run: %v, after the re-run cleanup: %v\nyum calls:\n%s",
				p, firstRun, readPkgs(db), calls)
		}
	}
}
