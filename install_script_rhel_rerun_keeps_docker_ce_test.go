package main

// install_script_rhel_rerun_keeps_docker_ce_test.go — re-running
// scripts/install.sh on a RHEL-family or Fedora host must not uninstall the
// Docker Engine a previous run installed.
//
// The "Cleaning up old Docker installations" step removed `containerd.io`
// alongside the distro packages. containerd.io is not a distro package: it is
// Docker's own runtime, installed by this very script from
// download.docker.com, and docker-ce requires it. So on every re-run (a
// supported path — "Culvert deployment already exists at …") the step ran
// `dnf remove -y containerd.io`, and dnf removed docker-ce with it as a
// dependent package, stopping the daemon and every Culvert container.
//
// The run could not recover either. docker-ce-cli and docker-compose-plugin
// survive the removal, so the next step's `command -v docker && docker compose
// version` guard reads "Docker with Compose v2 already installed" and skips
// the install; docker.service no longer exists; and the recovery path's
// `dnf reinstall -y docker-ce docker-ce-cli containerd.io` only reinstalls
// what is still installed (docker-ce-cli). The installer ends on "Docker
// daemon could not be started after recovery attempts" with the proxy down.
//
// Measured against the real dnf 4 in rockylinux:9 with Docker CE 29.9.3 /
// containerd.io 2.4.2 from download.docker.com; the shims below reproduce the
// behaviour observed there ("Removing dependent packages: docker-ce").

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// rhelRpmShim answers `rpm -q PKG` from the newline-separated package list in
// $RPM_DB.
const rhelRpmShim = `#!/bin/bash
[[ "$1" == "-q" && -n "${2:-}" ]] || { echo "unexpected rpm invocation: $*" >&2; exit 2; }
grep -qxF -- "$2" "$RPM_DB" && { echo "$2-1.el9.x86_64"; exit 0; }
echo "package $2 is not installed"
exit 1
`

// rhelDnfRemoveShim emulates `dnf remove -y PKG` over $RPM_DB, including the
// dependent-package removal real dnf performs: docker-ce requires
// containerd.io, so removing containerd.io removes docker-ce too.
const rhelDnfRemoveShim = `#!/bin/bash
echo "dnf $*" >>"$DNF_LOG"
[[ "$1" == "remove" && "$2" == "-y" && -n "${3:-}" ]] || { echo "unexpected dnf invocation: $*" >&2; exit 1; }
drop=("$3")
[[ "$3" == "containerd.io" ]] && drop+=("docker-ce")
for p in "${drop[@]}"; do
  grep -vxF -- "$p" "$RPM_DB" >"$RPM_DB.tmp" || true
  mv "$RPM_DB.tmp" "$RPM_DB"
done
exit 0
`

// runRHELCleanupArm runs the cleanup step's `rhel|fedora)` arm from
// scripts/install.sh for the given distro family against a host with the
// given packages installed, and returns the packages still installed
// afterwards plus the dnf invocations made.
func runRHELCleanupArm(t *testing.T, family string, installed []string) (left map[string]bool, calls string) {
	t.Helper()
	// The body of the cleanup step's `rhel|fedora)` arm, up to the next arm.
	body := extractShellLines(t, "scripts/install.sh", "# Remove distro-packaged Docker/Podman", "  amzn)")
	harness := "set -euo pipefail\ninfo() { :; }\nsudo() { \"$@\"; }\n" +
		"case \"$FIXTURE_FAMILY\" in\n  rhel|fedora)\n" + body + "\nesac\necho FRAGMENT_OK\n"

	dir := t.TempDir()
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, src := range map[string]string{"rpm": rhelRpmShim, "dnf": rhelDnfRemoveShim} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(src), 0o700); err != nil { //nolint:gosec // test-owned shim
			t.Fatal(err)
		}
	}
	db := filepath.Join(dir, "rpmdb")
	if err := os.WriteFile(db, []byte(strings.Join(installed, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(dir, "dnf.log")
	cmd := exec.CommandContext(t.Context(), "bash", "-c", harness) //nolint:gosec // fixed harness built from repo script
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FIXTURE_FAMILY="+family,
		"RPM_DB="+db,
		"DNF_LOG="+logFile,
	)
	out, err := cmd.CombinedOutput()
	rawCalls, _ := os.ReadFile(logFile) //nolint:gosec // test-owned path
	calls = string(rawCalls)
	if err != nil || !strings.Contains(string(out), "FRAGMENT_OK") {
		t.Fatalf("cleanup step aborted: %v\noutput:\n%s\ndnf calls:\n%s", err, out, calls)
	}
	raw, err := os.ReadFile(db) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	left = map[string]bool{}
	for _, p := range strings.Fields(string(raw)) {
		left[p] = true
	}
	return left, calls
}

func TestInstallScript_RHELCleanup_KeepsInstallerDockerCEOnRerun(t *testing.T) {
	dockerCE := []string{"docker-ce", "docker-ce-cli", "containerd.io", "docker-compose-plugin"}
	cases := []struct {
		name, family string
		installed    []string
		wantKept     []string
		wantRemoved  []string
	}{
		{"rhel re-run with the installer's Docker CE", "rhel", dockerCE, dockerCE, nil},
		{"fedora re-run with the installer's Docker CE", "fedora", dockerCE, dockerCE, nil},
		// Control: the step still removes the conflicting distro packages.
		{"rhel fresh host with distro docker + podman-docker", "rhel",
			[]string{"docker", "podman-docker", "bash"}, []string{"bash"}, []string{"docker", "podman-docker"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			left, calls := runRHELCleanupArm(t, tc.family, tc.installed)
			for _, p := range tc.wantKept {
				if !left[p] {
					t.Errorf("cleanup uninstalled %s; installed after the step: %v\ndnf calls:\n%s", p, left, calls)
				}
			}
			for _, p := range tc.wantRemoved {
				if left[p] {
					t.Errorf("cleanup left the conflicting distro package %s installed\ndnf calls:\n%s", p, calls)
				}
			}
		})
	}
}
