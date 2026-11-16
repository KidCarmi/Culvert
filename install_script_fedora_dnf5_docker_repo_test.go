package main

// install_script_fedora_dnf5_docker_repo_test.go — the Fedora branch of
// scripts/install.sh must register Docker's dnf repository on dnf5.
//
// Fedora 41 replaced dnf4 with dnf5, whose config-manager plugin dropped the
// `--add-repo URL` option in favour of the `addrepo --from-repofile=URL`
// subcommand. The installer ran `sudo dnf config-manager --add-repo ...`
// unconditionally, which dnf5 rejects:
//
//	Unknown argument "--add-repo" for command "config-manager".   (exit 2)
//
// and, under the script's `set -euo pipefail`, that aborted the install before
// Docker — and therefore Culvert — was ever installed, on every Fedora release
// still in support. Measured against the real dnf5 5.4.6 in the fedora:latest
// image; the shims below reproduce exactly the behaviour observed there
// (including dnf5 refusing to re-add an existing repo file without
// --overwrite, which a re-run after a partial install hits).

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fedoraDnfShim emulates the parts of `dnf` the Fedora branch touches, as
// dnf5 or dnf4 per $FIXTURE_DNF. Every invocation is appended to $DNF_LOG; a
// registered repo is recorded as the file $DNF_REPO_FILE.
const fedoraDnfShim = `#!/bin/bash
echo "dnf $*" >>"$DNF_LOG"
if [[ "$1" == "--version" ]]; then
  if [[ "$FIXTURE_DNF" == 5 ]]; then echo "dnf5 version 5.4.6.0"; else echo "4.22.0"; fi
  exit 0
fi
[[ "$1" == "install" ]] && exit 0
[[ "$1" == "config-manager" ]] || { echo "unexpected dnf invocation: $*" >&2; exit 1; }
shift
if [[ "$FIXTURE_DNF" == 5 ]]; then
  if [[ "$1" != "addrepo" ]]; then
    echo "Unknown argument \"$1\" for command \"config-manager\"." >&2
    exit 2
  fi
  shift
  overwrite=0 from=""
  for a in "$@"; do
    case "$a" in
      --overwrite) overwrite=1 ;;
      --from-repofile=*) from="${a#--from-repofile=}" ;;
      *) echo "Unknown argument \"$a\" for command \"addrepo\"." >&2; exit 2 ;;
    esac
  done
  [[ -n "$from" ]] || { echo "missing --from-repofile" >&2; exit 2; }
  if [[ -e "$DNF_REPO_FILE" && "$overwrite" != 1 ]]; then
    echo "File \"docker-ce.repo\" already exists. Add \"--overwrite\" to overwrite." >&2
    exit 1
  fi
  echo "$from" >"$DNF_REPO_FILE"
  exit 0
fi
# dnf4: only the legacy option form exists.
if [[ "$1" == "--add-repo" && -n "${2:-}" ]]; then
  echo "$2" >"$DNF_REPO_FILE"
  exit 0
fi
echo "No such command: config-manager $*" >&2
exit 1
`

func TestInstallScript_FedoraDockerRepo_WorksOnDnf5AndDnf4(t *testing.T) {
	const repoURL = "https://download.docker.com/linux/fedora/docker-ce.repo"
	// The body of the `fedora)` arm, up to (not including) the next arm.
	body := extractShellLines(t, "scripts/install.sh",
		`info "Installing from Docker's official dnf repository..."`, "    amzn)")
	harness := "set -euo pipefail\ninfo() { :; }\nsudo() { \"$@\"; }\n" +
		"case fedora in\n  fedora)\n" + body + "\nesac\necho FRAGMENT_OK\n"

	cases := []struct {
		name, dnf    string
		repoPreexist bool // a prior, partially completed run already wrote the repo file
	}{
		{"dnf5 fresh host (Fedora 41+)", "5", false},
		{"dnf5 re-run with the repo file already present", "5", true},
		{"dnf4 (legacy Fedora)", "4", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bin, "dnf"), []byte(fedoraDnfShim), 0o700); err != nil { //nolint:gosec // test-owned shim
				t.Fatal(err)
			}
			logFile := filepath.Join(dir, "dnf.log")
			repoFile := filepath.Join(dir, "docker-ce.repo")
			if tc.repoPreexist {
				if err := os.WriteFile(repoFile, []byte("stale\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.CommandContext(t.Context(), "bash", "-c", harness) //nolint:gosec // fixed harness built from repo script
			cmd.Env = append(os.Environ(),
				"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"FIXTURE_DNF="+tc.dnf,
				"DNF_LOG="+logFile,
				"DNF_REPO_FILE="+repoFile,
			)
			out, err := cmd.CombinedOutput()
			calls, _ := os.ReadFile(logFile) //nolint:gosec // test-owned path
			if err != nil || !strings.Contains(string(out), "FRAGMENT_OK") {
				t.Fatalf("Fedora Docker install aborted on dnf%s: %v\noutput:\n%s\ndnf calls:\n%s", tc.dnf, err, out, calls)
			}
			got, err := os.ReadFile(repoFile) //nolint:gosec // test-owned path
			if err != nil || strings.TrimSpace(string(got)) != repoURL {
				t.Fatalf("Docker repo not registered from %s on dnf%s (repo file: %q, err %v)\ndnf calls:\n%s",
					repoURL, tc.dnf, got, err, calls)
			}
			if !strings.Contains(string(calls), "dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin") {
				t.Fatalf("docker-ce was never installed on dnf%s; dnf calls:\n%s", tc.dnf, calls)
			}
		})
	}
}
