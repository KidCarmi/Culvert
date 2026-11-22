package main

// install_runner_docker_group_membership_test.go — scripts/install-runner.sh
// must decide docker-group membership from the group named exactly "docker".
//
// The runner installer adds the invoking user to the docker group (section 2:
// "the most common cause of CI failures on self-hosted runners") and, in its
// closing banner, tells the operator to re-login when that membership is not
// active yet. Both decisions were `groups "$u" | grep -qw docker`. `grep -w`
// treats `-` and `.` as word boundaries and `groups USER` prints the USERNAME
// itself ahead of the group list, so a runner account named `docker-ops`, or
// one in an unrelated group such as `docker-users` or `svc.docker`, read as
// already in the docker group. The script then skipped `usermod -aG docker`,
// installed the runner service as that user, and printed a clean success
// banner — while every job on the runner fails with "permission denied while
// trying to connect to the Docker daemon socket".
//
// scripts/install.sh had the identical check and was fixed
// (install_script_docker_group_membership_test.go); this pins the twin.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runnerScriptSlice returns scripts/install-runner.sh from the banner line
// that precedes startMarker up to the banner line that precedes endMarker
// ("" = end of file).
func runnerScriptSlice(t *testing.T, startMarker, endMarker string) string {
	t.Helper()
	b, err := os.ReadFile("scripts/install-runner.sh")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	bannerStart := func(marker string) int {
		i := strings.Index(src, marker)
		if i < 0 {
			t.Fatalf("marker %q not found in install-runner.sh", marker)
		}
		// Back up over the `####` banner line that precedes the marker line.
		return strings.LastIndex(strings.TrimRight(src[:i], "\n"), "\n") + 1
	}
	start := 0
	if startMarker != "" {
		start = bannerStart(startMarker)
	}
	end := len(src)
	if endMarker != "" {
		end = bannerStart(endMarker)
	}
	return src[start:end]
}

// runRunnerScriptSection runs the script's real config+helpers head followed
// by the real section, with `groups`, `id`, `sudo` and `docker` shimmed on
// PATH so the result depends only on the fixture user and group list. The
// sudo shim records its argv to the returned log instead of running anything.
func runRunnerScriptSection(t *testing.T, section, user, groupList string) (stdout, sudoLog string) {
	t.Helper()
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "sudo.log")
	shims := map[string]string{
		// `groups USER` prints "USER : g1 g2 ..."; `id -nG USER` prints "g1 g2 ...".
		"groups": "#!/bin/sh\nprintf '%s : %s\\n' \"$1\" \"$FIXTURE_GROUPS\"\n",
		"id": "#!/bin/sh\ncase \"$1\" in\n" +
			"-un) printf '%s\\n' \"$FIXTURE_USER\" ;;\n" +
			"-nG) printf '%s\\n' \"$FIXTURE_GROUPS\" ;;\n" +
			"*) exit 2 ;;\nesac\n",
		"sudo":   "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$SUDO_LOG\"\n",
		"docker": "#!/bin/sh\nexit 0\n", // daemon reachable: isolates the group check
	}
	for name, body := range shims {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // test-owned shim
			t.Fatal(err)
		}
	}
	head := runnerScriptSlice(t, "", "# 0. Validate runner token")
	// Values the closing banner prints; section 2 assigns CURRENT_USER itself.
	prelude := "CURRENT_USER=\"$FIXTURE_USER\"\nREPO_URL=https://example.invalid/o/r\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", head+prelude+section) //nolint:gosec // harness built from the repo script
	cmd.Env = []string{
		"PATH=" + bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + t.TempDir(),
		"RUNNER_NAME=test-runner",
		"FIXTURE_USER=" + user,
		"FIXTURE_GROUPS=" + groupList,
		"SUDO_LOG=" + logPath,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install-runner.sh section failed: %v\n%s", err, out)
	}
	logged, _ := os.ReadFile(logPath) // absent = sudo never ran
	return string(out), string(logged)
}

var runnerDockerGroupCases = []struct {
	name, user, groups string
	member             bool
}{
	{"member", "alice", "alice sudo docker", true},
	{"member first", "alice", "docker alice", true},
	{"not a member", "alice", "alice sudo", false},
	{"hyphenated lookalike group", "alice", "alice sudo docker-users", false},
	{"dotted lookalike group", "alice", "alice svc.docker", false},
	{"username contains docker", "docker-ops", "docker-ops sudo", false},
	{"username is docker, not in group", "docker", "users", false},
}

func TestInstallRunner_AddsUserToDockerGroup_ExactGroupNameOnly(t *testing.T) {
	section := runnerScriptSlice(t, "# 2. Add current user to the docker group", "# 3. Download the GitHub Actions runner")
	for _, tc := range runnerDockerGroupCases {
		t.Run(tc.name, func(t *testing.T) {
			out, sudoLog := runRunnerScriptSection(t, section, tc.user, tc.groups)
			added := strings.Contains(sudoLog, "usermod -aG docker "+tc.user)
			if added == tc.member {
				t.Errorf("user %q groups %q: usermod -aG docker ran = %v, want %v\nsudo log: %q\noutput:\n%s",
					tc.user, tc.groups, added, !tc.member, sudoLog, out)
			}
		})
	}
}

func TestInstallRunner_ClosingBanner_ReloginNote_ExactGroupNameOnly(t *testing.T) {
	section := runnerScriptSlice(t, "# Done", "")
	for _, tc := range runnerDockerGroupCases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := runRunnerScriptSection(t, section, tc.user, tc.groups)
			noted := strings.Contains(out, "ACTION REQUIRED")
			if noted == tc.member {
				t.Errorf("user %q groups %q: re-login note printed = %v, want %v\noutput:\n%s",
					tc.user, tc.groups, noted, !tc.member, out)
			}
		})
	}
}
