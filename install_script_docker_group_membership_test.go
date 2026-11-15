package main

// install_script_docker_group_membership_test.go — user_in_docker_group in
// scripts/install.sh must recognise membership of the group named exactly
// "docker", and nothing else.
//
// The installer decides whether to `usermod -aG docker` the invoking user, and
// whether to print the closing "log out and back in to use docker without
// sudo" note, from this check. It used to be `groups "$u" | grep -qw docker`.
// `grep -w` treats `-` and `.` as word boundaries, and `groups USER` prints the
// USERNAME itself ahead of the group list, so a user named `docker-ops`, or a
// user in an unrelated group such as `docker-users` or `svc.docker`, read as
// already in the docker group. The installer then skipped `usermod` and
// suppressed the note, and every non-sudo `docker compose ...` command the
// closing banner tells the operator to run fails with "permission denied on
// /var/run/docker.sock".

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// runUserInDockerGroup runs the REAL user_in_docker_group from
// scripts/install.sh for user, with `groups` and `id` shimmed on PATH so the
// result depends only on the fixture group list (never on the CI host).
func runUserInDockerGroup(t *testing.T, user, groupList string) bool {
	t.Helper()
	fn := extractShellFunction(t, "scripts/install.sh", "user_in_docker_group")
	bin := t.TempDir()
	// `groups USER` prints "USER : g1 g2 ..."; `id -nG USER` prints "g1 g2 ...".
	shims := map[string]string{
		"groups": "#!/bin/sh\nprintf '%s : %s\\n' \"$1\" \"$FIXTURE_GROUPS\"\n",
		"id":     "#!/bin/sh\n[ \"$1\" = -nG ] || exit 2\nprintf '%s\\n' \"$FIXTURE_GROUPS\"\n",
	}
	for name, body := range shims {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(body), 0o700); err != nil { //nolint:gosec // test-owned shim
			t.Fatal(err)
		}
	}
	harness := "set -euo pipefail\n" + fn + "\nif user_in_docker_group \"$FIXTURE_USER\"; then echo yes; else echo no; fi\n"
	cmd := exec.CommandContext(t.Context(), "bash", "-c", harness) //nolint:gosec // fixed harness built from repo script
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"FIXTURE_USER="+user,
		"FIXTURE_GROUPS="+groupList,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("user_in_docker_group harness: %v: %s", err, out)
	}
	switch string(out) {
	case "yes\n":
		return true
	case "no\n":
		return false
	}
	t.Fatalf("unexpected harness output %q", out)
	return false
}

func TestInstallScript_UserInDockerGroup_ExactGroupNameOnly(t *testing.T) {
	cases := []struct {
		name, user, groups string
		want               bool
	}{
		{"member", "alice", "alice sudo docker", true},
		{"member first", "alice", "docker alice", true},
		{"not a member", "alice", "alice sudo", false},
		{"hyphenated lookalike group", "alice", "alice sudo docker-users", false},
		{"dotted lookalike group", "alice", "alice svc.docker", false},
		{"username contains docker", "docker-ops", "docker-ops sudo", false},
		{"username is docker, not in group", "docker", "users", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runUserInDockerGroup(t, tc.user, tc.groups); got != tc.want {
				t.Fatalf("user_in_docker_group(%q) with groups %q = %v, want %v", tc.user, tc.groups, got, tc.want)
			}
		})
	}
}
