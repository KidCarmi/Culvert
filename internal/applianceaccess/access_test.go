package applianceaccess

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestExactCommandsCannotBecomeShellOrPrivilegedActions(t *testing.T) {
	for _, raw := range []string{"help", "status", "status-json", "diagnostics", "exit"} {
		if _, err := Parse(raw); err != nil {
			t.Errorf("valid command %q refused", raw)
		}
	}
	for _, raw := range []string{"", " status", "status ", "status\n", "status\x00", "status;id", "status && id", "$(id)", "`id`", "${SHELL}", "env", "bash", "sh -c id", "sudo -n id", "recover", "reboot", "poweroff", "--host=worker", "--admin", "status --json", "status > /root/x", "status | sh", "../status", "scp -t /tmp/x", "internal-sftp", "/usr/lib/openssh/sftp-server", "sftp", "ssh -L /tmp/a:/run/docker.sock host", strings.Repeat("A", 100000)} {
		if command, err := Parse(raw); err == nil || command != Invalid {
			t.Errorf("untrusted command accepted: %q", raw[:min(len(raw), 80)])
		}
	}
	for command := Command(0); command < 255; command++ {
		argv, ok := command.Argv()
		if !ok {
			continue
		}
		if len(argv) != 2 || argv[0] != "/opt/culvert-appliance/bin/culvert-console" || !slices.Contains([]string{"--text", "--json", "--report"}, argv[1]) {
			t.Fatalf("command %d exposes non-public argv", command)
		}
		argv[0] = "/bin/bash"
		next, _ := command.Argv()
		if next[0] == "/bin/bash" {
			t.Fatal("caller changed future fixed argv")
		}
	}
}

func TestForcedInvocationPTYAndNoPTY(t *testing.T) {
	for _, tty := range []bool{false, true} {
		for _, args := range [][]string{{"-c", ForcedCommand}, {"--ssh"}} {
			got, err := Select(args, "status", tty)
			if err != nil || got != Status {
				t.Fatal("fixed SSH invocation refused")
			}
			got, err = Select(args, "", tty)
			want := Help
			if tty {
				want = Interactive
			}
			if err != nil || got != want {
				t.Fatal("PTY selection incorrect")
			}
		}
		for _, args := range [][]string{nil, {"-l"}, {"-c", "status"}, {"-c", ForcedCommand + "; /bin/sh"}, {"-c", ForcedCommand, "extra"}, {"--ssh", "extra"}, {"--admin"}, {"--host=worker"}, {"--version"}} {
			if _, err := Select(args, "status", tty); err == nil {
				t.Fatalf("unexpected login shell argv admitted: %q", args)
			}
		}
	}
}

func TestOperatorIdentityHasNoRootOrPrivilegedGroupFallback(t *testing.T) {
	baseline := Identity{UID: 1200, EUID: 1200, GID: 1200, EGID: 1200, Username: "culvert-operator", Groupname: "culvert-operator", Groups: []int{1200}}
	if !baseline.Allowed() {
		t.Fatal("dedicated routine identity refused")
	}
	for _, mutate := range []func(*Identity){
		func(i *Identity) { i.UID, i.EUID = 0, 0 },
		func(i *Identity) { i.EUID = 0 },
		func(i *Identity) { i.GID, i.EGID = 0, 0 },
		func(i *Identity) { i.EGID++ },
		func(i *Identity) { i.Username = "culvert" },
		func(i *Identity) { i.Groupname = "docker" },
		func(i *Identity) { i.Groupname = "culvert-maint" },
		func(i *Identity) { i.Groups = []int{1200, 0} },
		func(i *Identity) { i.Groups = []int{1200, 27} },
		func(i *Identity) { i.Groups = []int{1200, 999} },
	} {
		i := baseline
		mutate(&i)
		if i.Allowed() {
			t.Fatal("privileged or mismatched identity admitted")
		}
	}
}

func TestChildEnvironmentDoesNotInheritInjectionOrSocketAccess(t *testing.T) {
	for _, key := range []string{"BASH_ENV", "ENV", "LD_PRELOAD", "SSH_AUTH_SOCK", "SSH_ORIGINAL_COMMAND", "PYTHONPATH", "GODEBUG", "SYSTEMD_PAGER", "PAGER", "HOME", "PATH", "TERM", "http_proxy"} {
		t.Setenv(key, "untrusted-fixture")
	}
	for _, value := range Environment() {
		if strings.Contains(value, "untrusted-fixture") {
			t.Fatal("environment inherited attacker input")
		}
	}
	if len(Environment()) != 6 || !slices.Contains(Environment(), "HOME=/") || !slices.Contains(Environment(), "SYSTEMD_PAGER=") {
		t.Fatal("child environment expanded unexpectedly")
	}
}

func TestSSHDRestrictionContract(t *testing.T) {
	data, err := os.ReadFile("../../appliance/provision/sshd-50-culvert.conf")
	if err != nil {
		t.Fatal(err)
	}
	config := strings.ReplaceAll(string(data), "\r\n", "\n")
	for _, line := range []string{"AllowUsers culvert-operator", "ForceCommand " + ForcedCommand, "DisableForwarding yes", "AllowStreamLocalForwarding no", "AllowTcpForwarding no", "AllowAgentForwarding no", "PermitUserRC no", "PermitUserEnvironment no", "PermitTunnel no", "PermitRootLogin no", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "AuthenticationMethods publickey"} {
		if !strings.Contains("\n"+config, "\n"+line+"\n") {
			t.Errorf("missing SSH boundary: %s", line)
		}
	}
}

func FuzzRestrictedCommand(f *testing.F) {
	for _, seed := range []string{"status", "help", "diagnostics", "status-json", "exit", "sudo id", "status\nsh", "internal-sftp"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		command, err := Parse(raw)
		if err == nil && !slices.Contains([]string{"status", "help", "diagnostics", "status-json", "exit"}, raw) {
			t.Fatal("nonliteral command admitted")
		}
		if err != nil && command != Invalid {
			t.Fatal("refused text returned actionable command")
		}
	})
}
