// Package applianceaccess owns the routine SSH command policy. It has no shell,
// credential reader, privileged operation, socket client or mutable global state.
package applianceaccess

import "errors"

const Binary = "/opt/culvert-appliance/bin/culvert-access"
const ForcedCommand = Binary + " --ssh"
const Version = "culvert-access 1"

// Command identifies a fixed operation; no caller text becomes executable argv.
type Command uint8

const (
	Invalid Command = iota
	Help
	Status
	StatusJSON
	Diagnostics
	Interactive
	Exit
)

const HelpText = `Culvert routine SSH access (read-only)
Commands: help | status | status-json | diagnostics | exit
No shell, file transfer, forwarding, setup secrets or privileged operations.
Administrative recovery: use the VM console and the local culvert account.
`

// Select accepts only sshd's exact forced invocation. A bare login, -c with
// another command, subsystem request, or arbitrary option never becomes a shell.
func Select(args []string, original string, terminal bool) (Command, error) {
	forced := len(args) == 2 && args[0] == "-c" && args[1] == ForcedCommand
	direct := len(args) == 1 && args[0] == "--ssh"
	if !forced && !direct {
		return Invalid, errors.New("restricted SSH invocation required")
	}
	if original == "" {
		if terminal {
			return Interactive, nil
		}
		return Help, nil
	}
	return Parse(original)
}

// Parse deliberately does not tokenize, trim, expand or evaluate shell input.
func Parse(raw string) (Command, error) {
	switch raw {
	case "help":
		return Help, nil
	case "status":
		return Status, nil
	case "status-json":
		return StatusJSON, nil
	case "diagnostics":
		return Diagnostics, nil
	case "exit":
		return Exit, nil
	default:
		return Invalid, errors.New("unsupported command; type help")
	}
}

// Argv returns fresh, fixed read-only argv. Even a forged Command value cannot
// select the console's --admin, --login or privileged --host entry points.
func (c Command) Argv() ([]string, bool) {
	const console = "/opt/culvert-appliance/bin/culvert-console"
	switch c {
	case Status:
		return []string{console, "--text"}, true
	case StatusJSON:
		return []string{console, "--json"}, true
	case Diagnostics:
		return []string{console, "--report"}, true
	default:
		return nil, false
	}
}

// Identity comes from effective OS credentials and NSS, never USER/HOME or SSH
// metadata. The dedicated operator is permitted only its own primary group.
type Identity struct {
	UID, EUID, GID, EGID int
	Username, Groupname  string
	Groups               []int
}

func (i Identity) Allowed() bool {
	if i.UID <= 0 || i.UID != i.EUID || i.GID <= 0 || i.GID != i.EGID || i.Username != "culvert-operator" || i.Groupname != "culvert-operator" {
		return false
	}
	for _, group := range i.Groups {
		if group != i.GID {
			return false
		}
	}
	return true
}

// Environment does not inherit PATH, LD_PRELOAD, BASH_ENV, SSH_AUTH_SOCK, TERM,
// proxy settings, locale hooks or a user's configuration directories.
func Environment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/", "LC_ALL=C", "TERM=dumb", "SYSTEMD_PAGER=", "SYSTEMD_COLORS=0"}
}
