//go:build linux

// culvert-access is the dedicated routine operator's login shell, not a shell
// interpreter. Root provisioning must install the matching account/sshd policy.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceaccess"
)

func main() { os.Exit(run()) }

func run() int {
	// Packaging smoke only: no identity lookup, probe, filesystem or child call.
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		if _, err := fmt.Fprintln(os.Stdout, applianceaccess.Version); err != nil {
			return 1
		}
		return 0
	}
	if len(os.Args) == 2 && os.Args[1] == "--import-keys" {
		if err := importKeys(context.Background()); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "Operator key provisioning failed; inspect account and import configuration locally.")
			return 1
		}
		return 0
	}
	if !operatorIdentity() {
		_, _ = fmt.Fprintln(os.Stderr, "Routine SSH requires the unprivileged culvert-operator account with its own group only.")
		return 1
	}
	command, err := applianceaccess.Select(os.Args[1:], os.Getenv("SSH_ORIGINAL_COMMAND"), sameTerminal())
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	if command == applianceaccess.Interactive {
		return prompt(ctx)
	}
	if err := dispatch(ctx, command, os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "Culvert observation unavailable; use the local VM console for recovery.")
		return 1
	}
	return 0
}

func operatorIdentity() bool {
	u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		return false
	}
	g, err := user.LookupGroupId(strconv.Itoa(os.Getegid()))
	if err != nil || u.Gid != g.Gid {
		return false
	}
	groups, err := os.Getgroups()
	if err != nil {
		return false
	}
	return (applianceaccess.Identity{UID: os.Getuid(), EUID: os.Geteuid(), GID: os.Getgid(), EGID: os.Getegid(), Username: u.Username, Groupname: g.Name, Groups: groups}).Allowed()
}

func prompt(ctx context.Context) int {
	if _, err := fmt.Fprint(os.Stdout, applianceaccess.HelpText); err != nil {
		return 1
	}
	for count := 0; count < 256; count++ {
		if _, err := fmt.Fprint(os.Stdout, "culvert> "); err != nil {
			return 1
		}
		line, err := terminalLine(ctx, 0)
		if err != nil {
			return 1
		}
		command, err := applianceaccess.Parse(line)
		if err != nil {
			if _, err := fmt.Fprintln(os.Stdout, "Unsupported command; type help."); err != nil {
				return 1
			}
			continue
		}
		if command == applianceaccess.Exit {
			return 0
		}
		if err := dispatch(ctx, command, os.Stdout); err != nil {
			if _, err := fmt.Fprintln(os.Stdout, "Culvert observation unavailable; use the local VM console for recovery."); err != nil {
				return 1
			}
		}
	}
	return 0
}
