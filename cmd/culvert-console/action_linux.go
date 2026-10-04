//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errTerminalState = errors.New("terminal state unavailable; reconnect or use SSH")

func commandName(args []string) string {
	commands := []struct {
		name string
		args []string
	}{
		{"pam_login", []string{"/bin/login", "culvert"}},
		{"network_show", []string{"/opt/culvert-appliance/bin/culvert-net", "show"}},
		{"setup_access", []string{"/usr/bin/sudo", "--", "/opt/culvert-appliance/bin/culvert-status"}},
		{"retry_reset", []string{"/usr/bin/sudo", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=retry-reset"}},
		{"retry_start", []string{"/usr/bin/sudo", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=retry-start"}},
		{"reboot", []string{"/usr/bin/sudo", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=reboot"}},
		{"poweroff", []string{"/usr/bin/sudo", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=poweroff"}},
		{"network_change", []string{"/usr/bin/sudo", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=network"}},
		{"recovery_shell", []string{"/bin/bash", "--noprofile", "--norc"}},
	}
	for _, command := range commands {
		if slices.Equal(command.args, args) {
			return command.name
		}
	}
	return ""
}

func execute(ctx context.Context, args []string) error {
	name := commandName(args)
	if name == "" {
		return errors.New("console command is not allowlisted")
	}
	return auditCommand(ctx, name, func() error { return interactiveCommand(ctx, args) }, journalRecord, os.Stderr)
}

func interactiveCommand(ctx context.Context, args []string) (result error) {
	original, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		return errors.Join(errTerminalState, err)
	}
	defer func() {
		// Child programs may leave echo/canonical mode changed even on success.
		restoreErr := errors.Join(unix.IoctlSetTermios(0, unix.TCSETS, original), unix.IoctlSetInt(0, unix.TCFLSH, unix.TCIFLUSH))
		if restoreErr != nil {
			result = errors.Join(result, errTerminalState, restoreErr)
		}
	}()
	// #nosec G204 -- execute accepts only exact fixed argv from commandName.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = actionEnvironment()
	// Give PAM/sudo a chance to close their session before forced termination.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run console action: %w", err)
	}
	return nil
}

func actionEnvironment() []string {
	env := probeEnvironment()
	term := os.Getenv("TERM")
	if ansi, _ := terminalCapabilities(); !ansi {
		term = "dumb"
	}
	env = append(env, "TERM="+term)
	if u, err := user.LookupId(strconv.Itoa(os.Geteuid())); err == nil {
		env = append(env, "HOME="+u.HomeDir)
	}
	return env
}
