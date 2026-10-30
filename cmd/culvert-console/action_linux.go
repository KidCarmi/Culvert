//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var errTerminalState = errors.New("terminal state unavailable; reconnect or use SSH")

func commandName(args []string) string {
	name, _ := allowlistedCommand(args)
	return name
}

// allowlistedCommand returns the allowlist entry args matches exactly, with
// the allowlist's OWN argv: execute runs that copy, never the caller's slice.
func allowlistedCommand(args []string) (name string, argv []string) {
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
		{"recovery_secrets", []string{"/usr/bin/sudo", "-k", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=recovery-secrets"}},
	}
	for _, command := range commands {
		if slices.Equal(command.args, args) {
			return command.name, slices.Clone(command.args)
		}
	}
	return "", nil
}

func execute(ctx context.Context, args []string) error {
	name, argv := allowlistedCommand(args)
	if name == "" {
		return errors.New("console command is not allowlisted")
	}
	return auditCommand(ctx, name, func() error { return interactiveCommand(ctx, argv) }, journalRecord, os.Stderr)
}

func interactiveCommand(ctx context.Context, args []string) (result error) {
	original, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		return errors.Join(errTerminalState, err)
	}
	defer func() {
		// Child programs may leave echo/canonical mode changed even on success.
		restoreErr := restoreTerminal(original)
		if restoreErr != nil {
			result = errors.Join(result, errTerminalState, restoreErr)
		}
	}()
	// #nosec G204 G702 -- execute passes only the allowlist's own fixed argv
	// (allowlistedCommand); the only other caller is the PTY test harness.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = actionEnvironment()
	// Give PAM/sudo a chance to close their session before forced termination.
	cmd.Cancel = func() error { return cmd.Process.Signal(syscall.SIGTERM) }
	cmd.WaitDelay = 2 * time.Second
	if name := commandName(args); name == "reboot" || name == "poweroff" {
		// Let the root helper's bounded 90s cancellation recovery finish under
		// the shared maintenance locks before sudo is forcibly terminated.
		cmd.WaitDelay = 2 * time.Minute
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run console action: %w", err)
	}
	return nil
}

// restoreTerminal takes the terminal foreground back for the console's process
// group, then restores the modes the child may have changed.
//
// An interactive child (the recovery shell's bash) moves itself into its own
// process group and makes it the terminal foreground. It hands the foreground
// back when it exits normally, but not when it is killed: on cancellation
// (SIGTERM at shutdown) bash ignores SIGTERM and WaitDelay SIGKILLs it. The
// console is then a BACKGROUND process of its own terminal, and TCSETS from
// the background raises SIGTTOU, whose default action stops the whole process.
// A stopped process runs nothing, the shutdown watchdog included, so systemd
// waited out its 90 s session stop timeout on a maintenance reboot (Q7, ESXi).
//
// While SIGTTOU is blocked in the calling thread, the kernel treats it as
// ignored for these ioctls: both the foreground hand-back (TIOCSPGRP) and
// TCSETS are permitted from the background and no stop signal is generated
// (POSIX tcsetpgrp/tcsetattr; Linux tty_check_change). The mask is per-thread
// and restored before returning, so the process-wide disposition is never
// changed and no later child can inherit an ignored job-control signal.
func restoreTerminal(original *unix.Termios) (result error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var block, previous unix.Sigset_t
	block.Val[(unix.SIGTTOU-1)/64] |= 1 << ((uint(unix.SIGTTOU) - 1) % 64)
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &block, &previous); err != nil {
		return err
	}
	defer func() {
		result = errors.Join(result, unix.PthreadSigmask(unix.SIG_SETMASK, &previous, nil))
	}()
	var errs []error
	// ENOTTY: not our controlling terminal (no job control applies).
	if foreground, err := unix.IoctlGetInt(0, unix.TIOCGPGRP); err == nil && foreground != unix.Getpgrp() {
		errs = append(errs, unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, unix.Getpgrp()))
	}
	errs = append(errs, unix.IoctlSetTermios(0, unix.TCSETS, original), unix.IoctlSetInt(0, unix.TCFLSH, unix.TCIFLUSH))
	return errors.Join(errs...)
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
