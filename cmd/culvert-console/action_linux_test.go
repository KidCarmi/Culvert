//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCommandAdapterRejectsModifiedArguments(t *testing.T) {
	for _, args := range [][]string{nil, {"/bin/bash", "-c", "anything"}, {"/bin/login", "root"}, {"/usr/bin/sudo", "--", "/usr/bin/systemctl", "restart", "culvert-firstboot.service"}} {
		if commandName(args) != "" || execute(context.Background(), args) == nil {
			t.Fatal("unexpected command accepted")
		}
	}
	if commandName([]string{"/bin/bash", "--noprofile", "--norc"}) != "recovery_shell" {
		t.Fatal("missing shell action")
	}
	// The recovery-secret reveal is allowlisted ONLY with sudo -k (a fresh
	// password prompt); the same verb without -k is refused.
	secrets := []string{"/usr/bin/sudo", "-k", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=recovery-secrets"}
	if commandName(secrets) != "recovery_secrets" {
		t.Fatal("missing recovery_secrets action")
	}
	if commandName([]string{"/usr/bin/sudo", "--", "/opt/culvert-appliance/bin/culvert-console", "--host=recovery-secrets"}) != "" {
		t.Fatal("recovery secrets allowlisted without a fresh sudo authentication")
	}
}

func TestActionEnvironmentExcludesParentSecrets(t *testing.T) {
	t.Setenv("PRIVATE_CREDENTIAL", "NEVER_COPY")
	t.Setenv("TERM", "vt100")
	env := strings.Join(actionEnvironment(), "\n")
	if strings.Contains(env, "NEVER_COPY") || !strings.Contains(env, "TERM=vt100") {
		t.Fatal(env)
	}
	t.Setenv("TERM", "xterm\nTERM=xterm")
	if !strings.Contains(strings.Join(actionEnvironment(), "\n"), "TERM=dumb") {
		t.Fatal("unsafe terminal inherited")
	}
}

func TestActionProcess(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if mode != "action-return" && mode != "action-wait" && mode != "action-ignore" && mode != "action-foreground" {
		return
	}
	term, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	term.Lflag &^= unix.ECHO | unix.ICANON
	if err := unix.IoctlSetTermios(0, unix.TCSETS, term); err != nil {
		t.Fatal(err)
	}
	if mode == "action-ignore" {
		signal.Ignore(syscall.SIGTERM)
	}
	if mode == "action-foreground" {
		// What an interactive bash (the recovery shell) does: its own process
		// group, the terminal foreground, and SIGTERM ignored. It hands the
		// foreground back only on a normal exit, never when it is SIGKILLed.
		signal.Ignore(syscall.SIGTERM, syscall.SIGTTOU)
		if err := unix.Setpgid(0, 0); err != nil {
			t.Fatal(err)
		}
		if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, unix.Getpgrp()); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(os.Stdout, "CHILD OWNS FOREGROUND")
	}
	fmt.Fprintln(os.Stdout, "CHILD CHANGED TERMINAL")
	if mode != "action-return" {
		time.Sleep(30 * time.Second)
	}
}

func terminalActionFixture(ctx context.Context, mode string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return "child-return", interactiveCommand(ctx, []string{exe, "-test.run=^TestActionProcess$", "--", mode})
}

func TestRealPTYChildRestoresTerminal(t *testing.T) {
	for _, mode := range []string{"action-return", "action-wait", "action-ignore"} {
		s := startTerminalMode(t, 25, 80, "linux", mode)
		if mode != "action-return" {
			s.await(t, "CHILD CHANGED TERMINAL")
			if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatal(err)
			}
			s.await(t, "RESTORED CANCELLED")
		} else {
			s.await(t, "RESTORED ACTION:child-return")
		}
		if err := s.cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
}

// TestRealPTYCancelledForegroundChildDoesNotStopConsole is the Q7 regression
// (ESXi, 30 Oct 2026: a 90.1 s session-stop wait on a maintenance reboot). The
// console runs as the session leader of a PTY it controls, like the tty1
// session. Its child takes the terminal foreground and ignores SIGTERM, like
// the recovery shell. On SIGTERM the console cancels, the child is SIGKILLed
// after WaitDelay without handing the foreground back, and the console must
// still restore the terminal and exit. Before the fix its TCSETS ran from the
// background, SIGTTOU stopped the whole process (state T), and nothing in it,
// including the shutdown watchdog, could run again.
func TestRealPTYCancelledForegroundChildDoesNotStopConsole(t *testing.T) {
	s := startControllingTerminal(t, "action-foreground")
	s.await(t, "CONSOLE PID ")
	s.await(t, "CHILD OWNS FOREGROUND")
	pid := consolePID(t, s.seen)
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	// WaitDelay (2 s) kills the child; allow that plus a margin, but never the
	// 90 s a stopped console costs systemd.
	deadline := time.Now().Add(8 * time.Second)
	for !strings.Contains(s.pending, "RESTORED CANCELLED") {
		if state := processState(pid); state == "T" || state == "t" {
			t.Fatalf("console stopped by job control (state %s) after its foreground child was killed: %q", state, s.pending)
		}
		if time.Now().After(deadline) {
			t.Fatalf("console did not restore and exit within 8s (state %s): %q", processState(pid), s.pending)
		}
		select {
		case chunk, ok := <-s.chunks:
			if !ok {
				t.Fatalf("PTY closed before restore: %q", s.pending)
			}
			s.pending += chunk
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := s.cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

// processState returns the one-letter state from /proc/<pid>/stat.
func processState(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "?"
	}
	i := strings.LastIndexByte(string(b), ')')
	if i < 0 || i+2 >= len(b) {
		return "?"
	}
	return string(b[i+2])
}

// consolePID parses the guardian's "CONSOLE PID <n>" line.
func consolePID(t *testing.T, out string) int {
	t.Helper()
	i := strings.Index(out, "CONSOLE PID ")
	if i < 0 {
		t.Fatalf("no console pid in %q", out)
	}
	f := strings.Fields(out[i+len("CONSOLE PID "):])
	if len(f) == 0 {
		t.Fatalf("no console pid in %q", out)
	}
	pid, err := strconv.Atoi(f[0])
	if err != nil || pid <= 1 {
		t.Fatalf("bad console pid in %q", out)
	}
	return pid
}

// TestRealPTYJobControlNormalActionRestores is the control for the regression
// above: in the same job-control topology an action that returns normally is
// still restored and reported, so the fix did not trade the shutdown stop for
// a broken everyday path.
func TestRealPTYJobControlNormalActionRestores(t *testing.T) {
	s := startControllingTerminal(t, "action-return")
	s.await(t, "RESTORED ACTION:child-return")
	if err := s.cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

// TestRestoreTerminalRestoresThreadSignalMask pins the other half of the
// containment: the SIGTTOU block is per-thread and undone before return, on
// success and on failure alike (here fd 0 is not a terminal, so every ioctl
// fails and the error path is the one exercised).
func TestRestoreTerminalRestoresThreadSignalMask(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var before, after unix.Sigset_t
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, nil, &before); err != nil {
		t.Fatal(err)
	}
	_ = restoreTerminal(&unix.Termios{})
	if err := unix.PthreadSigmask(unix.SIG_BLOCK, nil, &after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("thread signal mask changed by restoreTerminal: %#x -> %#x", before.Val[0], after.Val[0])
	}
}
