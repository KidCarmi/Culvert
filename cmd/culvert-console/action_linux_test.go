//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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
	if mode != "action-return" && mode != "action-wait" && mode != "action-ignore" {
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
