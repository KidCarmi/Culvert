//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
	"golang.org/x/sys/unix"
)

func TestTerminalCapabilities(t *testing.T) {
	for _, term := range []string{"linux", "vt100", "dumb", "unknown"} {
		t.Setenv("TERM", term)
		ansi, color := terminalCapabilities()
		if term == "dumb" || term == "unknown" {
			if ansi || color {
				t.Fatal("unknown terminal received controls")
			}
		}
		if term == "vt100" && color {
			t.Fatal("vt100 received color")
		}
	}
	t.Setenv("TERM", "linux")
	t.Setenv("NO_COLOR", "")
	ansi, color := terminalCapabilities()
	if !ansi || color {
		t.Fatal("NO_COLOR not honored")
	}
}

func TestTerminalProcess(t *testing.T) {
	if os.Args[len(os.Args)-1] != "console-pty" {
		return
	}
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "ens160", "device"), 0o700); err != nil {
		t.Fatal(err)
	}
	collector := applianceconsole.NewCollector(applianceconsole.Sources{NetDir: dir, Probe: func(_ context.Context, args []string) string {
		switch args[0] {
		case "/usr/sbin/ip":
			return `[{"ifname":"ens160","operstate":"UP","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24}]}]`
		case "/usr/bin/systemctl":
			return "ActiveState=inactive\nResult=success"
		default:
			return ""
		}
	}})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer stop()
	before, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	var action string
	switch os.Getenv("CONSOLE_TEST_MODE") {
	case "confirm":
		action, err = confirm(ctx, "CONFIRM READY: ")
	case "reject":
		action, err = menu(ctx, collector, false)
		if err == nil || action != "" {
			t.Fatalf("unsafe input accepted: action=%q err=%v", action, err)
		}
	default:
		action, err = menu(ctx, collector, false)
	}
	if err != nil && ctx.Err() == nil && os.Getenv("CONSOLE_TEST_MODE") != "reject" {
		t.Fatal(err)
	}
	after, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if *before != *after {
		t.Fatal("terminal modes not restored")
	}
	switch {
	case ctx.Err() != nil:
		fmt.Fprintln(os.Stdout, "RESTORED CANCELLED")
	case os.Getenv("CONSOLE_TEST_MODE") == "reject":
		fmt.Fprintln(os.Stdout, "RESTORED REJECTED")
	default:
		fmt.Fprintln(os.Stdout, "RESTORED ACTION:"+action)
	}
}

func TestRealPTYSignalRestoresTerminal(t *testing.T) {
	s := startTerminal(t, 25, 80, "linux")
	s.await(t, "Read-only public console")
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	s.await(t, "RESTORED CANCELLED")
	if err := s.cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

type terminalSession struct {
	master  *os.File
	cmd     *exec.Cmd
	chunks  chan string
	pending string
}

func startTerminal(t *testing.T, rows, columns uint16, term string) *terminalSession {
	t.Helper()
	return startTerminalMode(t, rows, columns, term, "")
}

func startTerminalMode(t *testing.T, rows, columns uint16, term, mode string) *terminalSession {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "ptmx")
	t.Cleanup(func() { master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	index, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	slaveFD, err := unix.Open(fmt.Sprintf("/dev/pts/%d", index), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	slave := os.NewFile(uintptr(slaveFD), "pts")
	defer slave.Close()
	if err := unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{Row: rows, Col: columns}); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	// #nosec G204 -- execute this test binary with a fixed helper-test selector.
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestTerminalProcess$", "--", "console-pty")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "TERM=" + term, "CONSOLE_TEST_MODE=" + mode}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	s := &terminalSession{master: master, cmd: cmd, chunks: make(chan string, 32)}
	t.Cleanup(func() { cancel(); cmd.Wait() })
	go func() {
		defer close(s.chunks)
		buffer := make([]byte, 8192)
		for {
			n, err := master.Read(buffer)
			if n > 0 {
				select {
				case s.chunks <- string(buffer[:n]):
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return s
}

func (s *terminalSession) await(t *testing.T, text string) {
	t.Helper()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for !strings.Contains(s.pending, text) {
		select {
		case chunk, ok := <-s.chunks:
			if !ok {
				t.Fatalf("PTY closed before %q: %q", text, s.pending)
			}
			s.pending += chunk
		case <-deadline.C:
			t.Fatalf("PTY timeout waiting for %q: %q", text, s.pending)
		}
	}
	s.pending = ""
}

func (s *terminalSession) send(t *testing.T, text string) {
	t.Helper()
	if _, err := s.master.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

func TestRealPTYNavigationResizePasteAndRestoration(t *testing.T) {
	for _, tt := range []struct {
		height uint16
		term   string
	}{{25, "linux"}, {24, "linux"}, {24, "vt100"}, {24, "dumb"}} {
		t.Run(fmt.Sprintf("%s-%d", tt.term, tt.height), func(t *testing.T) {
			s := startTerminal(t, tt.height, 80, tt.term)
			s.await(t, "Read-only public console")
			s.send(t, "1")
			s.await(t, "NETWORK / OBSERVED STATE")
			s.send(t, "b")
			s.await(t, "Installation report")
			// A pasted sequence must not open views or dispatch login.
			s.send(t, "\x1b[200~0LS234\x1b[201~")
			s.send(t, "\x1b[B\r")
			s.await(t, "SETUP ACCESS / BROWSER HANDOFF")
			s.send(t, "b")
			s.await(t, "Installation report")
			if err := unix.IoctlSetWinsize(int(s.master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 12, Col: 40}); err != nil {
				t.Fatal(err)
			}
			s.send(t, "r")
			s.await(t, "> [2]")
			s.send(t, "l")
			s.await(t, "RESTORED ACTION:login")
			if err := s.cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
