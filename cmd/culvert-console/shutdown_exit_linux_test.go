//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestShutdownExitProcess is the subprocess half of the blocked-write
// reproduction. It mirrors production run(): signal.NotifyContext with NO
// overall timeout, so the ONLY way it can exit on SIGTERM is the watchdog (or,
// pre-fix, never). It then parks in a write(2) to tty1 that cannot complete —
// the parent holds the PTY master open and never reads it, so the line buffer
// fills and the write blocks, exactly as tty1 blocks when plymouth stops
// draining the VT during shutdown (ASTRA PID 6427, 90s). A blocked write is not
// interruptible by ctx; nothing short of os.Exit ends it.
func TestShutdownExitProcess(t *testing.T) {
	if os.Getenv("CONSOLE_SHUTDOWN_TEST") != "1" {
		return
	}
	grace, err := time.ParseDuration(os.Getenv("CONSOLE_SHUTDOWN_GRACE"))
	if err != nil {
		t.Fatalf("bad grace: %v", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer stop()
	if os.Getenv("CONSOLE_SHUTDOWN_WATCHDOG") != "off" {
		armShutdownExit(ctx, grace)
	}
	// Signal readiness out of band (the tty is deliberately unread), then block.
	if ready := os.Getenv("CONSOLE_SHUTDOWN_READY"); ready != "" {
		if err := os.WriteFile(ready, []byte("x"), 0o600); err != nil {
			t.Fatalf("readiness: %v", err)
		}
	}
	buf := make([]byte, 64*1024)
	for {
		// Blocks once the PTY buffer fills; ctx cancellation cannot unblock it.
		if _, err := unix.Write(1, buf); err != nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// spawnBlockedConsole starts TestShutdownExitProcess on a PTY slave whose master
// the caller holds open but never reads, so the child parks in a blocked write.
func spawnBlockedConsole(t *testing.T, grace time.Duration, watchdog bool) (*exec.Cmd, *os.File) {
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
	slaveFD, err := unix.Open("/dev/pts/"+itoa(index), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	slave := os.NewFile(uintptr(slaveFD), "pts")
	defer slave.Close()
	ready := t.TempDir() + "/ready"
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A cancellable context satisfies noctx without capping the run: it is
	// cancelled only at cleanup, never on a timer, so it cannot mask the hang
	// the control relies on (production run() has no overall timeout either).
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// #nosec G204 -- fixed selector against this test binary.
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestShutdownExitProcess$", "--", "blocked-write")
	wd := "on"
	if !watchdog {
		wd = "off"
	}
	cmd.Env = append(os.Environ(),
		"CONSOLE_SHUTDOWN_TEST=1",
		"CONSOLE_SHUTDOWN_GRACE="+grace.String(),
		"CONSOLE_SHUTDOWN_WATCHDOG="+wd,
		"CONSOLE_SHUTDOWN_READY="+ready,
	)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Wait until the child is about to block, then let it enter the write(2).
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatal("child never reached the blocking write")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	return cmd, master
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// TestArmShutdownExit pins the backstop deterministically: it stays inert while
// the console is running (no exit before ctx is cancelled, so an operator at the
// menu is never force-exited), and it exits 0 within the grace once cancelled.
func TestArmShutdownExit(t *testing.T) {
	exited := make(chan int, 1)
	orig := shutdownExitFunc
	shutdownExitFunc = func(code int) { exited <- code }
	t.Cleanup(func() { shutdownExitFunc = orig })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	armShutdownExit(ctx, 100*time.Millisecond)

	select {
	case <-exited:
		t.Fatal("backstop fired before shutdown was requested")
	case <-time.After(250 * time.Millisecond):
	}

	cancel()
	select {
	case code := <-exited:
		if code != 0 {
			t.Fatalf("backstop exit code %d, want 0", code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backstop did not exit within the grace after cancellation")
	}
}

// TestConsoleShutdownBoundsBlockedWrite proves the fix and that its gate is not
// vacuous. With the watchdog armed, a console parked in an uninterruptible tty
// write exits within the grace of a SIGTERM (what systemd's session scope needs
// so it never waits its 90s default and SIGKILLs us). The control, with the
// watchdog disabled, reproduces the pre-fix hang: the same SIGTERM leaves the
// process blocked because signal.NotifyContext replaces the default terminate
// and ctx cancellation cannot unblock the write.
func TestConsoleShutdownBoundsBlockedWrite(t *testing.T) {
	const grace = 2 * time.Second

	t.Run("watchdog_bounds_blocked_write", func(t *testing.T) {
		cmd, _ := spawnBlockedConsole(t, grace, true)
		start := time.Now()
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			elapsed := time.Since(start)
			if elapsed > grace+2*time.Second {
				t.Fatalf("exit took %v, want <= %v", elapsed, grace+2*time.Second)
			}
			if err != nil {
				t.Fatalf("console did not exit cleanly after SIGTERM: %v", err)
			}
			if elapsed < grace-500*time.Millisecond {
				t.Fatalf("exited in %v, before the grace %v — watchdog not the cause", elapsed, grace)
			}
		case <-time.After(grace + 5*time.Second):
			_ = cmd.Process.Kill()
			<-done
			t.Fatal("console still blocked after SIGTERM — 90s shutdown stall not fixed")
		}
	})

	t.Run("control_pre_fix_hangs_without_watchdog", func(t *testing.T) {
		cmd, _ := spawnBlockedConsole(t, grace, false)
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
			t.Fatal("control exited on SIGTERM without the watchdog — reproduction is vacuous")
		case <-time.After(grace + 2*time.Second):
			// Still blocked, as the pre-fix console was. Clean up.
			_ = cmd.Process.Kill()
			<-done
		}
	})
}
