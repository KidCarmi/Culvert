//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
	"golang.org/x/sys/unix"
)

// adminIdentity uses the effective OS identity, never USER or login form input.
func adminIdentity() bool {
	if os.Geteuid() == 0 {
		return false
	}
	u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	return err == nil && u.Username == "culvert"
}

func onBootConsole() bool {
	expected, err := os.Stat("/dev/tty1")
	if err != nil {
		return false
	}
	actual, err := os.Stdin.Stat()
	return err == nil && os.SameFile(expected, actual)
}

// validateTerminal enforces the root getty boundary before any public login call.
func validateTerminal(admin bool) error {
	if _, err := unix.IoctlGetTermios(0, unix.TCGETS); err != nil {
		return errors.New("interactive mode requires a terminal")
	}
	if _, err := unix.IoctlGetTermios(1, unix.TCGETS); err != nil {
		return errors.New("interactive output requires a terminal")
	}
	if admin {
		if !adminIdentity() {
			return errors.New("admin mode requires an authenticated culvert user")
		}
	} else if os.Geteuid() != 0 || !onBootConsole() {
		return errors.New("login mode requires root on /dev/tty1")
	}
	return nil
}

// readKey handles fragmented escape sequences without a goroutine left reading
// passwords while /bin/login owns the terminal. Calls are bounded by poll.
func readKey(ctx context.Context) (string, error) {
	var sequence strings.Builder
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		poll := []unix.PollFd{{Fd: 0, Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return "", err
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return "", errors.New("console input unavailable")
		}
		var b [1]byte
		count, err := unix.Read(0, b[:])
		if err != nil {
			return "", err
		}
		if count != 1 {
			continue
		}
		sequence.WriteByte(b[0])
		if sequence.Len() == 1 && b[0] != 27 {
			return applianceconsole.DecodeKey(sequence.String()), nil
		}
		if key := applianceconsole.DecodeKey(sequence.String()); key != "" {
			return key, nil
		}
		if sequence.Len() >= 16 {
			return "", nil
		}
	}
	return "", nil
}

func menu(ctx context.Context, collector applianceconsole.Collector, admin bool) (string, error) {
	original, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		return "", err
	}
	mode := *original
	mode.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	mode.Iflag &^= unix.IXON | unix.ICRNL | unix.INLCR | unix.IGNCR
	mode.Cc[unix.VMIN], mode.Cc[unix.VTIME] = 0, 0
	if err := unix.IoctlSetTermios(0, unix.TCSETS, &mode); err != nil {
		return "", err
	}
	defer func() {
		// Best-effort restoration also runs when the terminal has disconnected.
		_ = unix.IoctlSetTermios(0, unix.TCSETS, original)
		_, _ = fmt.Fprint(os.Stdout, "\x1b[?25h\x1b[2J\x1b[H")
	}()
	if _, err := fmt.Fprint(os.Stdout, "\x1b[?25l"); err != nil {
		return "", fmt.Errorf("hide cursor: %w", err)
	}
	return runMenu(ctx, collector, admin)
}

type menuDisplay struct {
	snapshot           applianceconsole.Snapshot
	refresh            time.Time
	diagnostics, dirty bool
	height, width      int
}

func (d *menuDisplay) redraw(ctx context.Context, collector applianceconsole.Collector, admin bool) error {
	if time.Now().After(d.refresh) {
		d.snapshot = collector.Collect(ctx)
		d.refresh = time.Now().Add(5 * time.Second)
		d.dirty = true
	}
	height, width := 25, 80
	if size, err := unix.IoctlGetWinsize(1, unix.TIOCGWINSZ); err == nil && size.Row > 0 && size.Col > 0 {
		height, width = int(size.Row), int(size.Col)
	}
	if !d.dirty && height == d.height && width == d.width {
		return nil
	}
	lines := applianceconsole.Display(d.snapshot, admin, d.diagnostics, height, width)
	if _, err := fmt.Fprint(os.Stdout, "\x1b[2J\x1b[H"+strings.Join(lines, "\n")); err != nil {
		return fmt.Errorf("draw menu: %w", err)
	}
	d.dirty, d.height, d.width = false, height, width
	return nil
}

func runMenu(ctx context.Context, collector applianceconsole.Collector, admin bool) (string, error) {
	lastInput := time.Now()
	display := menuDisplay{dirty: true}
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := display.redraw(ctx, collector, admin); err != nil {
			return "", err
		}
		key, err := readKey(ctx)
		if err != nil {
			return "", err
		}
		if key != "" {
			lastInput = time.Now()
		}
		if admin && time.Since(lastInput) >= 5*time.Minute {
			return "logout", nil
		}
		switch choice := applianceconsole.Choice(key, admin); choice {
		case "refresh":
			display.refresh = time.Time{}
		case "diagnostics":
			display.diagnostics = !display.diagnostics
			display.dirty = true
		case "":
		default:
			return choice, nil
		}
	}
}

func execute(ctx context.Context, args []string) error {
	// #nosec G204 -- login and recovery policy supply fixed argv; no shell interpolation.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(probeEnvironment(), "TERM=linux")
	if u, err := user.LookupId(strconv.Itoa(os.Geteuid())); err == nil {
		cmd.Env = append(cmd.Env, "HOME="+u.HomeDir)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run console action: %w", err)
	}
	return nil
}

func confirm(prompt string) (string, error) {
	if _, err := fmt.Fprint(os.Stdout, prompt); err != nil {
		return "", fmt.Errorf("display confirmation: %w", err)
	}
	// No buffered reader may retain keystrokes needed by a later PAM/sudo prompt.
	var answer strings.Builder
	var b [1]byte
	for {
		if _, err := os.Stdin.Read(b[:]); err != nil {
			return "", err
		}
		if b[0] == '\n' {
			return strings.TrimSuffix(answer.String(), "\r"), nil
		}
		if answer.Len() < 128 {
			answer.WriteByte(b[0])
		} else {
			return "", errors.New("confirmation too long")
		}
	}
}

// runTerminal preserves the normal PAM login boundary. There is no autologin,
// credential parser, root shell, HTTP listener, or sudo-policy change here.
func runTerminal(ctx context.Context, collector applianceconsole.Collector, actions applianceconsole.Actions, admin bool) error {
	if err := validateTerminal(admin); err != nil {
		return err
	}
	for {
		choice, err := menu(ctx, collector, admin)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			if !admin {
				return execute(ctx, []string{"/bin/login", "culvert"})
			}
			return errors.New("console unavailable; use SSH for recovery")
		}
		if choice == "logout" {
			return nil
		}
		if choice == "login" {
			_ = execute(ctx, []string{"/bin/login", "culvert"})
			continue
		}
		if err := actions.Apply(ctx, choice); err != nil {
			if _, writeErr := fmt.Fprintln(os.Stderr, applianceconsole.Clean(err.Error(), 160)); writeErr != nil {
				return fmt.Errorf("display action error: %w", writeErr)
			}
		}
		if _, err := confirm("\nPress Enter to return to the menu..."); err != nil {
			return nil
		}
	}
}
