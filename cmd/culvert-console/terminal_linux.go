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
	input, inputErr := os.Stdin.Stat()
	output, outputErr := os.Stdout.Stat()
	if inputErr != nil || outputErr != nil || !os.SameFile(input, output) {
		return errors.New("interactive input and output must use the same terminal")
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
	inputCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	b, err := confirmationByte(inputCtx, 0)
	if err != nil {
		if ctx.Err() == nil && errors.Is(err, context.DeadlineExceeded) {
			return "", nil
		}
		return "", err
	}
	if b == 27 {
		// Start the sequence budget at Escape, not at the preceding idle poll.
		return readEscape(ctx)
	}
	return applianceconsole.DecodeKey(string(b)), nil
}

func readEscape(ctx context.Context) (string, error) {
	inputCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()
	var sequence strings.Builder
	sequence.WriteByte(27)
	for sequence.Len() < 16 {
		b, err := confirmationByte(inputCtx, 0)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			if errors.Is(err, context.DeadlineExceeded) {
				break
			}
			return "", err
		}
		sequence.WriteByte(b)
		if sequence.String() == "\x1b[200~" {
			return "", discardPaste(ctx)
		}
		if key := applianceconsole.DecodeKey(sequence.String()); key != "" {
			return key, nil
		}
	}
	if sequence.Len() == 1 {
		return "ESC", nil
	}
	return "", errors.New("incomplete or unsupported console escape sequence")
}

func menu(ctx context.Context, collector applianceconsole.Collector, admin bool) (choice string, result error) {
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
	ansi, _ := terminalCapabilities()
	defer func() {
		// Never hand the terminal to PAM/sudo if restoration or draining failed.
		restoreErr := unix.IoctlSetTermios(0, unix.TCSETS, original)
		var displayErr error
		if ansi {
			_, displayErr = fmt.Fprint(os.Stdout, "\x1b[0m\x1b[?25h\x1b[?2004l\x1b[2J\x1b[H")
		}
		result = errors.Join(result, restoreErr, displayErr, unix.IoctlSetInt(0, unix.TCFLSH, unix.TCIFLUSH))
		if result != nil {
			choice = ""
		}
	}()
	if ansi {
		if _, err := fmt.Fprint(os.Stdout, "\x1b[2J\x1b[H\x1b[?25l\x1b[?2004h"); err != nil {
			return "", fmt.Errorf("hide cursor: %w", err)
		}
	}
	return runMenu(ctx, collector, admin)
}

type menuDisplay struct {
	snapshot      applianceconsole.Snapshot
	refresh       time.Time
	dirty         bool
	view          applianceconsole.View
	ansi, color   bool
	lastFrame     string
	height, width int
}

func (d *menuDisplay) redraw(ctx context.Context, collector applianceconsole.Collector) error {
	if time.Now().After(d.refresh) {
		d.snapshot = collector.Collect(ctx)
		d.refresh = time.Now().Add(5 * time.Second)
		d.dirty = true
	}
	height, width := terminalSize()
	if !d.dirty && height == d.height && width == d.width {
		return nil
	}
	panelHeight, panelWidth := min(height, 25), min(width, 80)
	rows := d.view.Frame(d.snapshot, panelHeight, panelWidth)
	frame := applianceconsole.Render(rows, d.color)
	if !d.ansi && frame == d.lastFrame {
		d.dirty = false
		return nil
	}
	d.lastFrame = frame
	if d.ansi {
		frame = positionedFrame(rows, d.color, height, width, panelHeight, panelWidth)
		if height != d.height || width != d.width {
			frame = "\x1b[2J" + frame
		}
	} else {
		frame = "\nObserved (UTC): " + applianceconsole.Clean(d.snapshot.ObservedAt, 40) + "\n" + frame + "\n"
	}
	if _, err := fmt.Fprint(os.Stdout, frame); err != nil {
		return fmt.Errorf("draw menu: %w", err)
	}
	d.dirty, d.height, d.width = false, height, width
	return nil
}

func terminalSize() (height, width int) {
	if size, err := unix.IoctlGetWinsize(1, unix.TIOCGWINSZ); err == nil && size.Row > 0 && size.Col > 0 {
		return int(size.Row), int(size.Col)
	}
	return 25, 80
}

func positionedFrame(rows []applianceconsole.Row, color bool, height, width, panelHeight, panelWidth int) string {
	var output strings.Builder
	top, left := (height-panelHeight)/2+1, (width-panelWidth)/2+1
	for i := range rows {
		rows[i].Text += strings.Repeat(" ", max(0, panelWidth-1-len(rows[i].Text)))
		output.WriteString(fmt.Sprintf("\x1b[%d;%dH", top+i, left))
		output.WriteString(applianceconsole.Render(rows[i:i+1], color))
	}
	return output.String()
}

// discardPaste consumes bracketed paste as data, never as recovery commands.
// A missing terminator ends the session; late paste bytes cannot become actions.
func discardPaste(ctx context.Context) error {
	deadline := time.Now().Add(2 * time.Second)
	var tail string
	for time.Now().Before(deadline) && ctx.Err() == nil {
		poll := []unix.PollFd{{Fd: 0, Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return fmt.Errorf("drain paste: %w", err)
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return errors.New("console input unavailable during paste")
		}
		var b [1]byte
		if count, err := unix.Read(0, b[:]); err != nil || count != 1 {
			if err == nil {
				err = errors.New("console input closed")
			}
			return fmt.Errorf("read paste: %w", err)
		}
		tail += string(b[:])
		if len(tail) > 6 {
			tail = tail[len(tail)-6:]
		}
		if tail == "\x1b[201~" {
			return nil
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return errors.New("unterminated console paste")
}

func runMenu(ctx context.Context, collector applianceconsole.Collector, admin bool) (string, error) {
	lastInput := time.Now()
	ansi, color := terminalCapabilities()
	display := menuDisplay{dirty: true, view: applianceconsole.NewView(admin), ansi: ansi, color: color}
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if err := display.redraw(ctx, collector); err != nil {
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
		if key != "" {
			display.dirty = true
		}
		switch choice := display.view.Handle(key); choice {
		case "refresh":
			display.refresh = time.Time{}
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

func confirm(ctx context.Context, prompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := unix.IoctlSetInt(0, unix.TCFLSH, unix.TCIFLUSH); err != nil {
		return "", fmt.Errorf("clear confirmation input: %w", err)
	}
	if _, err := fmt.Fprint(os.Stdout, prompt); err != nil {
		return "", fmt.Errorf("display confirmation: %w", err)
	}
	// No buffered reader may retain keystrokes needed by a later PAM/sudo prompt.
	var answer strings.Builder
	for {
		b, err := confirmationByte(ctx, 0)
		if err != nil {
			return "", err
		}
		if b == '\n' {
			if err := unix.IoctlSetInt(0, unix.TCFLSH, unix.TCIFLUSH); err != nil {
				return "", fmt.Errorf("drain confirmation input: %w", err)
			}
			return strings.TrimSuffix(answer.String(), "\r"), nil
		}
		if answer.Len() < 128 {
			answer.WriteByte(b)
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
			return fmt.Errorf("console unavailable; reconnect or use SSH for recovery: %w", err)
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
		if _, err := confirm(ctx, "\nPress Enter to return to the menu..."); err != nil {
			return nil
		}
	}
}

// Unknown terminals receive printable output only. No-color keeps navigation.
func terminalCapabilities() (ansi, color bool) {
	term := os.Getenv("TERM")
	ansi = term == "linux" || term == "vt100" || term == "ansi" || strings.HasPrefix(term, "xterm") || strings.HasPrefix(term, "screen") || strings.HasPrefix(term, "tmux")
	_, noColor := os.LookupEnv("NO_COLOR")
	return ansi, ansi && term != "vt100" && !noColor
}
