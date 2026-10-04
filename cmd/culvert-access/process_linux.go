//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceaccess"
	"golang.org/x/sys/unix"
)

const outputLimit = 256 * 1024

type boundedOutput struct {
	data     []byte
	overflow bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	remaining := max(0, outputLimit-len(b.data))
	if len(p) > remaining {
		b.overflow = true
	}
	b.data = append(b.data, p[:min(len(p), remaining)]...)
	return len(p), nil
}

func dispatch(parent context.Context, command applianceaccess.Command, out io.Writer) error {
	if command == applianceaccess.Help {
		_, err := io.WriteString(out, applianceaccess.HelpText)
		return err
	}
	if command == applianceaccess.Exit {
		return nil
	}
	argv, ok := command.Argv()
	if !ok {
		return errors.New("read-only command required")
	}
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	// #nosec G204 G702 -- Argv returns its own exact fixed read-only commands.
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir, cmd.Env = "/", applianceaccess.Environment()
	// nil stdin is /dev/null: probe children cannot consume SSH command input.
	cmd.Stdin, cmd.Stderr = nil, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 500 * time.Millisecond
	var output boundedOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil || output.overflow {
		return errors.New("bounded observation failed")
	}
	// Console reports are already sanitized. Refuse unexpected control bytes
	// rather than letting a compromised/mismatched child drive the terminal.
	for _, b := range output.data {
		if (b < 32 && b != '\n' && b != '\t') || b == 127 {
			return errors.New("invalid observation output")
		}
	}
	_, err := out.Write(output.data)
	return err
}

func sameTerminal() bool {
	if _, err := unix.IoctlGetTermios(0, unix.TCGETS); err != nil {
		return false
	}
	if _, err := unix.IoctlGetTermios(1, unix.TCGETS); err != nil {
		return false
	}
	input, inErr := os.Stdin.Stat()
	output, outErr := os.Stdout.Stat()
	return inErr == nil && outErr == nil && os.SameFile(input, output)
}

// terminalLine has no buffered reader or background goroutine. It rejects an
// overlong line rather than interpreting a prefix as the next command.
func terminalLine(parent context.Context, fd int) (string, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Minute)
	defer cancel()
	line := make([]byte, 0, 96)
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		// #nosec G115 -- fd is an open descriptor supplied by this process.
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) || n == 0 {
			continue
		}
		if err != nil || poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return "", errors.New("SSH input unavailable")
		}
		var b [1]byte
		if n, err := unix.Read(fd, b[:]); err != nil || n != 1 {
			return "", errors.New("SSH input unavailable")
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		if b[0] < 32 || b[0] > 126 || len(line) >= 96 {
			return "", errors.New("SSH input rejected")
		}
		line = append(line, b[0])
	}
}
