//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRealPTYMalformedInputRestoresWithoutDispatch(t *testing.T) {
	for _, input := range []string{"\x1b[", "\x1b[" + strings.Repeat("1", 20) + "L", "\x1b[200~REBOOT\nL"} {
		t.Run(input, func(t *testing.T) {
			s := startTerminalMode(t, 25, 80, "linux", "reject")
			s.await(t, "Read-only public console")
			s.send(t, input)
			s.await(t, "RESTORED REJECTED")
			if err := s.cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRealPTYConfirmationCancellation(t *testing.T) {
	s := startTerminalMode(t, 25, 80, "linux", "confirm")
	s.await(t, "CONFIRM READY:")
	s.send(t, "REBOOT") // Incomplete canonical input must not prevent cancellation.
	if err := s.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	s.await(t, "RESTORED CANCELLED")
	if err := s.cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmationReadDeadlineAndDisconnect(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := confirmationByte(ctx, int(reader.Fd())); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline ignored: %v", err)
	}
	writer.Close()
	if _, err := confirmationByte(context.Background(), int(reader.Fd())); err == nil {
		t.Fatal("disconnected input accepted")
	}
}
