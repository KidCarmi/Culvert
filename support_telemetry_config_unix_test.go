//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestTelemetryConfigRejectsFIFOWithoutBlocking proves a FIFO planted at the
// config path is rejected as non-regular AND does not hang the loader.
//
// This is the reason the open carries oNonBlock. The pre-TOCTOU loader
// Lstat'd first and so never opened a FIFO at all; moving every check onto
// the descriptor means the open happens FIRST, and a plain O_RDONLY open of a
// FIFO blocks until a writer appears — which, on the synchronous startup
// path, would hang boot. With O_NONBLOCK the open returns immediately and the
// descriptor-bound Stat refuses it.
//
// The test would fail by TIMING OUT rather than asserting if the flag were
// dropped, so it is deliberately given no writer.
func TestTelemetryConfigRejectsFIFOWithoutBlocking(t *testing.T) {
	withTempTelemetryDir(t)
	path := telemetryConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skipf("mkfifo unsupported here: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := readTelemetryConfigBytes(path)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, errTelemetryConfigUnsafe) {
			t.Fatalf("err = %v, want errTelemetryConfigUnsafe for a FIFO at the config path", err)
		}
	case <-t.Context().Done():
		t.Fatal("readTelemetryConfigBytes blocked on a FIFO — the open must carry O_NONBLOCK")
	}

	if got := telemetryConfigGet(); got.Enabled || got.Credential != "" {
		t.Fatalf("a FIFO at the config path must fail closed, got %+v", got)
	}
	if telemetryEnabled() {
		t.Error("a FIFO config must never produce an enabled posture")
	}
}
