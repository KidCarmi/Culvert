package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestPeekEncryptedMagic_DoesNotHangOnFIFO guards against a TOCTOU hang in
// runListBackups' one-shot classification path.
//
// discoverBackups classifies each directory entry in two steps separated in
// time: an Lstat-based "is this a regular file?" check (runListBackups), then
// a re-open of the same path in peekEncryptedMagic to peek its magic bytes.
// list_backups.go's own doc comment on oNoFollow names exactly this window
// ("Open uses O_NOFOLLOW so a symlink-replacement race after the caller's
// DirEntry.Type() / Lstat checks cannot trick us into reading from an
// unintended target") but O_NOFOLLOW only refuses a SYMLINK substituted into
// that window — it does nothing for a FIFO substituted the same way.
//
// open(2): "opening a FIFO for reading normally blocks until some other
// process opens the same FIFO for writing" — exactly the hang
// support_telemetry_config.go's readTelemetryConfigBytes already guards
// against by adding oNonBlock alongside oNoFollow (see its doc comment).
// peekEncryptedMagic carries oNoFollow only, so a regular file swapped for a
// FIFO between the caller's Lstat and this open blocks the whole --list-backups
// one-shot (and, through it, the Maintenance Agent's synchronous
// GET /v1/backups handler) indefinitely, with nothing to write to the pipe
// and end the wait.
//
// This test drives the vulnerable function directly against a FIFO (the
// state the TOCTOU race can reach) rather than trying to win the race itself,
// which is the same test-authoring convention this repo tests behavior
// against a directly-constructed FIFO/symlink path used
// throughout the *_toctou_test.go / *_chaos_test.go files in this tree.
func TestPeekEncryptedMagic_DoesNotHangOnFIFO(t *testing.T) {
	dir := t.TempDir()
	fifoPath := filepath.Join(dir, "swapped-to-fifo")
	if err := syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	done := make(chan bool, 1)
	go func() {
		done <- peekEncryptedMagic(fifoPath)
	}()

	select {
	case <-done:
		// Returned promptly — the guard is in place.
	case <-time.After(3 * time.Second):
		t.Fatal("peekEncryptedMagic hung opening a FIFO (missing oNonBlock) — " +
			"a regular file swapped for a FIFO between the caller's Lstat and " +
			"this open blocks --list-backups / GET /v1/backups indefinitely")
	}
}
