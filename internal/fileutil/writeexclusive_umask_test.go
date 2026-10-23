//go:build unix

package fileutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The requested mode must not depend on the process umask: a umask that
// masks owner bits would otherwise leave the rendezvous unreadable after a
// restart. Not parallel — umask is process-wide.
func TestWriteFileExclusive_ModeIsIndependentOfUmask(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.key.tmp")
	old := syscall.Umask(0o277)
	t.Cleanup(func() { syscall.Umask(old) })
	if err := WriteFileExclusive(path, []byte("k"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	syscall.Umask(old)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o under umask 0277, want 0600", got)
	}
}
