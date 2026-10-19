//go:build !linux

package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestRewriteInPlace_UnsupportedOffLinux: without an atomic exchange nothing
// is written and the caller gets ErrRewriteUnsupported.
func TestRewriteInPlace_UnsupportedOffLinux(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ui_users.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := RewriteInPlace(path, []byte("{}"), fi); !errors.Is(err, ErrRewriteUnsupported) {
		t.Fatalf("err = %v, want ErrRewriteUnsupported", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(fi, after) {
		t.Error("the target was replaced")
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d directory entries, want only the target", len(entries))
	}
}
