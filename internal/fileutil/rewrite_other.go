//go:build !linux

package fileutil

import (
	"fmt"
	"os"
)

// RewriteInPlace writes nothing here (the contract is in rewrite.go). Without renameat2's RENAME_EXCHANGE there is
// no way to replace path that cannot destroy a concurrent external change, so
// nothing is written and the caller has no write evidence.
func RewriteInPlace(path string, _ []byte, _ os.FileInfo) error {
	return fmt.Errorf("rewrite in place %s: %w", path, ErrRewriteUnsupported)
}

// ReplacementBlocked reports nothing here: the inode flags and statx
// attributes that block a replacement are Linux interfaces, so this platform
// has no live check (a known gap; a refused save still reports it).
func ReplacementBlocked(string) error { return nil }
