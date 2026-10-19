//go:build !linux

package fileutil

import (
	"fmt"
	"os"
)

// RewriteInPlace: see rewrite.go. Without renameat2's RENAME_EXCHANGE there is
// no way to replace path that cannot destroy a concurrent external change, so
// nothing is written and the caller has no write evidence.
func RewriteInPlace(path string, _ []byte, _ os.FileInfo) error {
	return fmt.Errorf("rewrite in place %s: %w", path, ErrRewriteUnsupported)
}
