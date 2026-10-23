//go:build unix && !linux

package main

import "testing"

func setSameInodeXattr(t *testing.T, _ string) {
	t.Helper()
	t.Skip("the same-inode xattr stand-in is Linux-only")
}
