//go:build !linux

package fileutil

// ReplacementBlocked reports nothing here: the inode flags and statx
// attributes that block a replacement are Linux interfaces, so this platform
// has no live check (a known gap; a refused save still reports it).
func ReplacementBlocked(string) error { return nil }
