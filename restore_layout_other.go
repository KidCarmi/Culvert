//go:build !linux

package main

// restore_layout_other.go — the product ships on Linux; elsewhere the restore
// keeps the whole-directory swap and reports free space as unknown.

func restoreDirIsMountPoint(string) bool { return false }

func restoreDirWritable(string) bool { return true }

func restoreFreeBytes(string) (uint64, bool) { return 0, false }
