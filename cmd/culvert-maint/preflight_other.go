//go:build !linux

package main

// dirTraversable is a no-op on non-Linux builds. The agent only runs on Linux
// (peer auth via SO_PEERCRED); the release ships linux/amd64 + linux/arm64
// only. This stub keeps darwin/windows cross-builds green.
func dirTraversable(string) error { return nil }
