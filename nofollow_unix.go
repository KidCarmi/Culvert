//go:build !windows

package main

import "syscall"

// oNoFollow is the open(2) O_NOFOLLOW flag on Unix-like platforms (Linux,
// darwin, the BSDs), where syscall defines it. Callers OR it into os.OpenFile
// to refuse opening a symlink — a defense-in-depth guard against a
// symlink-swap TOCTOU race after an Lstat/DirEntry check.
//
// The Windows counterpart (nofollow_windows.go) degrades this to a no-op
// because syscall.O_NOFOLLOW is undefined there; see that file for the
// platform rationale. Splitting the constant across build-tagged files keeps
// `GOOS=windows go build` compiling (the release matrix builds a windows/amd64
// convenience binary) without weakening the guard on the Linux appliance.
const oNoFollow = syscall.O_NOFOLLOW
