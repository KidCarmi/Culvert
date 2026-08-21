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

// oNonBlock is the open(2) O_NONBLOCK flag. Callers OR it in alongside
// oNoFollow when they open a path that an attacker could have replaced with a
// FIFO: opening a FIFO for reading BLOCKS until a writer appears, so a plain
// open would hang the caller instead of letting it reject the non-regular
// file. With O_NONBLOCK the open returns immediately and the caller's
// descriptor-bound Stat can refuse it. Ignored for regular files.
//
// Windows counterpart is a no-op (nofollow_windows.go).
const oNonBlock = syscall.O_NONBLOCK
