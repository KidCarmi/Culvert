//go:build windows

package main

// oNoFollow degrades to a no-op (0) on Windows: the syscall package there does
// not define O_NOFOLLOW. The Windows build is a compile/CLI convenience target
// only — Culvert ships as a Linux Docker appliance — so this platform never
// runs the backup/catalog read paths in anger. Callers that OR this flag in
// still perform their own Lstat + ModeSymlink checks before opening, so the
// open-flag is belt-and-suspenders that simply isn't available here.
//
// See nofollow_unix.go for the real flag on Unix-like platforms.
const oNoFollow = 0
