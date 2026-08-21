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

// oNonBlock likewise degrades to a no-op (0) on Windows, which has no FIFOs in
// the POSIX sense and no syscall.O_NONBLOCK. Callers use it only to avoid
// blocking on a FIFO that replaced a regular file; on this convenience target
// the descriptor-bound Stat still rejects any non-regular file, it just cannot
// guarantee the open itself returns promptly.
//
// NOTE for readers of the telemetry config loader: on Windows the no-follow
// guarantee is unavailable, so a symlink at the config path would be followed
// and the loader's symlink defense degrades to the type/permission checks it
// makes on the resulting descriptor. This is accepted for the same reason as
// oNoFollow above — the appliance ships as a Linux container; the Windows
// binary is a build-matrix convenience only.
const oNonBlock = 0
