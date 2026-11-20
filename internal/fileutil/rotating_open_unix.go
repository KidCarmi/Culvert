//go:build unix

package fileutil

import (
	"os"
	"syscall"
)

// oNoFollow and oNonBlock are the open(2) flags openLogAppend ORs in on
// Unix-like platforms, where syscall defines both (the same idiom as
// ReplacementBlocked in replacement_linux.go). rotating_open_other.go
// degrades them to 0 elsewhere.
const (
	oNoFollow = syscall.O_NOFOLLOW
	oNonBlock = syscall.O_NONBLOCK
)

// clearNonBlock turns O_NONBLOCK off on f after openLogAppend has verified it
// is a regular file, so log writes keep ordinary blocking semantics. It goes
// through RawConn.Control rather than f.Fd(), which would also change how the
// os package drives the descriptor.
func clearNonBlock(f *os.File) error {
	rc, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) {
		setErr = syscall.SetNonblock(int(fd), false)
	}); err != nil {
		return err
	}
	return setErr
}
