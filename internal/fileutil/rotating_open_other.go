//go:build !unix

package fileutil

import "os"

// oNoFollow and oNonBlock are 0 here: this platform's syscall package has no
// O_NOFOLLOW or O_NONBLOCK. openLogAppend therefore keeps its previous
// behaviour on it — a symlink at the log path is followed and an open of a
// FIFO is not guaranteed to return promptly — and only its regular-file check
// still applies. Culvert ships as a Linux appliance; these builds are
// compile/CLI convenience targets (see rotating_open_unix.go for the guard).
const (
	oNoFollow = 0
	oNonBlock = 0
)

// clearNonBlock has nothing to clear: oNonBlock is 0 on this platform.
func clearNonBlock(*os.File) error { return nil }
