//go:build unix

package fileutil

import (
	"os"
	"syscall"
)

// preserveOwner gives f the owner and group of orig, best effort. An
// unprivileged process may not give a file away (EPERM), and that refusal is
// deliberately ignored: the replacement then carries the process's own
// ownership, exactly as an AtomicWrite of the same target would.
func preserveOwner(f *os.File, orig os.FileInfo) {
	st, ok := orig.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = f.Chown(int(st.Uid), int(st.Gid)) // #nosec G104 -- best-effort; see doc comment
}
