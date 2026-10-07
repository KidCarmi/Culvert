//go:build linux

package main

import "golang.org/x/sys/unix"

// linux/kd.h. golang.org/x/sys does not export the console-mode requests.
const (
	kdSetMode = 0x4B3A // KDSETMODE
	kdGetMode = 0x4B3B // KDGETMODE
	kdText    = 0x00   // KD_TEXT
)

// The two console-mode ioctls, swappable in tests (no test host owns a VT).
var (
	vtGetMode = func(fd int) (int, error) { return unix.IoctlGetInt(fd, kdGetMode) }
	vtSetMode = func(fd int, mode int) error { return unix.IoctlSetInt(fd, kdSetMode, mode) }
)

// ensureTextMode puts the boot console back in text mode before the menu is
// drawn. A splash that exits while it holds the VT in graphics mode (plymouth
// does this when it quits inside its device wait) leaves the kernel ignoring
// every write to tty1: the menu would run but the screen would stay frozen on
// the last frame. Setting KD_TEXT also unblanks and repaints the VT.
//
// It is a repair, not a gate: a descriptor that is not a VT reports an error
// and nothing changes. It returns whether it changed the mode.
func ensureTextMode(fd int) (bool, error) {
	mode, err := vtGetMode(fd)
	if err != nil {
		return false, err
	}
	if mode == kdText {
		return false, nil
	}
	if err := vtSetMode(fd, kdText); err != nil {
		return false, err
	}
	return true, nil
}
