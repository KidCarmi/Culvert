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
// systemd's TTYReset=yes (getty@tty1) normally does the same before ExecStart,
// but it skips the whole reset when it cannot open /dev/console. On the
// appliance /dev/console is ttyS0, which the 8250 driver registers even on a
// VM with no serial port, so on ESXi this guard can be the only repair. Do not
// remove it as redundant.
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
