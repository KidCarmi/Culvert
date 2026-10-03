//go:build linux

package applianceconsole

import (
	"os"

	"golang.org/x/sys/unix"
)

// Nonblocking open followed by fstat in readPublicFile rejects FIFOs/devices
// without hanging collection. Symlinks remain supported for resolver files.
func openPublicFile(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
