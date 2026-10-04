//go:build linux

package server

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Called only with host-maintenance.lock held. A valid earlier-boot fence is
// removed under that same lock; current-boot fences outlive the power helper.
func pendingShutdown(stateDir string) (bool, error) {
	path := filepath.Join(stateDir, shutdownFenceName)
	data, err := readShutdownFile(path, shutdownFenceLimit)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	boot, err := parseShutdownFence(data)
	if err != nil {
		return false, err
	}
	current, err := readShutdownFile("/proc/sys/kernel/random/boot_id", 64)
	if err != nil {
		return false, err
	}
	currentBoot := strings.TrimSuffix(string(current), "\n")
	if !validBootID(currentBoot) {
		return false, errors.New("current boot identity unavailable")
	}
	if boot == currentBoot {
		return true, nil
	}
	if err := os.Remove(path); err != nil {
		return false, err
	}
	directory, err := os.Open(stateDir) //nolint:gosec // fixed agent-owned state directory
	if err != nil {
		return false, err
	}
	defer directory.Close()
	return false, directory.Sync()
}

func readShutdownFile(path string, limit int64) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return nil, err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&0o022 != 0 || st.Nlink != 1 {
		return nil, errors.New("unsafe pending shutdown identity or fence")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("pending shutdown identity or fence exceeds limit")
	}
	return data, nil
}
