//go:build darwin

package main

import "golang.org/x/sys/unix"

func statfsReadOnly(dir string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, err
	}
	return st.Flags&unix.MNT_RDONLY != 0, nil
}
