//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// confirmationByte polls canonical terminal input without a background reader
// that could retain input after cancellation or compete with a PAM child.
func confirmationByte(ctx context.Context, fd int) (byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		// #nosec G115 -- caller supplies an open OS file descriptor.
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("poll confirmation: %w", err)
		}
		if n == 0 {
			continue
		}
		if poll[0].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return 0, errors.New("confirmation input unavailable")
		}
		var b [1]byte
		count, err := unix.Read(fd, b[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("read confirmation: %w", err)
		}
		if count != 1 {
			return 0, io.EOF
		}
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		return b[0], nil
	}
}
