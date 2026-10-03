//go:build !linux

package server

import "errors"

func statfsFreeBytes(string) (uint64, error) {
	return 0, errors.New("free-space probe not supported on this platform")
}
