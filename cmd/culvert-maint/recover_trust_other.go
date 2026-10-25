//go:build !linux

package main

import "errors"

func acquireRecoveryHostLock(string) (release func(), busy bool, err error) {
	return nil, false, errors.New("release-trust recovery requires Linux")
}
