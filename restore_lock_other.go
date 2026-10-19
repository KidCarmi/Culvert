//go:build !unix

package main

import "errors"

var errDataDirLocked = errors.New("data directory is locked by another Culvert process")

// acquireDataDirLock is a no-op on platforms without flock; restore and the
// proxy are Linux-container features, so the lock is advisory there only.
func acquireDataDirLock(_ string) (func(), error) { return func() {}, nil }
