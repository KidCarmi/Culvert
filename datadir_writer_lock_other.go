//go:build !unix

package main

// datadir_writer_lock_other.go — no advisory locking on this platform, so the
// guard cannot establish a verdict and the boot proceeds with a notice. Mirrors
// internal/storeguard's dirlock_other.go: a platform without the primitive is an
// undetermined lock state, never a refusal.

import (
	"errors"
	"os"
)

func flockExclusiveNonBlocking(*os.File) (bool, error) {
	return false, errors.New("advisory file locking is not available on this platform")
}
