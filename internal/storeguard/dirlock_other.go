//go:build !unix

package storeguard

// dirlock_other.go — CHAOS-50/57 fail-safe stub for platforms without flock.
//
// Culvert ships on linux/amd64 and linux/arm64, so this file exists only so the
// package keeps compiling under a cross-platform vet/build. Reporting "cannot
// determine" makes every quarantine refuse on such a platform: the store still
// degrades safely, it just never self-heals.

import (
	"errors"
	"os"
)

func flockFile(*os.File) (bool, error) {
	return false, errors.New("lock state is not observable on this platform")
}

func unlockFile(*os.File) {}
