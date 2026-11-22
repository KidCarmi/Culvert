//go:build !unix

package writerlock

import (
	"errors"
	"os"
)

// flockExclusiveNonBlocking reports that the lock state cannot be established:
// a platform without advisory locking is Undetermined, never Held.
func flockExclusiveNonBlocking(*os.File) (bool, error) {
	return false, errors.New("advisory file locking is not available on this platform")
}
