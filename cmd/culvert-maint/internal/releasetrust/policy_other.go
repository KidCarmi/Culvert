//go:build !linux

package releasetrust

import (
	"errors"
	"os"
)

func privateFileOwner(os.FileInfo) bool { return false }

func privateDirectory(string) error {
	return errors.New("release trust requires Linux filesystem ownership")
}

// ReadPolicyFile refuses host trust configuration on unsupported platforms.
func ReadPolicyFile(string) ([]byte, error) {
	return nil, errors.New("release trust requires Linux filesystem ownership")
}
