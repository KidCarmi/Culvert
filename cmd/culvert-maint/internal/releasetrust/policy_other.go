//go:build !linux

package releasetrust

import (
	"errors"
	"os"
)

func privateFileOwner(os.FileInfo, int) bool { return false }

func privateDirectory(string, int) error {
	return errors.New("release trust requires Linux filesystem ownership")
}

func directoryOwner(string) (uid, gid int, err error) {
	return 0, 0, errors.New("release trust requires Linux filesystem ownership")
}

// ReadPolicyFile refuses host trust configuration on unsupported platforms.
func ReadPolicyFile(string) ([]byte, error) {
	return nil, errors.New("release trust requires Linux filesystem ownership")
}
