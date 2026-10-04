//go:build linux

package releasetrust

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// privateDirectory requires path to be a private directory owned by owner
// (the agent identity) with no replaceable ancestor. The agent passes its own
// euid; root-run recovery passes the uid that owns the agent's state.
func privateDirectory(path string, owner int) error {
	i, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() || i.Mode().Perm()&0o077 != 0 || int64(st.Uid) != int64(owner) {
		return errors.New("release trust: state directory must be private and agent-owned")
	}
	return stateAncestors(filepath.Dir(path), owner)
}

// directoryOwner reports the uid/gid owning path (not following a symlink).
func directoryOwner(path string) (uid, gid int, err error) {
	i, err := os.Lstat(path)
	if err != nil {
		return 0, 0, err
	}
	st, ok := i.Sys().(*syscall.Stat_t)
	if !ok || !i.IsDir() {
		return 0, 0, errors.New("release trust: state directory must be a real directory")
	}
	return int(st.Uid), int(st.Gid), nil
}

func stateAncestors(path string, owner int) error {
	for p := path; ; p = filepath.Dir(p) {
		i, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || !i.IsDir() || (st.Uid != 0 && int64(st.Uid) != int64(owner)) {
			return errors.New("release trust: unsafe state ancestor")
		}
		// A root-owned sticky directory (/tmp) protects an agent-owned
		// immediate child against replacement by other users. All descendants
		// are still checked; arbitrary writable ancestors remain forbidden.
		if i.Mode().Perm()&0o022 != 0 && (st.Uid != 0 || i.Mode()&os.ModeSticky == 0) {
			return errors.New("release trust: writable state ancestor")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return nil
}

func privateFileOwner(i os.FileInfo, owner int) bool {
	st, ok := i.Sys().(*syscall.Stat_t)
	return ok && int64(st.Uid) == int64(owner)
}

// ReadPolicyFile accepts only root-controlled files and ancestor directories.
// The agent must not accept trust material replaceable by its socket callers.
func ReadPolicyFile(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("release trust: policy path must be absolute")
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		i, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || i.Mode().Perm()&0o022 != 0 || i.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("release trust: policy path must be root-controlled")
		}
		if p == filepath.Clean(path) {
			if !i.Mode().IsRegular() || i.Size() > 1<<20 {
				return nil, errors.New("release trust: invalid policy file")
			}
		} else if !i.IsDir() {
			return nil, errors.New("release trust: invalid policy directory")
		}
		if p == filepath.Dir(p) {
			break
		}
	}
	return os.ReadFile(path)
}
