//go:build linux

package appliancehost

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const stateLimit = 256 * 1024

// Store uses a private, root-owned directory. Lock contention fails promptly.
type Store struct{ Directory string }

func secureDirectory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) {
		return errors.New("host store requires an absolute path")
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	for at := path; ; at = filepath.Dir(at) {
		st, err := os.Lstat(at)
		if err != nil {
			return err
		}
		var raw unix.Stat_t
		if err := unix.Lstat(at, &raw); err != nil {
			return err
		}
		if !st.IsDir() || raw.Uid != 0 || st.Mode().Perm()&0o022 != 0 {
			return errors.New("host store ancestors must be root-owned directories without group/other write access")
		}
		if at == "/" {
			break
		}
	}
	return nil
}

func readRegular(path string, limit int, private bool) (content []byte, mode os.FileMode, result error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, 0, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nil, 0, err
	}
	mask := uint32(0o022)
	if private {
		mask = 0o077
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Mode&mask != 0 || st.Nlink != 1 {
		return nil, 0, errors.New("unsafe host state file")
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(data) > limit {
		return nil, 0, errors.New("host state file exceeds size limit")
	}
	return data, os.FileMode(st.Mode & 0o777), err
}

func syncDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func atomicFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".culvert-stage-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// WithLock refuses corrupt/unknown state instead of silently resetting recovery.
func (s Store) WithLock(fn func(*Session) error) error {
	if err := secureDirectory(filepath.Dir(s.Directory), 0o755); err != nil {
		return err
	}
	// The worker's restrictive umask must not make sanitized status unreadable.
	// Ownership/ancestor checks above precede the explicit public directory mode.
	if err := publicDirectoryMode(filepath.Dir(s.Directory)); err != nil {
		return err
	}
	if err := secureDirectory(s.Directory, 0o700); err != nil {
		return err
	}
	st, err := os.Stat(s.Directory)
	if err != nil || st.Mode().Perm() != 0o700 {
		return errors.New("host store must have mode 0o700")
	}
	fd, err := unix.Open(filepath.Join(s.Directory, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	var lockStat unix.Stat_t
	if err := unix.Fstat(fd, &lockStat); err != nil {
		return err
	}
	if lockStat.Mode&unix.S_IFMT != unix.S_IFREG || lockStat.Uid != 0 || lockStat.Mode&0o077 != 0 || lockStat.Nlink != 1 {
		return errors.New("unsafe lock file")
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("host recovery busy: %w", err)
	}
	state, err := s.load()
	if err != nil {
		return err
	}
	session := &Session{State: state, Save: s.save}
	return fn(session)
}

func publicDirectoryMode(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm() == 0o755 {
		return nil
	}
	return os.Chmod(path, 0o755)
}

func (s Store) load() (State, error) {
	var state State
	data, _, err := readRegular(filepath.Join(s.Directory, "state.json"), stateLimit, true)
	switch {
	case err == nil:
		if err = json.Unmarshal(data, &state); err != nil {
			return state, errors.New("corrupt host recovery state; preserve for recovery")
		}
	case !errors.Is(err, os.ErrNotExist):
		return state, err
	default:
		state.Version = 1
	}
	return state, validateState(state)
}

func validateState(state State) error {
	if state.Version != 1 || len(state.Records) > 64 {
		return errors.New("unsupported host recovery state")
	}
	if t := state.Network; t != nil {
		switch t.Phase {
		case "queued", "applying", "testing", "rolling_back", "rolled_back", "confirmed", "conflict", "external_kept":
		default:
			return errors.New("unknown network recovery phase")
		}
		if len(t.ID) != 32 || t.Boot == "" || t.Deadline <= 0 || len(t.Candidate.Data) > 65536 || len(t.Original.Data) > 65536 {
			return errors.New("invalid network recovery state")
		}
	}
	return nil
}

func (s Store) save(state State) error {
	if err := validateState(state); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(data) > stateLimit {
		return errors.New("host recovery history exceeds size limit")
	}
	return atomicFile(filepath.Join(s.Directory, "state.json"), data, 0o600)
}

// Publish omits network configuration/backup data; it is explicitly an observation.
func (s Store) Publish(state State, path string) error {
	view := struct {
		Version      int           `json:"version"`
		Records      []Record      `json:"records"`
		NetworkID    string        `json:"network_id,omitempty"`
		NetworkPhase string        `json:"network_phase,omitempty"`
		Verification *Verification `json:"verification,omitempty"`
	}{Version: 1, Records: state.Records}
	if t := state.Network; t != nil {
		view.NetworkID, view.NetworkPhase = t.ID, t.Phase
		view.Verification = &t.Verification
	}
	data, err := json.Marshal(view)
	if err != nil {
		return err
	}
	if err := secureDirectory(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	previous, mode, err := readRegular(path, 65536, false)
	if err == nil && mode == 0o644 && bytes.Equal(previous, data) {
		return nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return atomicFile(path, data, 0o644)
}

// PublishCurrent reloads durable state while the caller still holds WithLock.
// A failed save must never expose the session's uncommitted in-memory phase.
func (s Store) PublishCurrent(path string) error {
	state, err := s.load()
	if err != nil {
		return err
	}
	return s.Publish(state, path)
}

// ReadIdentity reads a fixed root-owned identity file without following links,
// blocking on FIFOs or accepting unbounded content.
func ReadIdentity(path string) ([]byte, error) {
	data, _, err := readRegular(path, 64, false)
	return data, err
}
