//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceconsole"
	"golang.org/x/sys/unix"
)

const bootstrapDirectory = "/var/lib/culvert-console/bootstrap"
const bootstrapComplete = "/var/lib/culvert-appliance/state/console.done"

type bootstrapRecord struct {
	Version int    `json:"version"`
	Initial string `json:"initial"`
	Shadow  string `json:"shadow"`
	Ready   bool   `json:"ready"`
}

type bootstrapStore struct {
	directory string
	shadow    string
}

func validBootstrapPassword(password string) bool {
	if len(password) != 16 {
		return false
	}
	for _, ch := range password {
		if !strings.ContainsRune("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789", ch) {
			return false
		}
	}
	return true
}

// No credential is accepted in argv, environment, logs or public observations.
func recordBootstrap(parent context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("bootstrap recording requires root")
	}
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	password, err := bootstrapInput(ctx, int(os.Stdin.Fd()))
	if err != nil {
		return errors.New("bootstrap credential input unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	store := bootstrapStore{bootstrapDirectory, "/etc/shadow"}
	return store.producerLock(ctx, true, func() error { return store.save(password) })
}

func bootstrapInput(ctx context.Context, fd int) (string, error) {
	var input []byte
	for len(input) < 18 {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		// #nosec G115 -- supplied descriptor is an open local pipe.
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		n, err := unix.Poll(poll, 50)
		if errors.Is(err, unix.EINTR) || n == 0 {
			continue
		}
		if err != nil {
			return "", err
		}
		var b [1]byte
		n, err = unix.Read(fd, b[:])
		if err != nil {
			return "", err
		}
		if n == 0 {
			password := strings.TrimSuffix(string(input), "\n")
			if validBootstrapPassword(password) {
				return password, nil
			}
			break
		}
		input = append(input, b[0])
	}
	return "", errors.New("invalid bootstrap input")
}

func bootstrapAncestors(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("bootstrap path must be absolute")
	}
	for at := path; ; at = filepath.Dir(at) {
		var st unix.Stat_t
		if err := unix.Lstat(at, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return errors.New("unsafe bootstrap directory")
		}
		if at == "/" {
			return nil
		}
	}
}

func (s bootstrapStore) withLock(create bool, fn func() error) error {
	if os.Geteuid() != 0 {
		return errors.New("bootstrap access requires root")
	}
	if create {
		if err := bootstrapMakeDirectory(filepath.Dir(s.directory)); err != nil {
			return err
		}
		if err := bootstrapMakeDirectory(s.directory); err != nil {
			return err
		}
	}
	if err := bootstrapAncestors(s.directory); err != nil {
		return err
	}
	st, err := os.Lstat(s.directory)
	if err != nil || st.Mode().Perm() != 0o700 {
		return errors.New("unsafe bootstrap permissions")
	}
	fd, err := unix.Open(filepath.Join(s.directory, "lock"), unix.O_CREAT|unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	if err := bootstrapFileMode(fd, true); err != nil {
		return err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return err
	}
	defer func() { _ = unix.Flock(fd, unix.LOCK_UN) }()
	return fn()
}

// Producers tolerate a reader's brief lock without failing automatic first boot.
// UI and cleanup retain their nonblocking behavior through withLock directly.
func (s bootstrapStore) producerLock(ctx context.Context, create bool, fn func() error) error {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := s.withLock(create, func() error {
			if err := ctx.Err(); err != nil {
				return err
			}
			return fn()
		})
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}

func bootstrapMakeDirectory(path string) error {
	if err := bootstrapAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := bootstrapAncestors(path); err != nil {
		return err
	}
	// Persist the directory entry, not just later files inside the directory.
	return bootstrapSync(filepath.Dir(path))
}

func bootstrapFileMode(fd int, private bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0o022 != 0 {
		return errors.New("unsafe bootstrap file")
	}
	if private && st.Mode&0o777 != 0o600 {
		return errors.New("unsafe bootstrap file permissions")
	}
	return nil
}

func bootstrapRead(path string, limit int, private bool) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	if err := bootstrapFileMode(fd, private); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if len(data) > limit {
		return nil, errors.New("bootstrap file exceeds bound")
	}
	return data, err
}

func (s bootstrapStore) shadowHash() (hash string, forced bool, result error) {
	if err := bootstrapAncestors(filepath.Dir(s.shadow)); err != nil {
		return "", false, err
	}
	data, err := bootstrapRead(s.shadow, 128*1024, false)
	if err != nil {
		return "", false, err
	}
	seen := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if fields[0] != "culvert" {
			continue
		}
		if len(fields) != 9 || seen {
			return "", false, errors.New("ambiguous bootstrap account")
		}
		seen = true
		hash, forced = fields[1], fields[2] == "0"
	}
	if hash == "" || len(hash) > 1024 || !strings.HasPrefix(hash, "$") {
		return "", false, errors.New("bootstrap account unavailable")
	}
	return hash, forced, nil
}

func (s bootstrapStore) save(password string) error {
	if !validBootstrapPassword(password) {
		return errors.New("invalid bootstrap credential")
	}
	hash, forced, err := s.shadowHash()
	if err != nil {
		return err
	}
	if !forced {
		return errors.New("bootstrap account must require password change")
	}
	data, err := json.Marshal(bootstrapRecord{Version: 1, Initial: password, Shadow: hash})
	if err != nil {
		return err
	}
	return s.publish(data)
}

func (s bootstrapStore) publish(data []byte) error {
	path := filepath.Join(s.directory, "credential.json")
	if _, err := bootstrapRead(path, 2048, true); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(s.directory, ".pending-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(data); err == nil {
		err = f.Chmod(0o600)
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
	return bootstrapSync(s.directory)
}

func bootstrapSync(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s bootstrapStore) pending() (string, error) {
	data, err := bootstrapRead(filepath.Join(s.directory, "credential.json"), 2048, true)
	if err != nil {
		return "", err
	}
	var record bootstrapRecord
	if json.Unmarshal(data, &record) != nil || record.Version != 1 || !validBootstrapPassword(record.Initial) {
		return "", errors.New("invalid bootstrap record")
	}
	hash, forced, err := s.shadowHash()
	if err != nil {
		return "", err
	}
	if forced && hash == record.Shadow {
		if record.Ready {
			return record.Initial, nil
		}
		return "", nil
	}
	if err := os.Remove(filepath.Join(s.directory, "credential.json")); err != nil {
		return "", err
	}
	return "", bootstrapSync(s.directory)
}

// Commit can be retried after console.done without re-minting a password.
// The private ready bit is published only after the provisioning checkpoint is
// durable; a reader can never reveal a credential backed only by a cached touch.
func recordBootstrapCommit(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	store := bootstrapStore{bootstrapDirectory, "/etc/shadow"}
	err := store.producerLock(ctx, false, func() error { return store.commit(bootstrapComplete) })
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (s bootstrapStore) commit(complete string) error {
	data, err := bootstrapRead(filepath.Join(s.directory, "credential.json"), 2048, true)
	if err != nil {
		return err
	}
	var record bootstrapRecord
	if json.Unmarshal(data, &record) != nil || record.Version != 1 || !validBootstrapPassword(record.Initial) {
		return errors.New("invalid bootstrap record")
	}
	if err := bootstrapAncestors(filepath.Dir(complete)); err != nil {
		return err
	}
	if _, err := bootstrapRead(complete, 128, false); err != nil {
		return errors.New("bootstrap completion checkpoint unavailable")
	}
	if err := bootstrapSync(complete); err != nil {
		return err
	}
	if err := bootstrapSync(filepath.Dir(complete)); err != nil {
		return err
	}
	record.Ready = true
	data, err = json.Marshal(record)
	if err != nil {
		return err
	}
	return s.publish(data)
}

// Called only after terminal authorization; this secret never enters Snapshot.
func bootstrapPassword() string {
	store := bootstrapStore{bootstrapDirectory, "/etc/shadow"}
	return store.visible(bootstrapComplete)
}

func (s bootstrapStore) visible(complete string) string {
	if err := bootstrapAncestors(filepath.Dir(complete)); err != nil {
		return ""
	}
	if _, err := bootstrapRead(complete, 128, false); err != nil {
		return ""
	}
	var password string
	err := s.withLock(false, func() error {
		var err error
		password, err = s.pending()
		return err
	})
	if err != nil {
		return ""
	}
	return password
}

// The root worker can clear a consumed handoff even while a PAM session runs.
func cleanupBootstrap() error {
	store := bootstrapStore{bootstrapDirectory, "/etc/shadow"}
	err := store.withLock(false, func() error { _, err := store.pending(); return err })
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func bootstrapRows(password string, height, width int) []applianceconsole.Row {
	lines := []string{"INITIAL CONSOLE ACCESS", "User: culvert", "One-time password:", password, "L/F2 Sign in", "Change the password at first login.", "", "No password or SSH key was supplied at import.", "This password remains here until changed.", "SSH password login is disabled."}
	if height < 6 || width < 18 {
		lines = []string{"Resize to 18x6", "L/F2 Sign in"}
	}
	rows := make([]applianceconsole.Row, max(0, min(height, 25)-1))
	for i := range rows {
		if i < len(lines) {
			rows[i].Text = applianceconsole.Clean(lines[i], max(0, min(width, 80)-1))
		}
	}
	return rows
}
