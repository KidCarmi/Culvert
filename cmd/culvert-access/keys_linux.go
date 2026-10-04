//go:build linux

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/applianceaccess"
	"golang.org/x/sys/unix"
)

const importedKeys = "/home/culvert/.ssh/authorized_keys"
const operatorKeys = "/etc/ssh/culvert-authorized-keys/culvert-operator"

func importKeys(parent context.Context) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("root provisioning required")
	}
	u, err := user.Lookup("culvert")
	if err != nil {
		return errors.New("local account unavailable")
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil || uid == 0 {
		return errors.New("invalid local account")
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil || gid == 0 {
		return errors.New("invalid local account group")
	}
	data, err := readImportedKeys(parent, uint32(uid), uint32(gid), importedKeys)
	if err != nil {
		return err
	}
	canonical, err := applianceaccess.CanonicalKeys(data)
	if err != nil {
		return err
	}
	return publishOperatorKeys(operatorKeys, canonical)
}

func readImportedKeys(parent context.Context, uid, gid uint32, source string) ([]byte, error) {
	// Metadata only. Content is always read by the unprivileged account, even
	// if a user-controlled component is a symlink, FIFO or replaced mid-read.
	if _, err := os.Lstat(source); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, errors.New("key source metadata unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	// #nosec G204 G702 -- source is the fixed importedKeys path in production;
	// argv is never a shell command, and the child loses root before opening it.
	cmd := exec.CommandContext(ctx, "/usr/bin/cat", "--", source)
	cmd.Dir, cmd.Env = "/", applianceaccess.Environment()
	cmd.Stdin, cmd.Stderr = nil, io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}, Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = 250 * time.Millisecond
	var output keyOutput
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil || output.overflow {
		return nil, errors.New("bounded unprivileged key read failed")
	}
	return output.data, nil
}

type keyOutput struct {
	data     []byte
	overflow bool
}

func (b *keyOutput) Write(p []byte) (int, error) {
	remaining := max(0, applianceaccess.MaxKeyBytes-len(b.data))
	if len(p) > remaining {
		b.overflow = true
	}
	b.data = append(b.data, p[:min(len(p), remaining)]...)
	return len(p), nil
}

func safeKeyAncestors(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("absolute authorization path required")
	}
	for at := path; ; at = filepath.Dir(at) {
		var st unix.Stat_t
		if err := unix.Lstat(at, &st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
			return errors.New("unsafe authorization directory")
		}
		if at == "/" {
			return nil
		}
	}
}

func publishOperatorKeys(target string, data []byte) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("root publication required")
	}
	directory := filepath.Dir(target)
	if err := safeKeyAncestors(filepath.Dir(directory)); err != nil {
		return err
	}
	if err := os.Mkdir(directory, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := safeKeyAncestors(directory); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		return err
	}
	var existing unix.Stat_t
	if err := unix.Lstat(target, &existing); err == nil {
		if existing.Mode&unix.S_IFMT != unix.S_IFREG || existing.Uid != 0 || existing.Nlink != 1 || existing.Mode&0o022 != 0 {
			return errors.New("unsafe authorization target")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	return writeOperatorKeys(target, data)
}

// All target/ancestor validation precedes this atomic replacement. Only root
// can write the publication directory; user-controlled source paths are absent.
func writeOperatorKeys(target string, data []byte) error {
	directory := filepath.Dir(target)
	f, err := os.CreateTemp(directory, ".operator-keys-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o644)
	}
	if err == nil {
		err = f.Chown(0, 0)
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(f.Name(), target); err != nil {
		return err
	}
	if err := syncKeyDirectory(directory); err != nil {
		return err
	}
	return syncKeyDirectory(filepath.Dir(directory))
}

func syncKeyDirectory(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
