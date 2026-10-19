package main

// roster_disk_identity.go — "the file on disk is still what Culvert last
// wrote" (Codex P2 4317365500 on PR #1601).
//
// The admin_roster_durability row's write evidence (uiUsersWriteTried/Err)
// says a write to the roster path CAN land. It does not say the file still
// holds what Culvert wrote: a configuration manager or an operator can
// replace ui_users.json afterwards, and the row would go on reading
// "persisting to disk" while a restart would load the replacement — possibly
// restoring a revoked account or password, or dropping changes made since.
//
// So every landed write (the boot rewrite, and each roster save) records the
// size and SHA-256 of the exact bytes written, and the row compares the file
// with them. A content hash rather than the inode identity (dev+ino, size,
// mtime): it also catches an in-place edit of the same inode, it does not
// false-alarm on a touch, a chmod or an identical re-copy (none changes what a
// restart loads), and it is cheap here — the roster is small, the size check
// short-circuits a different-length file without reading it, and the row is
// computed at diagnostics rate, not on a hot path.

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"syscall"
)

// rosterWrittenDigest identifies the bytes Culvert last wrote to path.
// The zero value (path "") means no landed write is recorded.
type rosterWrittenDigest struct {
	path string
	size int64
	sum  [sha256.Size]byte
}

func digestRosterWrite(path string, data []byte) rosterWrittenDigest {
	return rosterWrittenDigest{path: path, size: int64(len(data)), sum: sha256.Sum256(data)}
}

// rosterOnDiskDiffers reports whether the roster file at path no longer holds
// the bytes Culvert last wrote to it. It is false when no write to path is
// recorded (nothing to compare). READ-ONLY: it opens the file for reading
// only. saveUIUsersMu is held (lock order saveUIUsersMu → c.mu, as for every
// roster writer) so a save in flight — renamed into place but not yet
// recorded — cannot be mistaken for an external replacement.
func (c *Config) rosterOnDiskDiffers(path string) (bool, error) {
	c.saveUIUsersMu.Lock()
	defer c.saveUIUsersMu.Unlock()
	c.mu.RLock()
	d := c.uiUsersWritten
	c.mu.RUnlock()
	if d.path == "" || d.path != path {
		return false, nil
	}
	// O_NONBLOCK: the path is not trusted to still be a regular file.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-configured -ui-users-file path
	if err != nil {
		return false, err
	}
	defer func() { _ = f.Close() }() // #nosec G104 -- read-only handle
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if !fi.Mode().IsRegular() || fi.Size() != d.size {
		return true, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, d.size+1)); err != nil {
		return false, err
	}
	return !bytes.Equal(h.Sum(nil), d.sum[:]), nil
}

// rosterReplacedProblem is the targetProblem for a roster file that no longer
// holds what Culvert last wrote, "" when it does (or nothing is recorded).
func (c *Config) rosterReplacedProblem(path string) string {
	differs, err := c.rosterOnDiskDiffers(path)
	switch {
	case err != nil:
		return "the configured roster path cannot be inspected"
	case differs:
		return rosterTargetReplaced
	}
	return ""
}
