package main

// roster_disk_identity.go — "the file on disk is still what Culvert last
// wrote" (Codex P2s 4317365500, 4317730264 and 4317730279 on PR #1601).
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
//
// A byte-identical copy can still be a problem: installed with another owner
// in a sticky directory, it makes the next save's rename fail with EPERM. So
// the write also records the file's owner, and an identical file whose owner
// changed is reported when the change would make a save be refused
// (renameLikelyRefused). The inode number and mtime are deliberately NOT part
// of the identity: an identical re-copy, a touch or a chmod stays ok.
//
// No disk I/O happens under saveUIUsersMu (Codex P2 4317730279): on a stalled
// NFS or FUSE volume a viewer's diagnostics request would otherwise block
// every roster mutation, TOTP and backup-code logins included. Instead every
// Culvert roster write brackets itself with uiUsersWriteGen (odd while a
// write is in progress, seqlock style): the row snapshots the recorded
// identity and the generation, reads the file with no lock held, and accepts
// the result only if the generation did not move. A moved generation means a
// Culvert write raced the read: it retries once, and if the generation moves
// again it reports the file as in flux (ok) rather than a false "replaced".
// At most one identity read is in flight at a time (rosterIdentityFlight), so
// concurrent requests on a stalled volume share one blocked read instead of
// each starting another.

import (
	"bytes"
	"crypto/sha256"
	"io"
	"os"
	"sync"
	"syscall"
)

// rosterWrittenDigest identifies what Culvert last wrote to path. The zero
// value (path "") means no landed write is recorded.
type rosterWrittenDigest struct {
	path  string
	size  int64
	sum   [sha256.Size]byte
	owner fileOwnerID // the file's owner after the write; owner.known false where the platform has none
}

func digestRosterWrite(path string, data []byte, owner fileOwnerID) rosterWrittenDigest {
	return rosterWrittenDigest{path: path, size: int64(len(data)), sum: sha256.Sum256(data), owner: owner}
}

// rosterDiskVerdict is what the identity read found.
type rosterDiskVerdict int

const (
	rosterDiskSame         rosterDiskVerdict = iota // what Culvert wrote, or nothing to compare, or in flux
	rosterDiskReplaced                              // different content: replaced or edited outside Culvert
	rosterDiskOwnerChanged                          // same content, another owner a save may be refused over
)

// beginRosterWrite and endRosterWrite bracket every Culvert write to the
// roster file (saveUIUsersMu held, so writers never interleave): the
// generation is odd while one is in progress and moves with each.
func (c *Config) beginRosterWrite() { c.uiUsersWriteGen.Add(1) }
func (c *Config) endRosterWrite()   { c.uiUsersWriteGen.Add(1) }

// rosterIdentityOpen opens the roster for the identity read. A seam only for
// tests, which block it to stand in for a stalled volume. O_NONBLOCK: the
// path is not trusted to still be a regular file.
var rosterIdentityOpen = func(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- operator-configured -ui-users-file path
}

// rosterIdentityFlight lets at most one identity read of a given roster be in
// flight; callers that arrive meanwhile for the same Config and path wait for
// its result instead of starting their own.
var rosterIdentityFlight struct {
	mu      sync.Mutex
	pending *rosterIdentityCall
}

type rosterIdentityCall struct {
	c       *Config
	path    string
	done    chan struct{}
	verdict rosterDiskVerdict
	err     error
}

// rosterDiskState reports how the roster file at path compares with what
// Culvert last wrote to it. It never holds saveUIUsersMu.
func (c *Config) rosterDiskState(path string) (rosterDiskVerdict, error) {
	rosterIdentityFlight.mu.Lock()
	if call := rosterIdentityFlight.pending; call != nil && call.c == c && call.path == path {
		rosterIdentityFlight.mu.Unlock()
		<-call.done
		return call.verdict, call.err
	}
	call := &rosterIdentityCall{c: c, path: path, done: make(chan struct{})}
	owner := rosterIdentityFlight.pending == nil
	if owner {
		rosterIdentityFlight.pending = call
	}
	rosterIdentityFlight.mu.Unlock()

	call.verdict, call.err = c.rosterDiskStateOnce(path)

	if owner {
		rosterIdentityFlight.mu.Lock()
		rosterIdentityFlight.pending = nil
		rosterIdentityFlight.mu.Unlock()
	}
	close(call.done)
	return call.verdict, call.err
}

// rosterDiskStateOnce is one generation-checked identity read, retried once
// if a Culvert write raced it.
func (c *Config) rosterDiskStateOnce(path string) (rosterDiskVerdict, error) {
	for attempt := 0; attempt < 2; attempt++ {
		gen := c.uiUsersWriteGen.Load()
		if gen%2 == 1 {
			continue // a Culvert write is in progress
		}
		c.mu.RLock()
		d := c.uiUsersWritten
		c.mu.RUnlock()
		verdict, err := readRosterIdentity(path, d) // disk I/O: no lock held
		if c.uiUsersWriteGen.Load() == gen {
			return verdict, err
		}
	}
	return rosterDiskSame, nil // in flux: Culvert itself is writing it
}

// readRosterIdentity compares the file at path with d. READ-ONLY.
func readRosterIdentity(path string, d rosterWrittenDigest) (rosterDiskVerdict, error) {
	if d.path == "" || d.path != path {
		return rosterDiskSame, nil
	}
	f, err := rosterIdentityOpen(path)
	if err != nil {
		return rosterDiskSame, err
	}
	defer func() { _ = f.Close() }() // #nosec G104 -- read-only handle
	fi, err := f.Stat()
	if err != nil {
		return rosterDiskSame, err
	}
	if !fi.Mode().IsRegular() || fi.Size() != d.size {
		return rosterDiskReplaced, nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, d.size+1)); err != nil {
		return rosterDiskSame, err
	}
	if !bytes.Equal(h.Sum(nil), d.sum[:]) {
		return rosterDiskReplaced, nil
	}
	if now := ownerOf(fi); d.owner.known && now.known && now.uid != d.owner.uid && renameLikelyRefused(path, now) {
		return rosterDiskOwnerChanged, nil
	}
	return rosterDiskSame, nil
}

// rosterReplacedProblem is the targetProblem for a roster file that no longer
// matches what Culvert last wrote, "" when it does (or nothing is recorded).
func (c *Config) rosterReplacedProblem(path string) string {
	verdict, err := c.rosterDiskState(path)
	switch {
	case err != nil:
		return "the configured roster path cannot be inspected"
	case verdict == rosterDiskReplaced:
		return rosterTargetReplaced
	case verdict == rosterDiskOwnerChanged:
		return rosterTargetOwnerChanged
	}
	return ""
}
