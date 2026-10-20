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
// The comparison runs inside the row's one live filesystem probe
// (roster_probe.go), with no roster lock held: every Culvert roster write
// brackets itself with beginRosterWrite/endRosterWrite (uiUsersWriteGen moves
// at both ends, uiUsersWritesInFlight counts writers — two can overlap now
// that the boot rewrite runs in the background), and the probe accepts its
// identity result only if no write was in flight and the generation did not
// move.

import "crypto/sha256"

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
// roster file: a save (saveUIUsersMu held) and the background boot rewrite
// (not, so the two can overlap). The generation moves at both ends; the
// in-flight count is non-zero while any is in progress.
func (c *Config) beginRosterWrite() {
	c.uiUsersWritesInFlight.Add(1)
	c.uiUsersWriteGen.Add(1)
}

func (c *Config) endRosterWrite() {
	c.uiUsersWriteGen.Add(1)
	c.uiUsersWritesInFlight.Add(-1)
}

// rosterWriteQuiet reports the generation if no Culvert roster write is in
// progress, and false otherwise.
func (c *Config) rosterWriteQuiet() (uint64, bool) {
	gen := c.uiUsersWriteGen.Load()
	return gen, c.uiUsersWritesInFlight.Load() == 0
}
