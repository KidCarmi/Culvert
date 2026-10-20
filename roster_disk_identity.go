package main

// roster_disk_identity.go — "the file on disk is still what Culvert last
// wrote" (Codex P2s 4317365500, 4317730264 and 4317730279 on PR #1601).
//
// The admin_roster_durability row's write evidence (uiUsersWriteLanded)
// says a write to the roster path landed. It does not say the file still
// holds what Culvert wrote: a configuration manager or an operator can
// replace ui_users.json afterwards, and the row would go on reporting the
// last save as on disk while a restart would load the replacement — possibly
// restoring a revoked account or password, or dropping changes made since.
//
// So every landed roster save records the size and SHA-256 of the exact
// bytes written, and the row compares the file with them. The content hash
// catches an in-place edit of the same inode, and it is cheap here — the
// roster is small, the size check short-circuits a different-length file
// without reading it, and the row is computed at diagnostics rate, not on a
// hot path.
//
// Identical bytes are not enough (Codex P2s 4317730264 and 4325019932 on PR
// #1601): a same-UID replacement, or a same-inode SELinux label or NFSv4 ACL
// change, can deny the next rename while the content is unchanged — and the
// list of replacement-relevant attributes has no end. So the evidence of a
// landed write is valid ONLY while the target is exactly the inode Culvert
// landed and unchanged since: each landed write also records the inode's
// dev, ino and ctime (inodeStamp; the landed descriptor's fstat AFTER the
// rename, which itself sets the ctime), and any difference is
// rosterDiskChangedExternally. The more specific verdicts come first: other
// content is rosterDiskReplaced, and an identical file now owned by another
// account where the next rename would be refused is rosterDiskOwnerChanged.
// A touch, a chmod, an identical re-copy or an xattr/ACL change therefore
// warns too, deliberately: persistence is re-verified by the next save. On
// platforms without an inode stamp (roster_disk_stamp_other.go) only size,
// hash and owner are compared.
//
// The comparison runs inside the row's one live filesystem probe
// (roster_probe.go), with no roster lock held: every Culvert roster write
// brackets itself with beginRosterWrite/endRosterWrite (uiUsersWriteGen moves
// at both ends, uiUsersWritesInFlight counts writers in progress), and the
// probe accepts its
// identity result only if no write was in flight and the generation did not
// move.

import (
	"crypto/sha256"
	"os"
)

// rosterWrittenDigest identifies what Culvert last wrote to path. The zero
// value (path "") means no landed write is recorded.
type rosterWrittenDigest struct {
	path  string
	size  int64
	sum   [sha256.Size]byte
	owner fileOwnerID // the file's owner after the write; owner.known false where the platform has none
	stamp inodeStamp  // dev, ino and ctime of the landed inode; stamp.known false where the platform has none
}

// digestRosterWrite records data as written to path; landed is the landed
// file's own FileInfo (fileutil.WriteResult.Landed), nil if unknown.
func digestRosterWrite(path string, data []byte, landed os.FileInfo) rosterWrittenDigest {
	d := rosterWrittenDigest{path: path, size: int64(len(data)), sum: sha256.Sum256(data)}
	if landed != nil {
		d.owner, d.stamp = ownerOf(landed), stampOf(landed)
	}
	return d
}

// rosterDiskVerdict is what the identity read found.
type rosterDiskVerdict int

const (
	rosterDiskSame              rosterDiskVerdict = iota // what Culvert wrote, or nothing to compare, or in flux
	rosterDiskReplaced                                   // different content: replaced or edited outside Culvert
	rosterDiskOwnerChanged                               // same content, another owner a save may be refused over
	rosterDiskChangedExternally                          // same content and owner, but not the untouched inode Culvert landed
)

// beginRosterWrite and endRosterWrite bracket every Culvert write to the
// roster file (a save, or a corrupt roster's quarantine on load). The
// generation moves at both ends; the in-flight count is non-zero while any
// is in progress.
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
