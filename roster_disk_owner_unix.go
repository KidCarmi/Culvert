//go:build unix

package main

import (
	"math"
	"os"
	"syscall"
)

// fileOwnerID is a file's owner, where the platform has one.
type fileOwnerID struct {
	uid, gid uint32
	known    bool
}

func ownerOf(fi os.FileInfo) fileOwnerID {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fileOwnerID{uid: st.Uid, gid: st.Gid, known: true}
	}
	return fileOwnerID{}
}

// rosterEUID is the effective uid renameLikelyRefused reasons about. A seam
// only for tests, which run as root (whose renames are never refused).
var rosterEUID = func() uint32 {
	id := os.Geteuid()
	if id < 0 || id > math.MaxUint32 {
		return math.MaxUint32 // not a real uid: never root, never an owner
	}
	return uint32(id)
}

// renameLikelyRefused predicts whether this process's next save — a rename of
// a new file over the roster — would be refused because the file now belongs
// to another account. It covers the one case rename(2) decides by the
// TARGET's owner: a sticky directory, where only the file's owner, the
// directory's owner or a process with CAP_FOWNER may replace it. Root
// (approximating CAP_FOWNER) is never refused; nor is the file's or the
// directory's owner; nor is anyone in a non-sticky directory, where only the
// directory's own write and search permission count (probeRosterParent checks
// those live). Group ownership plays no part. dir is the probe's stat of the
// parent directory; any doubt (it could not be inspected) is reported as
// refused. No I/O: the probe supplies dir.
func renameLikelyRefused(dir os.FileInfo, dirErr error, now fileOwnerID) bool {
	euid := rosterEUID()
	if euid == 0 || now.uid == euid {
		return false
	}
	if dirErr != nil || dir == nil {
		return true
	}
	if dir.Mode()&os.ModeSticky == 0 {
		return false
	}
	owner := ownerOf(dir)
	return !owner.known || owner.uid != euid
}
