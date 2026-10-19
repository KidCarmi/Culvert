//go:build unix

package main

import (
	"math"
	"os"
	"path/filepath"
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
// a new file over path — would be refused because the file now belongs to
// another account. It covers the one case rename(2) decides by the TARGET's
// owner: a sticky directory, where only the file's owner, the directory's
// owner or a process with CAP_FOWNER may replace it. Root (approximating
// CAP_FOWNER) is never refused; nor is the file's or the directory's owner;
// nor is anyone in a non-sticky directory, where only the directory's own
// permissions count — and those were proven by the write being compared
// against. Group ownership plays no part. Any doubt (the directory cannot be
// inspected) is reported as refused.
func renameLikelyRefused(path string, now fileOwnerID) bool {
	euid := rosterEUID()
	if euid == 0 || now.uid == euid {
		return false
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		return true
	}
	if di.Mode()&os.ModeSticky == 0 {
		return false
	}
	dir := ownerOf(di)
	return !dir.known || dir.uid != euid
}
