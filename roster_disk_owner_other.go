//go:build !unix

package main

import "os"

// fileOwnerID is a file's owner, where the platform has one (not here).
type fileOwnerID struct {
	uid, gid uint32
	known    bool
}

func ownerOf(os.FileInfo) fileOwnerID { return fileOwnerID{} }

// renameLikelyRefused: there is no POSIX owner here, so an owner change is
// never reported.
func renameLikelyRefused(os.FileInfo, error, fileOwnerID) bool { return false }
