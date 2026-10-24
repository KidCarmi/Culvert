//go:build linux

package main

import (
	"os"
	"syscall"
)

// inodeStamp is the identity of one unchanged inode: its device, inode number
// and ctime. Any change to the inode — its content, mode, owner, ACL,
// security label, extended attributes or link count — moves the ctime, and a
// replacement is another inode, so an unchanged stamp means "the very file
// Culvert landed, untouched since".
type inodeStamp struct {
	dev, ino uint64
	ctime    syscall.Timespec
	known    bool
}

func stampOf(fi os.FileInfo) inodeStamp {
	if fi == nil {
		return inodeStamp{}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return inodeStamp{dev: st.Dev, ino: st.Ino, ctime: st.Ctim, known: true}
	}
	return inodeStamp{}
}
