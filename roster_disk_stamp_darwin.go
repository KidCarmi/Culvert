//go:build darwin

package main

import (
	"os"
	"syscall"
)

// inodeStamp is the identity of one unchanged inode (see the Linux file).
type inodeStamp struct {
	dev   int32
	ino   uint64
	ctime syscall.Timespec
	known bool
}

func stampOf(fi os.FileInfo) inodeStamp {
	if fi == nil {
		return inodeStamp{}
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return inodeStamp{dev: st.Dev, ino: st.Ino, ctime: st.Ctimespec, known: true}
	}
	return inodeStamp{}
}
