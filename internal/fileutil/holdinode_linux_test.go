//go:build linux

package fileutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestAtomicWriteInfo_LandedIsThePostRenameInode: WriteResult.Landed is the
// inode now at path as it is AFTER the rename — same dev/ino and the ctime
// the rename set — so a caller can later tell its own landed file from any
// change. Taking the fstat before the rename (the rename moves ctime) fails
// this test.
func TestAtomicWriteInfo_LandedIsThePostRenameInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "f.json")
	for i := 0; i < 3; i++ { // the first write creates; later ones replace
		res, err := AtomicWriteInfo(path, []byte("x"), 0o600)
		if err != nil || res.Landed == nil {
			t.Fatalf("AtomicWriteInfo = (%+v, %v)", res, err)
		}
		now, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !os.SameFile(res.Landed, now) {
			t.Fatal("Landed is not the inode at the path")
		}
		a, b := res.Landed.Sys().(*syscall.Stat_t), now.Sys().(*syscall.Stat_t)
		if a.Ctim != b.Ctim {
			t.Errorf("write %d: Landed ctime %v, the file's ctime %v: Landed predates the rename", i, a.Ctim, b.Ctim)
		}
	}
}
