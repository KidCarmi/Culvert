//go:build linux

package main

import (
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// setSameInodeXattr changes the roster's metadata on the same inode, as a
// setfacl or an SELinux relabel would (a user.* attribute stands in, since
// neither tool is assumed present). Skips where the filesystem refuses it.
func setSameInodeXattr(t *testing.T, path string) {
	t.Helper()
	if err := unix.Setxattr(path, "user.culvert.test", []byte("relabel"), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			t.Skipf("the test filesystem has no user extended attributes (%v)", err)
		}
		t.Fatal(err)
	}
}

// TestRosterIdentity_EachStampFieldIsCompared: a probed file with the landed
// ctime but another inode, or the landed inode with another ctime, is not
// the untouched landed file. No real replacement keeps the ctime, so the
// probed stamp is injected. Dropping the inode or the ctime from the
// comparison fails this test.
func TestRosterIdentity_EachStampFieldIsCompared(t *testing.T) {
	for name, alter := range map[string]func(s *inodeStamp){
		"another inode, same ctime":  func(s *inodeStamp) { s.ino++ },
		"another device, same ctime": func(s *inodeStamp) { s.dev++ },
		"same inode, another ctime":  func(s *inodeStamp) { s.ctime.Nsec = (s.ctime.Nsec + 1) % 1_000_000_000 },
	} {
		t.Run(name, func(t *testing.T) {
			c, _ := savedRosterCfg(t)
			landed := c.uiUsersWritten.stamp
			if !landed.known {
				t.Skip("no inode stamp on this platform")
			}
			prev := rosterStampOf
			rosterStampOf = func(os.FileInfo) inodeStamp {
				s := landed
				alter(&s)
				return s
			}
			t.Cleanup(func() { rosterStampOf = prev })
			if row := checkAdminRosterDurability(); row.Status != diagWarn || row.Message != rosterTargetChangedExternally {
				t.Errorf("row = %+v, want warn %q", row, rosterTargetChangedExternally)
			}
		})
	}
}
