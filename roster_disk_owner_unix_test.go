//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Gates for Codex P2 4317730264 on PR #1601: a byte-identical roster copy
// that now belongs to another account, in a way that makes the next save's
// rename be refused, is reported as an owner change. Since Codex P2
// 4325019932 every other change outside Culvert (an identical re-copy with
// the same owner, a touch, a chmod, a same-inode xattr) is reported as
// changed externally where the inode stamp is known, and Culvert's own
// saves stay ok.

const otherAccount = 65534 // nobody/nogroup

// installIdenticalCopy replaces path with a new inode holding the same bytes,
// owned by uid:gid, as a configuration manager re-deploying it would.
func installIdenticalCopy(t *testing.T, path string, uid, gid int) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatal(err)
	}
	side := path + ".cm"
	if err := os.WriteFile(side, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(side, uid, gid); err != nil {
		t.Fatalf("chown: %v", err)
	}
	if err := os.Rename(side, path); err != nil {
		t.Fatal(err)
	}
}

// asUnprivileged makes renameLikelyRefused reason as uid 1000 would; the
// tests run as root, whose renames are never refused.
func asUnprivileged(t *testing.T) {
	t.Helper()
	prev := rosterEUID
	rosterEUID = func() uint32 { return 1000 }
	t.Cleanup(func() { rosterEUID = prev })
}

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root to give the roster fixture to another account")
	}
}

// TestRosterIdentity_IdenticalCopyWithAnotherOwnerWarns: in a sticky
// directory owned by someone else, an identical copy owned by another account
// would make the next save be refused, so the row warns with its own message.
// Dropping the owner comparison fails this test.
func TestRosterIdentity_IdenticalCopyWithAnotherOwnerWarns(t *testing.T) {
	needRoot(t)
	_, path := savedRosterCfg(t)
	if err := os.Chmod(filepath.Dir(path), os.ModeSticky|0o777); err != nil { // #nosec G302 -- a sticky shared directory under test
		t.Fatal(err)
	}
	asUnprivileged(t)
	installIdenticalCopy(t, path, otherAccount, otherAccount)

	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetOwnerChanged {
		t.Fatalf("row = %+v, want warn %q", row, rosterTargetOwnerChanged)
	}
	for _, want := range []string{"chown", "-ui-users-file", "restart"} {
		if !strings.Contains(row.OperatorAction, want) {
			t.Errorf("action = %q, want the restore-ownership remedy (%q)", row.OperatorAction, want)
		}
	}
}

// TestRosterIdentity_ChangesOutsideCulvertWarn (Codex P2 4325019932 on PR
// #1601): the evidence of a landed save stands only while the target is the
// untouched inode that save landed. Each of these keeps the bytes, and none
// is reported as replaced content or a refusing owner, yet each is a change
// outside Culvert that could alter whether the next rename is allowed, so
// each is rosterTargetChangedExternally until the next save. (Before this,
// a re-copy, a touch, a chmod and an allowed owner change read ok; that is
// the deliberate behaviour change.) Platforms without an inode stamp keep
// comparing bytes and owner only.
func TestRosterIdentity_ChangesOutsideCulvertWarn(t *testing.T) {
	cases := map[string]func(t *testing.T, path string){
		"identical re-copy, same owner (new inode)": func(t *testing.T, path string) {
			installIdenticalCopy(t, path, os.Geteuid(), os.Getegid())
		},
		"touch": func(t *testing.T, path string) {
			future := time.Now().Add(time.Hour)
			if err := os.Chtimes(path, future, future); err != nil {
				t.Fatal(err)
			}
		},
		"chmod": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o640); err != nil { // #nosec G302 -- fixture mode under test
				t.Fatal(err)
			}
		},
		"same-inode ACL or label change (xattr stand-in)": setSameInodeXattr,
		"another owner in a non-sticky directory": func(t *testing.T, path string) {
			needRoot(t)
			asUnprivileged(t)
			installIdenticalCopy(t, path, otherAccount, otherAccount)
		},
		"another owner, but this process may replace any file": func(t *testing.T, path string) {
			needRoot(t)
			dir := filepath.Dir(path)
			if err := os.Chmod(dir, os.ModeSticky|0o777); err != nil { // #nosec G302 -- a sticky shared directory under test
				t.Fatal(err)
			}
			// Neither the directory nor the file is root's: only root's own
			// exemption keeps this rename permitted.
			if err := os.Chown(dir, otherAccount-1, otherAccount-1); err != nil {
				t.Fatal(err)
			}
			installIdenticalCopy(t, path, otherAccount, otherAccount) // rosterEUID stays root
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c, path := savedRosterCfg(t)
			change(t, path)
			want := rosterTargetChangedExternally
			if !c.uiUsersWritten.stamp.known {
				t.Skip("no inode stamp on this platform; bytes and owner only")
			}
			if row := checkAdminRosterDurability(); row.Status != diagWarn || row.Message != want {
				t.Fatalf("row = %+v, want warn %q", row, want)
			}
			if err := c.SaveUIUsersFile(); err != nil {
				t.Fatal(err)
			}
			if row := checkAdminRosterDurability(); row.Status != diagOK {
				t.Errorf("after the next save: row = %+v, want ok", row)
			}
		})
	}
}

// TestRosterIdentity_CulvertsOwnSavesStayOK: a save, and two saves in a row,
// leave the row ok — Culvert's own writes always re-record the stamp.
func TestRosterIdentity_CulvertsOwnSavesStayOK(t *testing.T) {
	c, _ := savedRosterCfg(t)
	for i := 0; i < 2; i++ {
		if row := checkAdminRosterDurability(); row.Status != diagOK {
			t.Fatalf("after %d save(s): row = %+v, want ok", i+1, row)
		}
		if err := c.SaveUIUsersFile(); err != nil {
			t.Fatal(err)
		}
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Errorf("after two saves in a row: row = %+v, want ok", row)
	}
}

// TestRosterIdentity_RecordsTheLandedFilesOwner (Codex P2 4319694771 on PR
// #1601): an external writer replaces the roster with an identical copy owned
// by another account between the save's rename and its return. The recorded
// owner must be the file Culvert landed (root), not the replacement, so the
// probe sees the change. Recording a stat of the path after the write fails
// this test.
func TestRosterIdentity_RecordsTheLandedFilesOwner(t *testing.T) {
	needRoot(t)
	c, path := savedRosterCfg(t)
	if err := os.Chmod(filepath.Dir(path), os.ModeSticky|0o777); err != nil { // #nosec G302 -- a sticky shared directory under test
		t.Fatal(err)
	}
	asUnprivileged(t)
	prev := rosterAtomicWrite
	rosterAtomicWrite = func(p string, data []byte, perm os.FileMode) (fileutil.WriteResult, error) {
		landed, err := prev(p, data, perm)
		if err == nil {
			installIdenticalCopy(t, p, otherAccount, otherAccount) // wins the race
		}
		return landed, err
	}
	t.Cleanup(func() { rosterAtomicWrite = prev })
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}

	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetOwnerChanged {
		t.Fatalf("row = %+v, want warn %q: the recorded owner must be the landed file's", row, rosterTargetOwnerChanged)
	}
}
