package main

import (
	"os"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Gate for Codex P1 4319946917 on PR #1601 at the row: the roster path keeps
// the strict "landed, directory not synced" answer that AtomicWrite's error
// deliberately does not carry.

// TestRosterSave_UnsyncedDirectoryIsReported: a roster save that lands while
// its directory cannot be opened for the fsync (WriteResult.DirSynced false,
// error nil as on main) makes the row warn; the next synced save clears it.
// Dropping DirSynced from the recorded evidence fails this test.
func TestRosterSave_UnsyncedDirectoryIsReported(t *testing.T) {
	c, _ := savedRosterCfg(t)
	prev := rosterAtomicWrite
	rosterAtomicWrite = func(p string, d []byte, perm os.FileMode) (fileutil.WriteResult, error) {
		res, err := prev(p, d, perm)
		res.DirSynced = false // the directory could not be opened for its fsync
		return res, err
	}
	t.Cleanup(func() { rosterAtomicWrite = prev })
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile = %v, want nil: the write landed", err)
	}
	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetDirNotSynced {
		t.Fatalf("row = %+v, want warn %q", row, rosterTargetDirNotSynced)
	}
	rosterAtomicWrite = prev
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Errorf("after a synced save: row = %+v, want ok", row)
	}
}
