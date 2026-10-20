package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Gates for Codex P1 4319946917 and P2 4319946921 on PR #1601 at the row:
// the roster path keeps the strict "landed, directory not synced" answer that
// AtomicWrite's error no longer carries, and an unsynced restore of a newer
// roster is reported with its recovery file.

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

// TestLoadUIUsersFile_UnsyncedBootRewriteIsReported: the boot rewrite landed
// but its directory could not be synced (ErrReplacedNotSynced): the roster is
// loaded, the rewrite counts as landed, and the row says it is not synced.
func TestLoadUIUsersFile_UnsyncedBootRewriteIsReported(t *testing.T) {
	path, _, _ := seedRosterFileForBoot(t)
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	prev := rosterRewriteInPlace
	rosterRewriteInPlace = func(p string, _ []byte, _ os.FileInfo, _ func() bool) error {
		return fmt.Errorf("rewrite in place %s: parent dir open: permission denied: %w", p, fileutil.ErrReplacedNotSynced)
	}
	t.Cleanup(func() { rosterRewriteInPlace = prev })
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	if tried, werr := c.rosterWriteEvidence(); !tried || werr != nil {
		t.Errorf("evidence = (%v, %v), want a landed write", tried, werr)
	}
	if row := checkAdminRosterDurability(); row.Status != diagWarn || row.Message != rosterTargetDirNotSynced {
		t.Errorf("row = %+v, want warn %q", row, rosterTargetDirNotSynced)
	}
}

// TestLoadUIUsersFile_UnsyncedRestoreIsReported: the boot rewrite saw a
// concurrent change and restored the newer file, but could not sync the
// restore. The log names the kept recovery file; the row says the restore
// is not durable. Reporting it as a plain concurrent change fails this test.
func TestLoadUIUsersFile_UnsyncedRestoreIsReported(t *testing.T) {
	path, _, _ := seedRosterFileForBoot(t)
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	kept := path + ".tmp.424242"
	prev := rosterRewriteInPlace
	rosterRewriteInPlace = func(p string, _ []byte, _ os.FileInfo, _ func() bool) error {
		return fmt.Errorf("rewrite in place %s: the target changed; the newer file was restored to the target, "+
			"but the restore could not be synced to disk (EIO), so the entry the restore displaced is kept at %s: %w",
			p, kept, errors.Join(fileutil.ErrConcurrentChange, fileutil.ErrRestoreNotSynced))
	}
	t.Cleanup(func() { rosterRewriteInPlace = prev })
	logs := captureLoggerForTest(t)
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	row := checkAdminRosterDurability()
	if row.Status != diagWarn || row.Message != rosterTargetRestoreNotSynced {
		t.Fatalf("row = %+v, want warn %q", row, rosterTargetRestoreNotSynced)
	}
	if !strings.Contains(row.OperatorAction, "ui_users.json.tmp.*") || strings.Contains(row.Message+row.OperatorAction, path) {
		t.Errorf("row = %+v, want the keep-the-recovery-file remedy without the path", row)
	}
	out := logs.String()
	if !strings.Contains(out, "could not be synced to disk") || !strings.Contains(out, sanitizeLog(kept)) {
		t.Errorf("log does not say the restore is unsynced and name %q:\n%s", kept, out)
	}
}
