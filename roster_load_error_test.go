package main

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// Gates for Codex P2 4327431894 on PR #1601: a failed startup load is a fact
// about the file as it was then. Once a roster write lands at that exact
// path the file holds the roster in use, so the load error no longer
// describes it; until then it stays, and outranks nothing it should not.

const rosterLoadFailedMsg = "the configured roster file could not be loaded at startup"

// TestRosterDurability_LandedSaveClearsTheStartupLoadError: after a nonfatal
// load error the row reports it; a save that lands at the same path clears it
// and the row shows the probe's state (here ok). Not clearing the error on a
// landed write fails this test.
func TestRosterDurability_LandedSaveClearsTheStartupLoadError(t *testing.T) {
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	setupRosterRecordedReadError(t, c)
	if row := checkAdminRosterDurability(); row.Status != diagWarn || !strings.HasPrefix(row.Message, rosterLoadFailedMsg) {
		t.Fatalf("after the load error: row = %+v, want warn %q", row, rosterLoadFailedMsg)
	}
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatal(err)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK || row.Message != rosterDurabilityLandedOK {
		t.Errorf("after a landed save at the same path: row = %+v, want ok", row)
	}
	if _, err := c.rosterPersistTarget(); err != nil {
		t.Errorf("load error still recorded after a landed save: %v", err)
	}
}

// TestRosterDurability_LoadErrorIsNotClearedForAnotherPath: a write landing
// for a path other than the configured one does not clear its load error.
func TestRosterDurability_LoadErrorIsNotClearedForAnotherPath(t *testing.T) {
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	setupRosterRecordedReadError(t, c)
	c.noteRosterWriteLanded(filepath.Join(t.TempDir(), "other.json"), []byte("{}"), nil, true)
	if _, err := c.rosterPersistTarget(); err == nil {
		t.Error("a write landing at another path cleared the configured path's load error")
	}
}

// TestRosterDurability_LoadErrorWithARefusedSave: with the load error still
// standing, a refused save shows the refusal (ranked first) and its remedy
// names the load failure the row also sees.
func TestRosterDurability_LoadErrorWithARefusedSave(t *testing.T) {
	snapshotAuthGlobals(t)
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	setupRosterRecordedReadError(t, c)

	prev := rosterAtomicWrite
	rosterAtomicWrite = func(p string, _ []byte, _ os.FileMode) (fileutil.WriteResult, error) {
		return fileutil.WriteResult{}, fmt.Errorf("atomic write %s: create temp: %w", p,
			&fs.PathError{Op: "open", Path: p + ".tmp.0", Err: syscall.EACCES})
	}
	t.Cleanup(func() { rosterAtomicWrite = prev })
	w := httptest.NewRecorder()
	apiAuthUsers(w, jsonReq(http.MethodPost, "/api/auth/users", map[string]any{
		"username": "newviewer", "password": "Sup3rSecret9!", "role": string(RoleViewer),
	}))
	if w.Code < 500 {
		t.Fatalf("POST with the save refused: status = %d, want 5xx", w.Code)
	}
	row := checkAdminRosterDurability()
	if !strings.HasPrefix(row.Message, "1 admin account change(s) were refused") ||
		!strings.Contains(row.OperatorAction, rosterLoadFailedMsg) {
		t.Errorf("row = %+v, want the refusal, with the load failure named in its remedy", row)
	}
	if _, err := c.rosterPersistTarget(); err == nil {
		t.Error("a refused save cleared the load error")
	}
}
