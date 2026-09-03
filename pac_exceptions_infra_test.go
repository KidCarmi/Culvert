package main

// pac_exceptions_infra_test.go — closes gap #2 (handler persist-error branches)
// and gap #4 (full backup→restore cycle). Infrastructure durability: a failed
// disk write must surface as 500 (never a silent success), and governance must
// survive a real backup + restore-commit, not just tarball inclusion.

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/pac"
)

// TestPEI_HandlerReturns500OnPersistFailure covers the error branches of
// pacExceptionPut / pacExceptionDelete: when the backing file cannot be
// written, the handler must return 500 rather than reporting success.
func TestPEI_HandlerReturns500OnPersistFailure(t *testing.T) {
	op := pacProfiles.Snapshot()
	oe := pacExceptions.Snapshot()
	t.Cleanup(func() { pacProfiles.Restore(op); pacExceptions.Restore(oe) })
	seedDirectCapableProfile(t, "vendor")

	// Backing path inside a NON-EXISTENT directory → the atomic write fails.
	badPath := filepath.Join(t.TempDir(), "missing-subdir", "pac_exceptions.json")

	// PUT a valid governance record for a known profile → persist fails → 500.
	pacExceptions.Restore(pac.ExceptionState{ByID: map[string]pac.ExceptionRecord{}, Path: badPath})
	if rec := peiExcItem(t, http.MethodPut, "vendor", `{"owner":"o","reason":"r"}`, RoleAdmin); rec.Code != http.StatusInternalServerError {
		t.Errorf("PUT with unwritable store = %d, want 500 (%s)", rec.Code, rec.Body.String())
	}

	// DELETE an in-memory record whose persist will fail → 500.
	pacExceptions.Restore(pac.ExceptionState{
		ByID: map[string]pac.ExceptionRecord{"vendor": {ProfileID: "vendor", Owner: "o", Reason: "r", Revision: 1}},
		Path: badPath,
	})
	if rec := peiExcItem(t, http.MethodDelete, "vendor", "", RoleAdmin); rec.Code != http.StatusInternalServerError {
		t.Errorf("DELETE with unwritable store = %d, want 500 (%s)", rec.Code, rec.Body.String())
	}
}

// TestPEI_GovernanceSurvivesBackupRestoreCommitCycle is the full cycle: seed a
// governance file into a real-CA backup source, runBackup, then runRestoreCommit
// (ModeFull) into a distinct current /data, and prove the governance file lands
// AND reloads into a store with the record intact and status governed.
func TestPEI_GovernanceSurvivesBackupRestoreCommitCycle(t *testing.T) {
	// Backup source: real CA + required Tier-1 artifacts + the governance file.
	backupDir := t.TempDir()
	ca := &clusterCA{}
	if err := ca.InitOrLoad(backupDir); err != nil {
		t.Fatalf("InitOrLoad: %v", err)
	}
	seedFile(t, backupDir, "ui_users.json", []byte(`{"users":[{"username":"alice","role":"admin"}]}`), 0o600)
	seedFile(t, backupDir, "cluster.json", []byte(`{"nodes":{}}`), 0o600)
	gov := `{"vendor":{"profileId":"vendor","owner":"neteng","reason":"vendor SaaS","expiresAt":"2099-01-01T00:00:00Z"}}`
	seedFile(t, backupDir, "pac_exceptions.json", []byte(gov), 0o600)

	out := filepath.Join(t.TempDir(), "backup.tar.gz")
	if err := runBackup(out, backupDir); err != nil {
		t.Fatalf("backup: %v", err)
	}

	// Current /data: distinct CA + a different roster, NO governance yet.
	currentDir := seedCurrentDataDir(t, true, []uiUserRecord{{Username: "bob", Role: RoleAdmin}}, 0)

	if _, err := captureStdout(t, func() error {
		return runRestoreCommit(out, currentDir, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	}); err != nil {
		t.Fatalf("restore commit: %v", err)
	}

	// The governance file was restored into /data.
	restored := filepath.Join(currentDir, "pac_exceptions.json")
	if _, err := os.Stat(restored); err != nil {
		t.Fatalf("governance file not restored into /data: %v", err)
	}
	// And it reloads into a store with the record intact + status governed.
	var st pac.ExceptionStore
	if err := st.Load(restored); err != nil {
		t.Fatalf("load restored governance: %v", err)
	}
	rec, ok := st.Get("vendor")
	if !ok || rec.Owner != "neteng" || rec.Reason != "vendor SaaS" {
		t.Errorf("governance not restored intact: %+v ok=%v", rec, ok)
	}
	if s := rec.Status(time.Now().UTC(), true); s != pac.GovGoverned {
		t.Errorf("restored status = %q, want governed", s)
	}
}
