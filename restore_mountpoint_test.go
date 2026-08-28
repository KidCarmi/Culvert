//go:build linux

package main

// restore_mountpoint_test.go — proves that runRestoreCommit's two-rename
// directory swap cannot complete when dataDir is itself a mount point: the
// EXACT topology of the documented deployment. docker-compose.yml's `cli`
// service (the operator-facing restore path, per
// docs/operator/docker-compose-backup-restore.md §6) mounts the named
// volume `proxy-data` at /data, and dataDir (main.go) is the hardcoded
// literal "/data" — there is no -data-dir flag to point it anywhere else.
//
// rename(2) refuses to rename a directory that is a mount point (EBUSY:
// "Device or resource busy"), so `os.Rename(dataDir, bakPath)` in
// runRestoreCommit can never succeed against the real `cli` container's
// /data. The one documented way to actually commit a restore therefore
// cannot work in the one deployment this feature ships for.
//
// Existing restore-commit tests (TestRestoreCommit_ModeFull_RoundTrip etc.)
// all pass a plain t.TempDir() as dataDir, which is never a mount point, so
// none of them exercise this path.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRestoreCommit_DataDirIsMountPoint_FailsInsteadOfCommitting(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_SYS_ADMIN to create a bind mount")
	}

	// backing stands in for the storage Docker allocates for a named volume;
	// mountPoint stands in for the container path (/data) it is mounted at.
	backing := t.TempDir()
	mountParent := t.TempDir()
	mountPoint := filepath.Join(mountParent, "data")
	if err := os.Mkdir(mountPoint, 0o750); err != nil {
		t.Fatalf("mkdir mount point: %v", err)
	}
	if err := syscall.Mount(backing, mountPoint, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("bind mount unavailable in this sandbox: %v", err)
	}
	defer func() {
		if err := syscall.Unmount(mountPoint, 0); err != nil {
			t.Logf("cleanup: unmount %s: %v", mountPoint, err)
		}
	}()

	// Seed "current" data through the mount point, mirroring
	// seedCurrentDataDir's fixture shape used by the other commit tests.
	if err := (&clusterCA{}).InitOrLoad(mountPoint); err != nil {
		t.Fatalf("InitOrLoad current: %v", err)
	}
	seedFile(t, mountPoint, "ui_users.json",
		[]byte(`{"users":[{"username":"bob","role":"admin"}]}`), 0o600)

	// A valid backup, same shape TestRestoreCommit_ModeFull_RoundTrip uses.
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)

	err := runRestoreCommit(src, mountPoint, "",
		restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	if err == nil {
		t.Fatal("expected restore commit to fail when dataDir is a mount point " +
			"(the real docker-compose `cli` service topology), but it succeeded")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "busy") {
		t.Fatalf("expected an EBUSY-flavoured rename failure naming the mount point, got: %v", err)
	}

	// The failure must be clean: mounted "current" data must be untouched
	// (bob still present), never partially swapped or lost.
	body, rerr := os.ReadFile(filepath.Join(mountPoint, "ui_users.json"))
	if rerr != nil {
		t.Fatalf("read ui_users.json after failed commit: %v", rerr)
	}
	if !strings.Contains(string(body), "bob") {
		t.Errorf("current data should be untouched after a failed commit; got %s", body)
	}
}
