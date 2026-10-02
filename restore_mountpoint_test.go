//go:build linux

package main

// restore_mountpoint_test.go — proves that a restore commit SUCCEEDS when
// dataDir is itself a mount point: the EXACT topology of the documented
// deployment. docker-compose.yml's `cli` service (the operator-facing restore
// path, docs/operator/docker-compose-backup-restore.md §6) mounts the named
// volume `proxy-data` at /data, and dataDir is "/data".
//
// rename(2) refuses to rename a directory that is a mount point (EBUSY), so
// the original two-rename sibling swap (`/data` → `/data.bak.<ts>`) could
// never commit on a real deployment. This file used to PIN that failure
// (TestRestoreCommit_DataDirIsMountPoint_FailsInsteadOfCommitting). The
// commit is now an in-place, journaled swap of the directory's top-level
// entries (restore_inplace.go), so the same scenario must succeed, leave the
// previous data preserved INSIDE the mount (where the volume keeps it), and
// leave no sibling of the mount point behind.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func mountBindDataDir(t *testing.T) (mountPoint string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root/CAP_SYS_ADMIN to create a bind mount")
	}
	// backing stands in for the storage Docker allocates for a named volume;
	// mountPoint stands in for the container path (/data) it is mounted at.
	backing := t.TempDir()
	mountParent := t.TempDir()
	mountPoint = filepath.Join(mountParent, "data")
	if err := os.Mkdir(mountPoint, 0o750); err != nil {
		t.Fatalf("mkdir mount point: %v", err)
	}
	if err := syscall.Mount(backing, mountPoint, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("bind mount unavailable in this sandbox: %v", err)
	}
	t.Cleanup(func() {
		if err := syscall.Unmount(mountPoint, 0); err != nil {
			t.Logf("cleanup: unmount %s: %v", mountPoint, err)
		}
	})
	// Sanity: the mount point itself cannot be renamed (the defect the
	// in-place swap exists to avoid). If this ever passes, the test would
	// prove less than it claims.
	if err := os.Rename(mountPoint, mountPoint+".probe"); err == nil {
		_ = os.Rename(mountPoint+".probe", mountPoint)
		t.Fatal("control: renaming the mount point unexpectedly succeeded; this topology no longer reproduces the defect")
	}
	return mountPoint
}

func TestRestoreCommit_DataDirIsMountPoint_Commits(t *testing.T) {
	mountPoint := mountBindDataDir(t)

	// Seed "current" data through the mount point, mirroring
	// seedCurrentDataDir's fixture shape used by the other commit tests.
	if err := (&clusterCA{}).InitOrLoad(mountPoint); err != nil {
		t.Fatalf("InitOrLoad current: %v", err)
	}
	seedFile(t, mountPoint, "ui_users.json",
		[]byte(`{"users":[{"username":"bob","role":"admin"}]}`), 0o600)
	// A file that is NOT in the archive: it must end up in the bak dir,
	// never silently lost and never left in the live tree (full mode).
	seedFile(t, mountPoint, "proxy.log", []byte("previous log"), 0o600)

	// A valid backup, same shape TestRestoreCommit_ModeFull_RoundTrip uses.
	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)

	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, mountPoint, "",
			restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("restore commit must succeed when dataDir is a mount point (the real docker-compose `cli` topology): %v", err)
	}

	body, rerr := os.ReadFile(filepath.Join(mountPoint, "ui_users.json"))
	if rerr != nil {
		t.Fatalf("read ui_users.json after commit: %v", rerr)
	}
	if !strings.Contains(string(body), "alice") || strings.Contains(string(body), "bob") {
		t.Errorf("restored roster should carry alice and not bob; got %s", body)
	}
	if _, err := os.Stat(filepath.Join(mountPoint, "proxy.log")); !os.IsNotExist(err) {
		t.Errorf("full mode must not leave non-archived previous files in the live tree (err=%v)", err)
	}
	bakPath, ok := readBak(t, mountPoint)
	if !ok {
		t.Fatal("previous data must be preserved in an in-place .restore-bak dir inside the mount")
	}
	if prev, err := os.ReadFile(filepath.Join(bakPath, "proxy.log")); err != nil || string(prev) != "previous log" {
		t.Errorf("previous non-archived file must be preserved in the bak dir: err=%v body=%q", err, prev)
	}
	if prev, err := os.ReadFile(filepath.Join(bakPath, "ui_users.json")); err != nil || !strings.Contains(string(prev), "bob") {
		t.Errorf("previous roster must be preserved in the bak dir: err=%v", err)
	}
	if stagingExists(t, mountPoint) {
		t.Error("staging dir must be gone after a successful commit")
	}
	if _, present, _ := readRestoreJournal(mountPoint); present {
		t.Error("journal must be removed after a successful commit")
	}
	// Nothing may land beside the mount point: a sibling would be OUTSIDE
	// the volume in the real topology.
	siblings, _ := os.ReadDir(filepath.Dir(mountPoint))
	for _, e := range siblings {
		if e.Name() != filepath.Base(mountPoint) {
			t.Errorf("unexpected sibling of the mount point: %s", e.Name())
		}
	}
	// And the process must be allowed to boot on the result.
	if gerr := checkInterruptedRestore(mountPoint); gerr != nil {
		t.Errorf("boot guard should pass after a completed commit: %v", gerr)
	}
}

// A top-level entry of dataDir that is itself a mount point (e.g. the
// `./yara:/data/yara:ro` bind docker-compose.yml suggests) cannot be moved
// aside; the commit must refuse BEFORE touching anything.
func TestRestoreCommit_NestedMountPoint_RefusesBeforeMutation(t *testing.T) {
	mountPoint := mountBindDataDir(t)
	if err := (&clusterCA{}).InitOrLoad(mountPoint); err != nil {
		t.Fatalf("InitOrLoad current: %v", err)
	}
	seedFile(t, mountPoint, "ui_users.json", []byte(`{"users":[{"username":"bob","role":"admin"}]}`), 0o600)
	nested := filepath.Join(mountPoint, "yara")
	if err := os.Mkdir(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount(t.TempDir(), nested, "", syscall.MS_BIND, ""); err != nil {
		t.Skipf("nested bind mount unavailable: %v", err)
	}
	t.Cleanup(func() { _ = syscall.Unmount(nested, 0) })

	src, _ := makeBackupWithRealCA(t, []uiUserRecord{{Username: "alice", Role: RoleAdmin}}, 0)
	_, err := captureStdout(t, func() error {
		return runRestoreCommit(src, mountPoint, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err == nil || !strings.Contains(err.Error(), "mount points inside the data directory") {
		t.Fatalf("expected a nested-mount refusal, got: %v", err)
	}
	if body, _ := os.ReadFile(filepath.Join(mountPoint, "ui_users.json")); !strings.Contains(string(body), "bob") {
		t.Errorf("current data must be untouched after the refusal; got %s", body)
	}
	if _, ok := readBak(t, mountPoint); ok {
		t.Error("no bak dir may be created by a refused commit")
	}
	if stagingExists(t, mountPoint) {
		t.Error("no staging dir may be left by a refused commit")
	}
}
