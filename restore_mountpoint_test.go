//go:build linux

package main

// restore_mountpoint_test.go — the restore commit on a data directory that is
// itself a mount point: the EXACT topology of the documented deployment.
// docker-compose.yml's `cli` service (the operator-facing restore path, per
// docs/operator/docker-compose-backup-restore.md §6) mounts the named volume
// `proxy-data` at /data.
//
// rename(2) refuses to rename a mount point (EBUSY), so the whole-directory
// swap can never complete there; this file used to pin exactly that failure.
// runRestoreCommit now detects the mount point and swaps the directory's
// CONTENT instead (restore_inplace.go). The other in-place tests force the
// layout; this one needs CAP_SYS_ADMIN and proves the detection and the swap
// on a real mount, with nothing forced.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestRestoreCommit_DataDirIsMountPoint_CommitsInPlace(t *testing.T) {
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

	if !restoreUsesInPlaceSwap(mountPoint) {
		t.Fatal("a bind-mounted data directory was not recognised as a mount point")
	}
	before := treeDigest(t, mountPoint)

	out, err := captureStdout(t, func() error {
		return runRestoreCommit(src, mountPoint, "", restoreOpts{Mode: modeFull, AcceptDPReenrollment: true})
	})
	if err != nil {
		t.Fatalf("restore commit on a mount point: %v\n%s", err, out)
	}

	// The mounted directory holds the backup's content (alice, not bob) …
	body, rerr := os.ReadFile(filepath.Join(mountPoint, "ui_users.json"))
	if rerr != nil {
		t.Fatalf("read ui_users.json after the commit: %v", rerr)
	}
	if !strings.Contains(string(body), "alice") || strings.Contains(string(body), "bob") {
		t.Errorf("the mounted data directory does not hold the backup's content: %s", body)
	}
	// … it is still the same mount, written through to the backing storage …
	if _, serr := os.Stat(filepath.Join(backing, "ui_users.json")); serr != nil {
		t.Errorf("the restored content is not on the mounted volume: %v", serr)
	}
	// … and the previous content is kept on that volume, complete.
	baks := inPlaceEntries(t, mountPoint, "bak")
	if len(baks) != 1 || treeDigest(t, baks[0]) != before {
		t.Errorf("the previous content was not kept intact in the work area: %v", baks)
	}
	if intentPresent(mountPoint) {
		t.Error("intent record left after the commit")
	}
}
