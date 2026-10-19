//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestLoadUIUsersFile_BootRewriteKeepsXattrs: the real boot rewrite (through
// LoadUIUsersFile and fileutil.RewriteInPlace, no seam) keeps the roster's
// extended attributes on the new inode (Codex P2 4316064806 on PR #1601), and
// the row reports it persisting.
func TestLoadUIUsersFile_BootRewriteKeepsXattrs(t *testing.T) {
	path, _, _ := seedRosterFileForBoot(t)
	const name, value = "user.backup.policy", "include"
	if err := unix.Lsetxattr(path, name, []byte(value), 0); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			t.Skipf("the test filesystem does not support user extended attributes (%v)", err)
		}
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	c := configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	c.SetUIUsersFile(path)
	if err := c.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(before, after) {
		t.Fatal("same inode after load: the roster was not rewritten in place")
	}
	buf := make([]byte, 64)
	n, err := unix.Lgetxattr(path, name, buf)
	if err != nil || !bytes.Equal(buf[:n], []byte(value)) {
		t.Errorf("%s after the boot rewrite = %q (err %v), want %q", name, buf[:max(n, 0)], err, value)
	}
	if row := checkAdminRosterDurability(); row.Status != diagOK {
		t.Errorf("row = %+v, want ok", row)
	}
}
