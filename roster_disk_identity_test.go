package main

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Gates for Codex P2 4317730279 on PR #1601: the roster identity read does
// its disk I/O with no roster lock held, and a Culvert write racing it is
// never reported as an external replacement.

// savedRosterCfg is a set-up node whose roster file was just saved, so a
// landed write (and its identity) is recorded.
func savedRosterCfg(t *testing.T) (c *Config, path string) {
	t.Helper()
	c = configuredRosterCfg(t, false)
	swapCfgForRosterDurability(t, c)
	path = filepath.Join(t.TempDir(), "ui_users.json")
	c.SetUIUsersFile(path)
	if err := c.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}
	return c, path
}

func setRosterIdentityOpen(t *testing.T, fn func(path string) (*os.File, error)) {
	t.Helper()
	prev := rosterIdentityOpen
	rosterIdentityOpen = fn
	t.Cleanup(func() { rosterIdentityOpen = prev })
}

// TestRosterIdentityRead_DoesNotBlockRosterWrites: while the identity read is
// stuck in the filesystem (a stalled NFS or FUSE volume, simulated by
// blocking the open), a roster save and a login-path best-effort mutation
// still complete promptly. Holding saveUIUsersMu across the read fails this
// test.
func TestRosterIdentityRead_DoesNotBlockRosterWrites(t *testing.T) {
	c, _ := savedRosterCfg(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var once atomic.Bool
	kernelOpen := rosterIdentityOpen
	setRosterIdentityOpen(t, func(p string) (*os.File, error) {
		if once.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		return kernelOpen(p)
	})
	rowDone := make(chan struct{})
	go func() {
		defer close(rowDone)
		_ = checkAdminRosterDurability()
	}()
	t.Cleanup(func() {
		close(release)
		<-rowDone
	})
	<-entered

	for name, write := range map[string]func() error{
		"SaveUIUsersFile":        c.SaveUIUsersFile,
		"mutateRosterBestEffort": func() error { return c.mutateRosterBestEffort(func() bool { return true }) },
	} {
		done := make(chan error, 1)
		go func() { done <- write() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%s blocked behind the diagnostics identity read", name)
		}
	}
}

// TestRosterIdentityRead_CulvertWriteDuringReadIsNotReplaced: a Culvert save
// landing while the identity read is in progress (so the file read is newer
// than the identity snapshot) moves the write generation; the read is
// retried, or reported in flux, never as "replaced". Dropping the generation
// re-check fails this test.
func TestRosterIdentityRead_CulvertWriteDuringReadIsNotReplaced(t *testing.T) {
	for _, racedReads := range []int32{1, 2} { // retried and then consistent; raced on both attempts
		t.Run(map[int32]string{1: "retried", 2: "in flux"}[racedReads], func(t *testing.T) {
			c, _ := savedRosterCfg(t)
			if err := c.SetUIUser("raced-"+t.Name(), "Or1ginalPass!", RoleAdmin); err != nil {
				t.Fatal(err)
			}
			kernelOpen := rosterIdentityOpen
			var calls atomic.Int32
			setRosterIdentityOpen(t, func(p string) (*os.File, error) {
				if calls.Add(1) <= racedReads {
					// A save lands after the identity was snapshotted: new
					// bytes on disk, a new recorded identity.
					done := make(chan error, 1)
					go func() { done <- c.SaveUIUsersFile() }()
					select {
					case err := <-done:
						if err != nil {
							t.Errorf("SaveUIUsersFile: %v", err)
						}
					case <-time.After(3 * time.Second):
						t.Error("SaveUIUsersFile blocked behind the identity read")
					}
				}
				return kernelOpen(p)
			})
			if row := checkAdminRosterDurability(); row.Status != diagOK {
				t.Errorf("row = %+v, want ok: a Culvert save racing the read is not an external replacement", row)
			}
			if n := calls.Load(); n < racedReads {
				t.Errorf("identity read ran %d time(s), want at least %d", n, racedReads)
			}
		})
	}
}

// TestRosterIdentityRead_ConcurrentRequestsShareOneRead: requests arriving
// while one identity read is blocked wait for it instead of starting more.
func TestRosterIdentityRead_ConcurrentRequestsShareOneRead(t *testing.T) {
	_, _ = savedRosterCfg(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var opens atomic.Int32
	kernelOpen := rosterIdentityOpen
	setRosterIdentityOpen(t, func(p string) (*os.File, error) {
		if opens.Add(1) == 1 {
			close(entered)
			<-release
		}
		return kernelOpen(p)
	})
	const n = 8
	done := make(chan struct{}, n)
	go func() { _ = checkAdminRosterDurability(); done <- struct{}{} }()
	<-entered
	for i := 1; i < n; i++ {
		go func() { _ = checkAdminRosterDurability(); done <- struct{}{} }()
	}
	time.Sleep(100 * time.Millisecond) // let the followers arrive and join
	close(release)
	for i := 0; i < n; i++ {
		<-done
	}
	if got := opens.Load(); got != 1 {
		t.Errorf("%d identity reads for %d concurrent requests, want 1", got, n)
	}
}
