package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// TestSaveUIUsersFile_ConcurrentSavesDoNotLoseUsers proves that concurrent
// admin-user mutations (e.g. two operators hitting POST /api/auth/users at
// the same time, or a password change racing a TOTP-counter persist) do not
// silently drop a user from the on-disk roster.
//
// SaveUIUsersFile snapshots c.uiUsers under a brief RLock, releases it, then
// writes the snapshot to disk via fileutil.AtomicWrite. Two concurrent calls
// each take their own independent, internally-consistent snapshot, but
// nothing serializes the disk WRITES against each other — whichever call's
// write reaches the final rename() LAST wins, regardless of which snapshot
// was taken more recently. A save that started (and snapshotted) before a
// concurrent SetUIUser call, but whose disk write finishes after a later
// save's write, silently overwrites the newer file with stale content —
// permanently losing the concurrently-added user from disk even though the
// admin API already returned 200 OK and the user is present in memory for
// the rest of the process's life. The loss only surfaces on the next
// restart, when the roster is reloaded from disk.
//
// The window this test exercises is inside SaveUIUsersFile's snapshot+write,
// not bcrypt's cost factor, so user records are seeded directly into the
// roster (bypassing SetUIUser's bcrypt hashing, which only adds latency that
// masks the race) to keep the reproduction fast and reliable across many
// trials.
func TestSaveUIUsersFile_ConcurrentSavesDoNotLoseUsers(t *testing.T) {
	const trials = 40
	const n = 30

	for trial := 0; trial < trials; trial++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "ui_users.json")

		c := &Config{}
		c.SetUIUsersFile(path)

		var wg sync.WaitGroup
		for i := 0; i < n; i++ {
			name := fmt.Sprintf("user%02d", i)
			wg.Add(1)
			go func(name string) {
				defer wg.Done()
				c.mu.Lock()
				if c.uiUsers == nil {
					c.uiUsers = map[string]*uiAdminUser{}
				}
				c.uiUsers[name] = &uiAdminUser{passHash: []byte("x"), role: RoleAdmin}
				c.mu.Unlock()
				if err := c.SaveUIUsersFile(); err != nil {
					t.Errorf("SaveUIUsersFile after creating %s: %v", name, err)
				}
			}(name)
		}
		wg.Wait()

		mem := c.ListUIUsers()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read persisted ui_users.json: %v", err)
		}
		var env uiUsersFileEnvelope
		if err := json.Unmarshal(data, &env); err != nil {
			t.Fatalf("unmarshal persisted ui_users.json: %v", err)
		}

		if len(env.Users) != len(mem) {
			t.Fatalf("trial %d: lost update: %d users created in memory (%v) but only %d persisted to disk (%v) — "+
				"a concurrently-created admin user was silently dropped from ui_users.json and would "+
				"vanish entirely on the next restart", trial, len(mem), mem, len(env.Users), env.Users)
		}

		onDisk := make(map[string]bool, len(env.Users))
		for _, u := range env.Users {
			onDisk[u.Username] = true
		}
		for _, u := range mem {
			if !onDisk[u.Username] {
				t.Fatalf("trial %d: user %q exists in memory but is missing from the persisted file", trial, u.Username)
			}
		}
	}
}
