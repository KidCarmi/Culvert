package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A pre-RBAC roster record carries no role. loadedRosterRole preserves that
// empty value on purpose (VerifyUIUser hands it back and the session
// middleware treats it as admin), so the account can sign in as an admin. The
// first-run bootstrap window must therefore treat it as a completed setup;
// otherwise a gateway upgraded with such a roster answers needsSetup:true and
// grants unauthenticated RoleAdmin while the admin account sits on disk.
func TestLoadUIUsersFile_RolelessLegacyAdminClosesBootstrapWindow(t *testing.T) {
	bodies := map[string]string{
		"bare array": `[{"username":"alice","pass_hash":"0a0b0c"}]`,
		"envelope":   `{"users":[{"username":"alice","pass_hash":"0a0b0c"}]}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "ui_users.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			c := &Config{cache: authCacheStore{entries: map[string]*authCacheEntry{}}}
			c.SetUIUsersFile(path)
			if err := c.LoadUIUsersFile(); err != nil {
				t.Fatalf("load: %v", err)
			}
			if !c.IsConfigured() {
				t.Errorf("loader: roster with an enrolled roleless account leaves IsConfigured()=false (unauthenticated admin window open)")
			}
			if !rosterBytesConfigure([]byte(body)) {
				t.Errorf("durable anchor: roleless account not treated as a completed setup")
			}
		})
	}
}
