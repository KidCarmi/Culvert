package main

// logstore_startup_test.go — per-slice tests for the log-store startup slice
// (resolver behavior + loader seed semantics), following the pattern of the
// other <domain>_startup_test.go files.

import (
	"context"
	"path/filepath"
	"testing"
)

func TestResolveLogStoreStartupConfig_DefaultDirUnderDataDir(t *testing.T) {
	fc := &FileConfig{}
	dataDirVal := t.TempDir()
	got := resolveLogStoreStartupConfig(fc, dataDirVal, "", "")
	if want := filepath.Join(dataDirVal, "logstore"); got.Dir != want {
		t.Errorf("Dir = %q, want %q", got.Dir, want)
	}
	if got.SeedEnable {
		t.Error("SeedEnable must be false when log_store_path is unset (GUI-enable only)")
	}
	if got.Passphrase != "" {
		t.Errorf("Passphrase = %q, want empty (no env values)", got.Passphrase)
	}
}

func TestResolveLogStoreStartupConfig_ConfigPathWinsAndSeeds(t *testing.T) {
	fc := &FileConfig{LogStorePath: "/custom/logs", LogRetentionDays: 30, LogRetentionMaxGB: 2.5}
	got := resolveLogStoreStartupConfig(fc, "/data", "", "")
	if got.Dir != "/custom/logs" {
		t.Errorf("Dir = %q, want /custom/logs", got.Dir)
	}
	if !got.SeedEnable {
		t.Error("SeedEnable must be true when log_store_path is set (back-compat)")
	}
	if got.RetentionDays != 30 || got.RetentionMaxGB != 2.5 {
		t.Errorf("retention = (%d, %v), want (30, 2.5)", got.RetentionDays, got.RetentionMaxGB)
	}
}

func TestResolveLogStoreStartupConfig_PassphraseFallback(t *testing.T) {
	fc := &FileConfig{}
	// Dedicated log passphrase wins.
	if got := resolveLogStoreStartupConfig(fc, "/d", "logpass", "capass"); got.Passphrase != "logpass" {
		t.Errorf("Passphrase = %q, want logpass (dedicated env wins)", got.Passphrase)
	}
	// Falls back to the CA passphrase.
	if got := resolveLogStoreStartupConfig(fc, "/d", "", "capass"); got.Passphrase != "capass" {
		t.Errorf("Passphrase = %q, want capass (CA fallback)", got.Passphrase)
	}
}

// The loader publishes the globals but does NOT open the store when the
// config did not seed-enable it (GUI-enable path owns that later).
func TestLoadLogStore_NoSeedPublishesGlobalsOnly(t *testing.T) {
	origDir, origPass := logStoreDir, logStorePassphrase
	t.Cleanup(func() { logStoreDir, logStorePassphrase = origDir, origPass })

	dir := t.TempDir()
	loadLogStore(logStoreStartupConfig{Dir: dir, Passphrase: "p", SeedEnable: false}, context.Background())
	if logStoreDir != dir || logStorePassphrase != "p" {
		t.Errorf("globals = (%q,%q), want (%q,p)", logStoreDir, logStorePassphrase, dir)
	}
	if globalLogStore.Load() != nil {
		t.Error("store must stay OFF (nil) when not seed-enabled")
	}
}
