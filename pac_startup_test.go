package main

// pac_startup_test.go — PR3 expansion Batch 3 coverage.

import (
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var pacStartupLoggerMu sync.Mutex

func ensurePACStartupTestLogger(t *testing.T) {
	t.Helper()
	pacStartupLoggerMu.Lock()
	defer pacStartupLoggerMu.Unlock()
	if logger == nil {
		logger = log.New(os.Stderr, "[test] ", 0)
	}
}

// resetPACStartupGlobals snapshots/restores the pacStore state (config,
// path, default port) for isolation under -shuffle.
func resetPACStartupGlobals(t *testing.T) {
	t.Helper()
	orig := pacStore.Snapshot()
	t.Cleanup(func() { pacStore.Restore(orig) })
}

func TestResolvePACStartupConfig_SetsPort(t *testing.T) {
	got := resolvePACStartupConfig("/data", 8080)
	if got.DefaultProxyPort != 8080 {
		t.Errorf("DefaultProxyPort: got %d, want 8080", got.DefaultProxyPort)
	}
	if got.ConfigPath != "/data/pac_config.json" {
		t.Errorf("ConfigPath: got %q", got.ConfigPath)
	}
	if got.LegacyConfigPath != "pac_config.json" {
		t.Errorf("LegacyConfigPath: got %q", got.LegacyConfigPath)
	}
}

func TestResolvePACStartupConfig_ZeroPort(t *testing.T) {
	got := resolvePACStartupConfig("", 0)
	if got.DefaultProxyPort != 0 {
		t.Errorf("expected zero port; got %d", got.DefaultProxyPort)
	}
}

// TestLoadPAC_MigratesLegacyCWDFile pins the one-way CWD→dataDir migration:
// when the dataDir file is absent but the legacy file exists, the legacy
// config is loaded, persisted to the new path, and subsequent writes go to
// the new path only (the legacy file stays frozen).
func TestLoadPAC_MigratesLegacyCWDFile(t *testing.T) {
	resetPACStartupGlobals(t)
	ensurePACStartupTestLogger(t)
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy_pac_config.json")
	newPath := filepath.Join(dir, "data", "pac_config.json")
	legacyCfg := `{"proxyHost":"proxy.legacy.example","proxyPort":3128,"exclusions":["corp.local"]}`
	if err := os.WriteFile(legacy, []byte(legacyCfg), 0o600); err != nil {
		t.Fatal(err)
	}

	err := loadPAC(pacStartupConfig{ConfigPath: newPath, LegacyConfigPath: legacy, DefaultProxyPort: 8080})
	if err != nil {
		t.Fatalf("loadPAC: %v", err)
	}
	got := pacStore.Get()
	if got.ProxyHost != "proxy.legacy.example" || got.ProxyPort != 3128 {
		t.Fatalf("legacy config not loaded: %+v", got)
	}
	if _, statErr := os.Stat(newPath); statErr != nil {
		t.Fatalf("migrated file not written to dataDir path: %v", statErr)
	}
	// Legacy file must be left in place (frozen).
	if _, statErr := os.Stat(legacy); statErr != nil {
		t.Errorf("legacy file must be left in place: %v", statErr)
	}

	// A mutation must land in the NEW path only.
	if err := pacStore.Set(PACConfig{ProxyHost: "updated.example", ProxyPort: 3128}); err != nil {
		t.Fatalf("Set after migration: %v", err)
	}
	newData, _ := os.ReadFile(newPath)
	if !strings.Contains(string(newData), "updated.example") {
		t.Error("mutation did not persist to the migrated path")
	}
	legacyData, _ := os.ReadFile(legacy)
	if strings.Contains(string(legacyData), "updated.example") {
		t.Error("mutation must not touch the frozen legacy file")
	}
}

// TestLoadPAC_PrefersDataDirFileOverLegacy: once the dataDir file exists the
// legacy file is ignored entirely.
func TestLoadPAC_PrefersDataDirFileOverLegacy(t *testing.T) {
	resetPACStartupGlobals(t)
	ensurePACStartupTestLogger(t)
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy_pac_config.json")
	newPath := filepath.Join(dir, "pac_config.json")
	if err := os.WriteFile(legacy, []byte(`{"proxyHost":"stale.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(`{"proxyHost":"current.example"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := loadPAC(pacStartupConfig{ConfigPath: newPath, LegacyConfigPath: legacy, DefaultProxyPort: 8080})
	if err != nil {
		t.Fatalf("loadPAC: %v", err)
	}
	if got := pacStore.Get(); got.ProxyHost != "current.example" {
		t.Errorf("dataDir file must win over legacy: %+v", got)
	}
}

func TestLoadPAC_MissingFileIsNonFatal(t *testing.T) {
	resetPACStartupGlobals(t)
	ensurePACStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.json")
	err := loadPAC(pacStartupConfig{ConfigPath: path, DefaultProxyPort: 9090})
	if err != nil {
		t.Fatalf("missing file should be non-fatal; got %v", err)
	}
	if pacStore.DefaultPort() != 9090 {
		t.Errorf("default port not set; got %d", pacStore.DefaultPort())
	}
}

func TestLoadPAC_AppliesPortEvenWhenConfigEmpty(t *testing.T) {
	resetPACStartupGlobals(t)
	ensurePACStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := loadPAC(pacStartupConfig{ConfigPath: path, DefaultProxyPort: 7777}); err != nil {
		t.Fatalf("loadPAC: %v", err)
	}
	if pacStore.DefaultPort() != 7777 {
		t.Errorf("default port: got %d", pacStore.DefaultPort())
	}
}

func TestLoadPAC_ParseErrorSurfaces(t *testing.T) {
	resetPACStartupGlobals(t)
	ensurePACStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := loadPAC(pacStartupConfig{ConfigPath: path})
	if err == nil {
		t.Fatal("expected parse error; got nil")
	}
	if !strings.Contains(err.Error(), "PAC config load error:") {
		t.Errorf("error prefix mismatch: %v", err)
	}
}
