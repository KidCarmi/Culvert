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

// resetPACStartupGlobals snapshots/restores pacDefaultProxyPort and
// pacStore.path for isolation under -shuffle.
func resetPACStartupGlobals(t *testing.T) {
	t.Helper()
	origPort := pacDefaultProxyPort
	pacStore.mu.RLock()
	origPath := pacStore.path
	origCfg := pacStore.cfg
	pacStore.mu.RUnlock()
	t.Cleanup(func() {
		pacDefaultProxyPort = origPort
		pacStore.mu.Lock()
		pacStore.path = origPath
		pacStore.cfg = origCfg
		pacStore.mu.Unlock()
	})
}

func TestResolvePACStartupConfig_SetsPort(t *testing.T) {
	got := resolvePACStartupConfig(8080)
	if got.DefaultProxyPort != 8080 {
		t.Errorf("DefaultProxyPort: got %d, want 8080", got.DefaultProxyPort)
	}
	if got.ConfigPath != "pac_config.json" {
		t.Errorf("ConfigPath: got %q", got.ConfigPath)
	}
}

func TestResolvePACStartupConfig_ZeroPort(t *testing.T) {
	got := resolvePACStartupConfig(0)
	if got.DefaultProxyPort != 0 {
		t.Errorf("expected zero port; got %d", got.DefaultProxyPort)
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
	if pacDefaultProxyPort != 9090 {
		t.Errorf("pacDefaultProxyPort not set; got %d", pacDefaultProxyPort)
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
	if pacDefaultProxyPort != 7777 {
		t.Errorf("pacDefaultProxyPort: got %d", pacDefaultProxyPort)
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
